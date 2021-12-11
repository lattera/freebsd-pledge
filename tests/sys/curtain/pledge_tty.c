#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <termios.h>
#include <sys/param.h>
#include <sys/ttycom.h>
#include <libutil.h>
#include <atf-c.h>
#include <pledge.h>

#include "path-utils.h"

ATF_TC_WITHOUT_HEAD(isatty_vnode);
ATF_TC_BODY(isatty_vnode, tc)
{
	int fd;
	ATF_REQUIRE((fd = creat("test", 0666)) >= 0);
	ATF_REQUIRE(pledge("stdio", "") >= 0);
	errno = 0;
	ATF_REQUIRE(isatty(fd) == 0);
	ATF_CHECK_EQ(ENOTTY, errno);
}

ATF_TC_WITHOUT_HEAD(isatty_pipe);
ATF_TC_BODY(isatty_pipe, tc)
{
	int fds[2];
	ATF_REQUIRE(pipe(fds) >= 0);
	ATF_REQUIRE(pledge("stdio", "") >= 0);
	errno = 0;
	ATF_REQUIRE(isatty(fds[0]) == 0);
	ATF_CHECK_EQ(ENOTTY, errno);
	ATF_REQUIRE(isatty(fds[1]) == 0);
	ATF_CHECK_EQ(ENOTTY, errno);
}

static const int misc_test_ioctls[] = {
	TIOCSBRK,
	TIOCCBRK,
	TIOCSDTR,
	TIOCCDTR,
	TIOCSTOP,
	TIOCSTART,
	TIOCSCTTY,
	TIOCDRAIN,
	TIOCEXCL,
	TIOCNXCL,
};

ATF_TC_WITHOUT_HEAD(tty_ioctls_pass_enotty);
ATF_TC_BODY(tty_ioctls_pass_enotty, tc)
{
	int fd;
	struct winsize ws;
	ATF_REQUIRE((fd = creat("test", 0666)) >= 0);
	ATF_REQUIRE(pledge("error stdio tty", "") >= 0);
	ATF_CHECK_ERRNO(ENOTTY, ioctl(fd, TIOCGWINSZ, &ws) < 0);
	for (size_t i = 0; i < nitems(misc_test_ioctls); i++)
		ATF_CHECK_ERRNO(ENOTTY, ioctl(fd, misc_test_ioctls[i]) < 0);
}

ATF_TC_WITHOUT_HEAD(tty_ioctls_deny);
ATF_TC_BODY(tty_ioctls_deny, tc)
{
	int fd;
	struct winsize ws;
	ATF_REQUIRE((fd = creat("test", 0666)) >= 0);
	ATF_REQUIRE(pledge("error stdio", "") >= 0);
	ATF_CHECK_ERRNO(EPERM, ioctl(fd, TIOCGWINSZ, &ws) < 0);
	for (size_t i = 0; i < nitems(misc_test_ioctls); i++)
		ATF_CHECK_ERRNO(EPERM, ioctl(fd, misc_test_ioctls[i]) < 0);
}

ATF_TC_WITHOUT_HEAD(openpty);
ATF_TC_BODY(openpty, tc)
{
	char path[PATH_MAX];
	struct termios tt;
	struct winsize ws;
	int master_fd, slave_fd;
	ATF_REQUIRE(pledge("error stdio pts", "") >= 0);
	ATF_REQUIRE(openpty(&master_fd, &slave_fd, path, NULL, NULL) >= 0);
	ATF_CHECK(isatty(slave_fd) > 0);
	check_access(path, "rw");
	ATF_CHECK(tcgetattr(slave_fd, &tt) >= 0);
	ATF_CHECK(tcsetattr(master_fd, TCSANOW, &tt) >= 0);
	ATF_CHECK(tcgetattr(master_fd, &tt) >= 0);
	ATF_CHECK(tcsetattr(slave_fd, TCSANOW, &tt) >= 0);
	ATF_CHECK(ioctl(slave_fd, TIOCGWINSZ, &ws) >= 0);
	ATF_CHECK(ioctl(master_fd, TIOCSWINSZ, &ws) >= 0);
	ATF_CHECK(ioctl(master_fd, TIOCGWINSZ, &ws) >= 0);
	ATF_CHECK(ioctl(slave_fd, TIOCSWINSZ, &ws) >= 0);
	ATF_CHECK(close(slave_fd) >= 0);
	ATF_CHECK(close(master_fd) >= 0);
}

ATF_TC_WITHOUT_HEAD(forkpty);
ATF_TC_BODY(forkpty, tc)
{
	char path[PATH_MAX];
	int master_fd, stderr_fd;
	int status;
	pid_t pid;
	ATF_REQUIRE(pledge("error stdio proc pts", "") >= 0);
	ATF_CHECK((stderr_fd = dup(STDERR_FILENO)) >= 0);
	ATF_REQUIRE((pid = forkpty(&master_fd, path, NULL, NULL)) >= 0);
	if (pid == 0) {
		dup2(stderr_fd, STDERR_FILENO);
		ATF_CHECK(isatty(STDIN_FILENO) > 0);
		ATF_CHECK(isatty(STDOUT_FILENO) > 0);
		ATF_CHECK(isatty(STDERR_FILENO) > 0);
		check_access(path, "rw");
		_exit(0);
	}
	ATF_REQUIRE(waitpid(pid, &status, WEXITED) == pid);
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_CHECK(close(master_fd) >= 0);
}

ATF_TC_WITHOUT_HEAD(openpty_barrier);
ATF_TC_BODY(openpty_barrier, tc)
{
	char path[PATH_MAX];
	int master_fd, slave_fd;
	ATF_REQUIRE(openpty(&master_fd, &slave_fd, path, NULL, NULL) >= 0);
	/* pledge() does not generally introduce barriers, but device barriers
	 * are an exception. */
	ATF_REQUIRE(pledge("error stdio pts", "") >= 0);
	ATF_CHECK(isatty(slave_fd) > 0);
	check_access(path, "");
	ATF_CHECK(close(slave_fd) >= 0);
	ATF_CHECK(close(master_fd) >= 0);
}

ATF_TC_WITHOUT_HEAD(devfs_path_discovery);
ATF_TC_BODY(devfs_path_discovery, tc)
{
	/* This should unveil /dev with UPERM_DEVFS. */
	ATF_REQUIRE(pledge("error stdio tty pts", "") >= 0);
	/* Check that ENOTDIR errors do not betray the existence of hidden device files. */
	const char *paths[] = {
#define		EXPAND(s) s, s "/", s "/.", s "/..", s "/x", s "/../x", s "/../" s
		EXPAND("/dev/io"),
		EXPAND("/dev/mem"),
#undef		EXPAND
	};
	for (size_t i = 0; i < nitems(paths); i++)
		check_access(paths[i], "");
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, isatty_vnode);
	ATF_TP_ADD_TC(tp, isatty_pipe);
	ATF_TP_ADD_TC(tp, tty_ioctls_pass_enotty);
	ATF_TP_ADD_TC(tp, tty_ioctls_deny);
	ATF_TP_ADD_TC(tp, openpty);
	ATF_TP_ADD_TC(tp, forkpty);
	ATF_TP_ADD_TC(tp, openpty_barrier);
	ATF_TP_ADD_TC(tp, devfs_path_discovery);
	return (atf_no_error());
}
