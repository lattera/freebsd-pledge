#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <sys/ttycom.h>
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

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, isatty_vnode);
	ATF_TP_ADD_TC(tp, isatty_pipe);
	ATF_TP_ADD_TC(tp, tty_ioctls_pass_enotty);
	ATF_TP_ADD_TC(tp, tty_ioctls_deny);
	return (atf_no_error());
}
