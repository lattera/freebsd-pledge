#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/signal.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <pledge.h>

ATF_TC_WITHOUT_HEAD(error_no_signal);
ATF_TC_BODY(error_no_signal, tc)
{
	ATF_REQUIRE(pledge("stdio error", "") >= 0);
	ATF_CHECK_ERRNO(EPERM, kill(getppid(), SIGTERM) < 0);
}

ATF_TC_WITHOUT_HEAD(violation_signal);
ATF_TC_BODY(violation_signal, tc)
{
	atf_tc_expect_signal(SIGKILL, "pledge violation");
	ATF_REQUIRE(pledge("stdio", "") >= 0);
	kill(getppid(), SIGTERM);
}

ATF_TC_WITHOUT_HEAD(fcntl_setown_allow);
ATF_TC_BODY(fcntl_setown_allow, tc)
{
	int fds[2], fd;
	ATF_REQUIRE(pledge("stdio proc", "") >= 0);
	ATF_REQUIRE(pipe(fds) >= 0);
	ATF_CHECK(close(fds[0]) >= 0);
	fd = fds[1];
	ATF_CHECK(fcntl(fd, F_SETOWN, getpid()) >= 0);
	ATF_CHECK(close(fd) >= 0);
}

ATF_TC_WITHOUT_HEAD(fcntl_setown_deny);
ATF_TC_BODY(fcntl_setown_deny, tc)
{
	int fds[2], fd;
	ATF_REQUIRE(pledge("stdio error", "") >= 0);
	ATF_REQUIRE(pipe(fds) >= 0);
	ATF_CHECK(close(fds[0]) >= 0);
	fd = fds[1];
	ATF_CHECK_ERRNO(EPERM, fcntl(fd, F_SETOWN, getpid()) < 0);
	ATF_CHECK(close(fd) >= 0);
}

#if 0

ATF_TC_WITHOUT_HEAD(can_signal_child);
ATF_TC_BODY(can_signal_child, tc)
{
	pid_t pid;
	int fds[2], status;
	ATF_REQUIRE(pledge("stdio error proc_barrier", "") >= 0);
	ATF_REQUIRE(pipe(fds) >= 0);
	ATF_REQUIRE((pid = fork()) >= 0);
	if (pid == 0) {
		ATF_REQUIRE(close(fds[1]) >= 0);
		char c;
		ATF_REQUIRE(read(fds[0], &c, sizeof c) >= 0); /* wait for parent to try to kill */
		ATF_REQUIRE(close(fds[0]) >= 0);
		_exit(1);
	}
	ATF_CHECK(close(fds[0]) >= 0);
	ATF_CHECK(kill(pid, SIGHUP) >= 0);
	ATF_CHECK(close(fds[1]) >= 0);
	ATF_REQUIRE(waitpid(pid, &status, WEXITED) == pid);
	ATF_CHECK(WIFSIGNALED(status));
	ATF_CHECK_EQ(SIGHUP, WTERMSIG(status));
}

ATF_TC_WITHOUT_HEAD(cannot_signal_parent);
ATF_TC_BODY(cannot_signal_parent, tc)
{
	pid_t pid;
	int fds[2], status;
	ATF_REQUIRE(pipe(fds) >= 0);
	ATF_REQUIRE((pid = fork()) >= 0);
	if (pid == 0) {
		ATF_REQUIRE(pledge("stdio error proc_barrier", "") >= 0);
		ATF_REQUIRE_ERRNO(ESRCH, kill(getppid(), SIGHUP) < 0);
		ATF_REQUIRE(close(fds[0]) >= 0);
		ATF_REQUIRE(close(fds[1]) >= 0);
		_exit(0);
	}
	ATF_CHECK(close(fds[1]) >= 0);
	char c;
	ATF_CHECK(read(fds[0], &c, sizeof c) >= 0); /* wait for child to try to kill */
	ATF_CHECK(close(fds[0]) >= 0);
	ATF_REQUIRE(waitpid(pid, &status, WEXITED) == pid);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
}

#endif

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, fcntl_setown_allow);
	ATF_TP_ADD_TC(tp, fcntl_setown_deny);
	ATF_TP_ADD_TC(tp, error_no_signal);
	ATF_TP_ADD_TC(tp, violation_signal);
#if 0
	ATF_TP_ADD_TC(tp, can_signal_child);
	ATF_TP_ADD_TC(tp, cannot_signal_parent);
#endif
	return (atf_no_error());
}
