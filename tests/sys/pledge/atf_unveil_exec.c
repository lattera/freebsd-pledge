#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <pledge.h>

#include "path-utils.h"

ATF_TC_WITHOUT_HEAD(unveil_unrestrict);
ATF_TC_BODY(unveil_unrestrict, tc)
{
	pid_t pid = atf_utils_fork();
	if (pid == 0) {
		ATF_REQUIRE(unveil("/", "x") >= 0);
		ATF_REQUIRE(unveil(NULL, NULL) >= 0);
		ATF_REQUIRE(execlp("test", "test", "-r", "/etc/rc", NULL) >= 0);
		_exit(127);
	}
	atf_utils_wait(pid, 0, "", "");
}

ATF_TC_WITHOUT_HEAD(unveilself_unrestrict);
ATF_TC_BODY(unveilself_unrestrict, tc)
{
	pid_t pid = atf_utils_fork();
	if (pid == 0) {
		ATF_REQUIRE(unveilself("/", "x") >= 0);
		ATF_REQUIRE(unveilself(NULL, NULL) >= 0);
		ATF_REQUIRE(execlp("test", "test", "-r", "/etc/rc", NULL) >= 0);
		_exit(127);
	}
	atf_utils_wait(pid, 0, "", "");
}

ATF_TC_WITHOUT_HEAD(exec_unveiled_path_allow);
ATF_TC_BODY(exec_unveiled_path_allow, tc)
{
	pid_t pid = atf_utils_fork();
	if (pid == 0) {
		const char *p = "/usr/bin/true";
		ATF_REQUIRE(unveil("/", "") >= 0);
		ATF_REQUIRE(unveil(p, "x") >= 0);
		ATF_REQUIRE(unveil("/libexec", "x") >= 0);
		ATF_REQUIRE(execl(p, "true", (char *)NULL) >= 0);
		_exit(127);
	}
	atf_utils_wait(pid, 0, "", "");
}

ATF_TC_WITHOUT_HEAD(exec_unveiled_path_deny);
ATF_TC_BODY(exec_unveiled_path_deny, tc)
{
	pid_t pid = atf_utils_fork();
	if (pid == 0) {
		const char *p = "/usr/bin/false";
		ATF_REQUIRE(unveil("/", "") >= 0);
		ATF_REQUIRE(unveil("/libexec", "x") >= 0);
		ATF_REQUIRE_ERRNO(ENOENT, execl(p, "false", (char *)NULL) < 0);
		_exit(0);
	}
	atf_utils_wait(pid, 0, "", "");
}

ATF_TC_WITHOUT_HEAD(exec_pledge_unveiled_path_allow);
ATF_TC_BODY(exec_pledge_unveiled_path_allow, tc)
{
	pid_t pid = atf_utils_fork();
	if (pid == 0) {
		const char *p = "/usr/bin/true";
		ATF_REQUIRE(pledge("stdio rpath exec", NULL) >= 0);
		ATF_REQUIRE(unveil("/", "") >= 0);
		ATF_REQUIRE(unveil(p, "x") >= 0);
		ATF_REQUIRE(execl(p, "true", (char *)NULL) >= 0);
		_exit(127);
	}
	atf_utils_wait(pid, 0, "", "");
}

ATF_TC_WITHOUT_HEAD(exec_pledge_unveiled_path_deny);
ATF_TC_BODY(exec_pledge_unveiled_path_deny, tc)
{
	pid_t pid = atf_utils_fork();
	if (pid == 0) {
		const char *p = "/usr/bin/false";
		ATF_REQUIRE(pledge("stdio rpath exec", NULL) >= 0);
		ATF_REQUIRE(unveil("/", "") >= 0);
		ATF_REQUIRE_ERRNO(ENOENT, execl(p, "false", (char *)NULL) < 0);
		_exit(0);
	}
	atf_utils_wait(pid, 0, "", "");
}


ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, unveil_unrestrict);
	ATF_TP_ADD_TC(tp, unveilself_unrestrict);
	ATF_TP_ADD_TC(tp, exec_unveiled_path_allow);
	ATF_TP_ADD_TC(tp, exec_unveiled_path_deny);
	ATF_TP_ADD_TC(tp, exec_pledge_unveiled_path_allow);
	ATF_TP_ADD_TC(tp, exec_pledge_unveiled_path_deny);
	return (atf_no_error());
}
