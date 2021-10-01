#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <errno.h>
#include <atf-c.h>
#include <pledge.h>

extern char **environ;

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

ATF_TC_WITHOUT_HEAD(unveil_self_unrestrict);
ATF_TC_BODY(unveil_self_unrestrict, tc)
{
	pid_t pid = atf_utils_fork();
	if (pid == 0) {
		ATF_REQUIRE(unveil_self("/", "x") >= 0);
		ATF_REQUIRE(unveil_self(NULL, NULL) >= 0);
		ATF_REQUIRE(execlp("test", "test", "-r", "/etc/rc", NULL) >= 0);
		_exit(127);
	}
	atf_utils_wait(pid, 0, "", "");
}


static void
prepare_unveil_exec(void)
{
	ATF_REQUIRE(unveil("/libexec", "x") >= 0);
}


ATF_TC_WITHOUT_HEAD(exec_path_allow);
ATF_TC_BODY(exec_path_allow, tc)
{
	pid_t pid = atf_utils_fork();
	if (pid == 0) {
		const char *p = "/usr/bin/true";
		const char *v[] = { "true", NULL };
		prepare_unveil_exec();
		ATF_REQUIRE(unveil(p, "x") >= 0);
		ATF_REQUIRE(execve(p, __DECONST(char **, v), environ) >= 0);
		_exit(127);
	}
	atf_utils_wait(pid, 0, "", "");
}

ATF_TC_WITHOUT_HEAD(exec_path_deny);
ATF_TC_BODY(exec_path_deny, tc)
{
	pid_t pid = atf_utils_fork();
	if (pid == 0) {
		const char *p = "/usr/bin/false";
		const char *v[] = { "false", NULL };
		prepare_unveil_exec();
		ATF_REQUIRE(unveil(p, "r") >= 0);
		ATF_REQUIRE_ERRNO(EACCES, execve(p, __DECONST(char **, v), environ) < 0);
		ATF_REQUIRE(unveil(p, "") >= 0);
		ATF_REQUIRE_ERRNO(ENOENT, execve(p, __DECONST(char **, v), environ) < 0);
		_exit(0);
	}
	atf_utils_wait(pid, 0, "", "");
}


ATF_TC_WITHOUT_HEAD(fexec_path_allow_1);
ATF_TC_BODY(fexec_path_allow_1, tc)
{
	pid_t pid = atf_utils_fork();
	if (pid == 0) {
		const char *p = "/usr/bin/true";
		const char *v[] = { "true", NULL };
		int fd;
		prepare_unveil_exec();
		ATF_REQUIRE(unveil(p, "rx") >= 0);
		ATF_REQUIRE((fd = open(p, O_RDONLY)) >= 0);
		ATF_REQUIRE(fexecve(fd, __DECONST(char **, v), environ) >= 0);
		_exit(127);
	}
	atf_utils_wait(pid, 0, "", "");
}

ATF_TC_WITHOUT_HEAD(fexec_path_allow_2);
ATF_TC_BODY(fexec_path_allow_2, tc)
{
	pid_t pid = atf_utils_fork();
	if (pid == 0) {
		const char *p = "/usr/bin/true";
		const char *v[] = { "true", NULL };
		int fd;
		prepare_unveil_exec();
		ATF_REQUIRE(unveil(p, "x") >= 0);
		ATF_REQUIRE((fd = open(p, O_EXEC)) >= 0);
		ATF_REQUIRE(unveil(p, "") >= 0);
		ATF_REQUIRE(fexecve(fd, __DECONST(char **, v), environ) >= 0);
		_exit(127);
	}
	atf_utils_wait(pid, 0, "", "");
}

ATF_TC_WITHOUT_HEAD(fexec_path_deny_1);
ATF_TC_BODY(fexec_path_deny_1, tc)
{
	pid_t pid = atf_utils_fork();
	if (pid == 0) {
		const char *p = "/usr/bin/false";
		const char *v[] = { "false", NULL };
		int fd;
		prepare_unveil_exec();
		ATF_REQUIRE(unveil(p, "r") >= 0);
		ATF_REQUIRE((fd = open(p, O_RDONLY)) >= 0);
		ATF_REQUIRE_ERRNO(EACCES, fexecve(fd, __DECONST(char **, v), environ) < 0);
		_exit(0);
	}
	atf_utils_wait(pid, 0, "", "");
}

ATF_TC_WITHOUT_HEAD(fexec_path_deny_2);
ATF_TC_BODY(fexec_path_deny_2, tc)
{
	pid_t pid = atf_utils_fork();
	if (pid == 0) {
		const char *p = "/usr/bin/false";
		const char *v[] = { "false", NULL };
		int fd;
		prepare_unveil_exec();
		ATF_REQUIRE(unveil(p, "rx") >= 0);
		ATF_REQUIRE((fd = open(p, O_RDONLY)) >= 0);
		ATF_REQUIRE(unveil(p, "r") >= 0);
		ATF_REQUIRE_ERRNO(EACCES, fexecve(fd, __DECONST(char **, v), environ) < 0);
		_exit(0);
	}
	atf_utils_wait(pid, 0, "", "");
}


ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, unveil_unrestrict);
	ATF_TP_ADD_TC(tp, unveil_self_unrestrict);
	ATF_TP_ADD_TC(tp, exec_path_allow);
	ATF_TP_ADD_TC(tp, exec_path_deny);
	ATF_TP_ADD_TC(tp, fexec_path_allow_1);
	ATF_TP_ADD_TC(tp, fexec_path_allow_2);
	ATF_TP_ADD_TC(tp, fexec_path_deny_1);
	ATF_TP_ADD_TC(tp, fexec_path_deny_2);
	return (atf_no_error());
}
