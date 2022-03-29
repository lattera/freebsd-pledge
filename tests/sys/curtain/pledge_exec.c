#include <stdio.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <pledge.h>

ATF_TC_WITHOUT_HEAD(no_pledge);
ATF_TC_BODY(no_pledge, tc)
{
	pid_t pid = atf_utils_fork();
	if (pid == 0) {
		ATF_REQUIRE(execlp("true", "true", NULL) >= 0);
		_exit(1);
	}
	atf_utils_wait(pid, 0, "", "");
}

ATF_TC_WITHOUT_HEAD(self_pledge);
ATF_TC_BODY(self_pledge, tc)
{
	pid_t pid = atf_utils_fork();
	if (pid == 0) {
		ATF_REQUIRE(pledge("stdio exec", NULL) >= 0);
		ATF_REQUIRE(execlp("true", "true", NULL) >= 0);
		_exit(1);
	}
	atf_utils_wait(pid, 0, "", "");
}

ATF_TC_WITHOUT_HEAD(exec_pledge);
ATF_TC_BODY(exec_pledge, tc)
{
	pid_t pid = atf_utils_fork();
	if (pid == 0) {
		ATF_REQUIRE(pledge(NULL, "stdio rpath") >= 0);
		ATF_REQUIRE(execlp("true", "true", NULL) >= 0);
		_exit(1);
	}
	atf_utils_wait(pid, 0, "", "");
}

ATF_TC_WITHOUT_HEAD(self_exec_pledge);
ATF_TC_BODY(self_exec_pledge, tc)
{
	pid_t pid = atf_utils_fork();
	if (pid == 0) {
		ATF_REQUIRE(pledge("stdio exec", "stdio rpath") >= 0);
		ATF_REQUIRE(execlp("true", "true", NULL) >= 0);
		_exit(1);
	}
	atf_utils_wait(pid, 0, "", "");
}

ATF_TC_WITHOUT_HEAD(self_exec_pledge_chained);
ATF_TC_BODY(self_exec_pledge_chained, tc)
{
	pid_t pid = atf_utils_fork();
	if (pid == 0) {
		ATF_REQUIRE(pledge("stdio exec", "stdio exec rpath") >= 0);
		ATF_REQUIRE(execlp("env", "env", "true", NULL) >= 0);
		_exit(1);
	}
	atf_utils_wait(pid, 0, "", "");
}


static char *
prepare_suid_check(const struct atf_tc *tc)
{
	char *suid_check_path;
	ATF_REQUIRE(asprintf(&suid_check_path, "%s/%s",
		    atf_tc_get_config_var(tc, "srcdir"), "suid-check") > 0);
	pid_t pid;
	int status;
	if (geteuid() == 0)
		atf_tc_skip("already running as superuser");
	ATF_REQUIRE((pid = fork()) >= 0);
	if (pid == 0) {
		execl(suid_check_path, suid_check_path, (char *)NULL);
		_exit(127);
	}
	ATF_REQUIRE(waitpid(pid, &status, WEXITED) == pid);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE(WEXITSTATUS(status) >= 30 && WEXITSTATUS(status) <= (30 + 3));
	if (WEXITSTATUS(status) != 30)
		atf_tc_skip("suid execution already disabled");
	return (suid_check_path);
}

ATF_TC_WITHOUT_HEAD(suid_no_pledge);
ATF_TC_BODY(suid_no_pledge, tc)
{
	const char *suid_check_path = prepare_suid_check(tc);
	pid_t pid = atf_utils_fork();
	if (pid == 0) {
		ATF_REQUIRE(execl(suid_check_path, suid_check_path, (char *)NULL) >= 0);
		_exit(127);
	}
	atf_utils_wait(pid, 30 + 0, "", "");
}

ATF_TC_WITHOUT_HEAD(suid_self_pledge);
ATF_TC_BODY(suid_self_pledge, tc)
{
	const char *suid_check_path = prepare_suid_check(tc);
	pid_t pid = atf_utils_fork();
	if (pid == 0) {
		ATF_REQUIRE(pledge("stdio exec", NULL) >= 0);
		ATF_REQUIRE(execl(suid_check_path, suid_check_path, (char *)NULL) >= 0);
		_exit(127);
	}
	atf_utils_wait(pid, 30 + 0, "", "");
}

ATF_TC_WITHOUT_HEAD(suid_exec_pledge);
ATF_TC_BODY(suid_exec_pledge, tc)
{
	const char *suid_check_path = prepare_suid_check(tc);
	pid_t pid = atf_utils_fork();
	if (pid == 0) {
		ATF_REQUIRE(pledge(NULL, "stdio rpath") >= 0);
		ATF_REQUIRE(execl(suid_check_path, suid_check_path, (char *)NULL) >= 0);
		_exit(127);
	}
	atf_utils_wait(pid, 30 + 1, "", "");
}

ATF_TC_WITHOUT_HEAD(suid_self_exec_pledge);
ATF_TC_BODY(suid_self_exec_pledge, tc)
{
	const char *suid_check_path = prepare_suid_check(tc);
	pid_t pid = atf_utils_fork();
	if (pid == 0) {
		ATF_REQUIRE(pledge("stdio exec", "stdio rpath") >= 0);
		ATF_REQUIRE(execl(suid_check_path, suid_check_path, (char *)NULL) >= 0);
		_exit(127);
	}
	atf_utils_wait(pid, 30 + 1, "", "");
}

ATF_TC_WITHOUT_HEAD(suid_unveils);
ATF_TC_BODY(suid_unveils, tc)
{
	const char *suid_check_path = prepare_suid_check(tc);
	pid_t pid = atf_utils_fork();
	if (pid == 0) {
		ATF_REQUIRE(unveil_exec("/", "rx") >= 0);
		ATF_REQUIRE(unveil_exec("/etc/rc", "") >= 0);
		ATF_REQUIRE(unveil_exec(NULL, NULL) >= 0);
		ATF_REQUIRE(execl(suid_check_path, suid_check_path, (char *)NULL) >= 0);
		_exit(127);
	}
	atf_utils_wait(pid, 30 + 3, "", "");
}

ATF_TC_WITHOUT_HEAD(suid_unveils_unfinalized);
ATF_TC_BODY(suid_unveils_unfinalized, tc)
{
	const char *suid_check_path = prepare_suid_check(tc);
	pid_t pid = atf_utils_fork();
	if (pid == 0) {
		ATF_REQUIRE(unveil_exec("/", "rx") >= 0);
		ATF_REQUIRE(unveil_exec("/etc/rc", "") >= 0);
		ATF_REQUIRE(execl(suid_check_path, suid_check_path, (char *)NULL) >= 0);
		_exit(127);
	}
	atf_utils_wait(pid, 30 + 3, "", "");
}


ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, no_pledge);
	ATF_TP_ADD_TC(tp, self_pledge);
	ATF_TP_ADD_TC(tp, exec_pledge);
	ATF_TP_ADD_TC(tp, self_exec_pledge);
	ATF_TP_ADD_TC(tp, self_exec_pledge_chained);

	ATF_TP_ADD_TC(tp, suid_no_pledge);
	ATF_TP_ADD_TC(tp, suid_self_pledge);
	ATF_TP_ADD_TC(tp, suid_exec_pledge);
	ATF_TP_ADD_TC(tp, suid_self_exec_pledge);
	ATF_TP_ADD_TC(tp, suid_unveils);
	ATF_TP_ADD_TC(tp, suid_unveils_unfinalized);

	return (atf_no_error());
}
