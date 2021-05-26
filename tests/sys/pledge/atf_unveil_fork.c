#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <pledge.h>

#include "misc-utils.h"
#define CHECK_HARDER
#include "path-utils.h"

ATF_TC_WITHOUT_HEAD(fork_hide_all);
ATF_TC_BODY(fork_hide_all, tc)
{
	ATF_REQUIRE(unveil("/", "") >= 0);
	fork_deleg();
	check_access("/", "d");
	check_access("/etc", "d");
	check_access("/dev", "d");
	check_access("/var", "d");
}

ATF_TC_WITHOUT_HEAD(fork_unveil_one);
ATF_TC_BODY(fork_unveil_one, tc)
{
	atf_utils_create_file("test", "");
	ATF_REQUIRE(unveil("test", "r") >= 0);
	ATF_REQUIRE(unveil(NULL, NULL) >= 0);
	fork_deleg();
	check_access("test", "r");
}

ATF_TC_WITHOUT_HEAD(fork_reunveil_drop);
ATF_TC_BODY(fork_reunveil_drop, tc)
{
	atf_utils_create_file("test", "");
	ATF_REQUIRE(unveil("test", "rw") >= 0);
	ATF_REQUIRE(unveil(NULL, NULL) >= 0);
	fork_deleg();
	check_access("test", "rw");
	ATF_REQUIRE(unveil("test", "r") >= 0);
	check_access("test", "r");
}

ATF_TC_WITHOUT_HEAD(fork_reunveil_raise);
ATF_TC_BODY(fork_reunveil_raise, tc)
{
	atf_utils_create_file("test", "");
	ATF_REQUIRE(unveil("test", "r") >= 0);
	ATF_REQUIRE(unveil(NULL, NULL) >= 0);
	fork_deleg();
	check_access("test", "r");
	ATF_REQUIRE(unveil("test", "rw") >= 0);
	check_access("test", "r");
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, fork_hide_all);
	ATF_TP_ADD_TC(tp, fork_unveil_one);
	ATF_TP_ADD_TC(tp, fork_reunveil_drop);
	ATF_TP_ADD_TC(tp, fork_reunveil_raise);
	return (atf_no_error());
}
