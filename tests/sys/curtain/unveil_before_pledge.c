#include <stdio.h>
#include <atf-c.h>
#include <pledge.h>

#include "path-utils.h"

ATF_TC_WITHOUT_HEAD(hides_fs);
ATF_TC_BODY(hides_fs, tc)
{
	ATF_REQUIRE(unveil_freeze() >= 0);
	ATF_REQUIRE(pledge("stdio", "") >= 0);
	check_access("/", "d");
	check_access("/dev", "d");
	check_access("/etc", "d");
	check_access("/var", "d");
}

ATF_TC_WITHOUT_HEAD(stdio_paths);
ATF_TC_BODY(stdio_paths, tc)
{
	ATF_REQUIRE(unveil_freeze() >= 0);
	ATF_REQUIRE(pledge("stdio", "") >= 0);
	check_access("/dev/null", "rw");
	check_access("/dev/random", "r");
}

ATF_TC_WITHOUT_HEAD(one_file);
ATF_TC_BODY(one_file, tc)
{
	atf_utils_create_file("test", "");
	ATF_REQUIRE(unveil("test", "r") >= 0);
	ATF_REQUIRE(unveil(NULL, NULL) >= 0);
	ATF_REQUIRE(pledge("stdio rpath", "") >= 0);
	check_access("test", "r");
}

ATF_TC_WITHOUT_HEAD(interspersed);
ATF_TC_BODY(interspersed, tc)
{
	atf_utils_create_file("test", "");
	ATF_REQUIRE(unveil("test", "r") >= 0);
	ATF_REQUIRE(pledge("stdio rpath", "") >= 0);
	ATF_REQUIRE(unveil(NULL, NULL) >= 0);
	check_access("test", "r");
}

ATF_TC_WITHOUT_HEAD(drop_perm_with_pledge);
ATF_TC_BODY(drop_perm_with_pledge, tc)
{
	atf_utils_create_file("test", "");
	ATF_REQUIRE(unveil("test", "rw") >= 0);
	ATF_REQUIRE(unveil(NULL, NULL) >= 0);
	check_access("test", "rw");
	ATF_REQUIRE(pledge("stdio rpath", "") >= 0);
	check_access("test", "r");
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, hides_fs);
	ATF_TP_ADD_TC(tp, stdio_paths);
	ATF_TP_ADD_TC(tp, one_file);
	ATF_TP_ADD_TC(tp, interspersed);
	ATF_TP_ADD_TC(tp, drop_perm_with_pledge);
	return (atf_no_error());
}
