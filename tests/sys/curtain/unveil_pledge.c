#include <stdio.h>
#include <atf-c.h>
#include <pledge.h>

#include "path-utils.h"

ATF_TC_WITHOUT_HEAD(drop_nothing);
ATF_TC_BODY(drop_nothing, tc)
{
	atf_utils_create_file("test", "");
	ATF_REQUIRE(pledge("stdio rpath wpath unveil", "") >= 0);
	ATF_REQUIRE(unveil("test", "rw") >= 0);
	ATF_REQUIRE(pledge("stdio rpath wpath", "") >= 0);
	check_access("test", "rw");
}

ATF_TC_WITHOUT_HEAD(drop_read);
ATF_TC_BODY(drop_read, tc)
{
	atf_utils_create_file("test", "");
	ATF_REQUIRE(pledge("stdio rpath wpath unveil", "") >= 0);
	ATF_REQUIRE(unveil("test", "rw") >= 0);
	ATF_REQUIRE(pledge("stdio wpath", "") >= 0);
	check_access("test", "w");
}

ATF_TC_WITHOUT_HEAD(drop_write);
ATF_TC_BODY(drop_write, tc)
{
	atf_utils_create_file("test", "");
	ATF_REQUIRE(pledge("stdio rpath wpath unveil", "") >= 0);
	ATF_REQUIRE(unveil("test", "rw") >= 0);
	ATF_REQUIRE(pledge("stdio rpath", "") >= 0);
	check_access("test", "r");
}

ATF_TC_WITHOUT_HEAD(drop_all);
ATF_TC_BODY(drop_all, tc)
{
	atf_utils_create_file("test", "");
	ATF_REQUIRE(pledge("stdio rpath wpath unveil", "") >= 0);
	ATF_REQUIRE(unveil("test", "rw") >= 0);
	ATF_REQUIRE(pledge("stdio", "") >= 0);
	check_access("test", "");
}

ATF_TC_WITHOUT_HEAD(drop_write_raise_allow);
ATF_TC_BODY(drop_write_raise_allow, tc)
{
	atf_utils_create_file("test", "");
	ATF_REQUIRE(pledge("stdio rpath wpath unveil", "") >= 0);
	ATF_REQUIRE(unveil("test", "r") >= 0);
	ATF_REQUIRE(pledge("stdio rpath wpath unveil", "") >= 0);
	check_access("test", "r");
	ATF_REQUIRE(unveil("test", "rw") >= 0);
	check_access("test", "rw");
}

ATF_TC_WITHOUT_HEAD(drop_write_raise_deny);
ATF_TC_BODY(drop_write_raise_deny, tc)
{
	atf_utils_create_file("test", "");
	ATF_REQUIRE(pledge("stdio rpath wpath unveil", "") >= 0);
	ATF_REQUIRE(unveil("test", "rw") >= 0);
	ATF_REQUIRE(pledge("stdio rpath unveil", "") >= 0);
	check_access("test", "r");
	ATF_REQUIRE(unveil("test", "rw") >= 0);
	check_access("test", "r");
}

ATF_TC_WITHOUT_HEAD(stdio_path_not_hidden);
ATF_TC_BODY(stdio_path_not_hidden, tc)
{
	ATF_REQUIRE(pledge("stdio rpath wpath unveil", "") >= 0);
	ATF_REQUIRE(unveil_freeze() >= 0);
	check_access("/dev/null", "rw");
}

ATF_TC_WITHOUT_HEAD(stdio_path_perms_merged);
ATF_TC_BODY(stdio_path_perms_merged, tc)
{
	ATF_REQUIRE(pledge("stdio rpath wpath unveil", "") >= 0);
	ATF_REQUIRE(unveil("/dev/null", "r") >= 0);
	check_access("/dev/null", "rw");
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, drop_nothing);
	ATF_TP_ADD_TC(tp, drop_write);
	ATF_TP_ADD_TC(tp, drop_write_raise_deny);
	ATF_TP_ADD_TC(tp, drop_write_raise_allow);
	ATF_TP_ADD_TC(tp, drop_read);
	ATF_TP_ADD_TC(tp, drop_all);
	ATF_TP_ADD_TC(tp, stdio_path_not_hidden);
	ATF_TP_ADD_TC(tp, stdio_path_perms_merged);
	return (atf_no_error());
}
