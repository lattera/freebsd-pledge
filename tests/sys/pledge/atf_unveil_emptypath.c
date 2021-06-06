#include <stdio.h>
#include <atf-c.h>
#include <pledge.h>

#include "path-utils.h"

ATF_TC_WITHOUT_HEAD(open_empty_path_rdonly_allow);
ATF_TC_BODY(open_empty_path_rdonly_allow, tc)
{
	int fd;
	ATF_REQUIRE(try_creat("f") >= 0);
	ATF_REQUIRE(unveil("f", "r") >= 0);
	check_access("f", "r");
	ATF_REQUIRE((fd = open("f", O_RDONLY)) >= 0);
	ATF_CHECK(openat(fd, "", O_RDONLY | O_EMPTY_PATH) >= 0);
}

ATF_TC_WITHOUT_HEAD(open_empty_path_rdonly_deny);
ATF_TC_BODY(open_empty_path_rdonly_deny, tc)
{
	int fd;
	ATF_REQUIRE(try_creat("f") >= 0);
	ATF_REQUIRE(unveil("f", "r") >= 0);
	check_access("f", "r");
	ATF_REQUIRE((fd = open("f", O_RDONLY)) >= 0);
	ATF_CHECK_ERRNO(EACCES, openat(fd, "", O_WRONLY | O_EMPTY_PATH) < 0);
	ATF_CHECK_ERRNO(EACCES, openat(fd, "", O_RDWR | O_EMPTY_PATH) < 0);
	ATF_CHECK_ERRNO(EACCES, openat(fd, "", O_EXEC | O_EMPTY_PATH) < 0);
}

ATF_TC_WITHOUT_HEAD(open_empty_path_wronly_allow);
ATF_TC_BODY(open_empty_path_wronly_allow, tc)
{
	int fd;
	ATF_REQUIRE(try_creat("f") >= 0);
	ATF_REQUIRE(unveil("f", "w") >= 0);
	check_access("f", "w");
	ATF_REQUIRE((fd = open("f", O_WRONLY)) >= 0);
	ATF_CHECK(openat(fd, "", O_WRONLY | O_EMPTY_PATH) >= 0);
}

ATF_TC_WITHOUT_HEAD(open_empty_path_wronly_deny);
ATF_TC_BODY(open_empty_path_wronly_deny, tc)
{
	int fd;
	ATF_REQUIRE(try_creat("f") >= 0);
	ATF_REQUIRE(unveil("f", "w") >= 0);
	check_access("f", "w");
	ATF_REQUIRE((fd = open("f", O_WRONLY)) >= 0);
	ATF_CHECK_ERRNO(EACCES, openat(fd, "", O_RDONLY | O_EMPTY_PATH) < 0);
	ATF_CHECK_ERRNO(EACCES, openat(fd, "", O_RDWR | O_EMPTY_PATH) < 0);
	ATF_CHECK_ERRNO(EACCES, openat(fd, "", O_EXEC | O_EMPTY_PATH) < 0);
}

ATF_TC_WITHOUT_HEAD(open_empty_path_exec_allow);
ATF_TC_BODY(open_empty_path_exec_allow, tc)
{
	int fd;
	ATF_REQUIRE(try_creat("f") >= 0);
	ATF_REQUIRE(chmod("f", 0755) >= 0);
	ATF_REQUIRE(unveil("f", "x") >= 0);
	check_access("f", "x");
	ATF_REQUIRE((fd = open("f", O_EXEC)) >= 0);
	ATF_CHECK(openat(fd, "", O_EXEC | O_EMPTY_PATH) >= 0);
}

ATF_TC_WITHOUT_HEAD(open_empty_path_exec_deny);
ATF_TC_BODY(open_empty_path_exec_deny, tc)
{
	int fd;
	ATF_REQUIRE(try_creat("f") >= 0);
	ATF_REQUIRE(chmod("f", 0755) >= 0);
	ATF_REQUIRE(unveil("f", "x") >= 0);
	check_access("f", "x");
	ATF_REQUIRE((fd = open("f", O_EXEC)) >= 0);
	ATF_CHECK_ERRNO(EACCES, openat(fd, "", O_RDONLY | O_EMPTY_PATH) < 0);
	ATF_CHECK_ERRNO(EACCES, openat(fd, "", O_WRONLY | O_EMPTY_PATH) < 0);
	ATF_CHECK_ERRNO(EACCES, openat(fd, "", O_RDWR | O_EMPTY_PATH) < 0);
}

ATF_TC_WITHOUT_HEAD(open_empty_path_search_allow);
ATF_TC_BODY(open_empty_path_search_allow, tc)
{
	int fd;
	ATF_REQUIRE(try_mkdir("d") >= 0);
	ATF_REQUIRE(unveil("d", "c") >= 0);
	check_access("d", "de");
	ATF_REQUIRE((fd = open("d", O_SEARCH)) >= 0);
	ATF_CHECK(openat(fd, "", O_SEARCH | O_EMPTY_PATH) >= 0);
}

ATF_TC_WITHOUT_HEAD(open_empty_path_search_deny);
ATF_TC_BODY(open_empty_path_search_deny, tc)
{
	int fd;
	ATF_REQUIRE(try_mkdir("d") >= 0);
	ATF_REQUIRE(unveil("d", "c") >= 0);
	check_access("d", "de");
	ATF_REQUIRE((fd = open("d", O_SEARCH)) >= 0);
	ATF_CHECK_ERRNO(EACCES, openat(fd, "", O_RDONLY | O_EMPTY_PATH) < 0);
}


ATF_TC_WITHOUT_HEAD(open_empty_path_regain_read);
ATF_TC_BODY(open_empty_path_regain_read, tc)
{
	int fd;
	ATF_REQUIRE(try_creat("f") >= 0);
	ATF_REQUIRE(unveil("f", "r") >= 0);
	check_access("f", "r");
	ATF_REQUIRE((fd = open("f", O_PATH)) >= 0);
	ATF_CHECK(openat(fd, "", O_EMPTY_PATH | O_RDONLY) >= 0);
	ATF_CHECK_ERRNO(EACCES, openat(fd, "", O_EMPTY_PATH | O_WRONLY) < 0);
	ATF_CHECK_ERRNO(EACCES, openat(fd, "", O_EMPTY_PATH | O_RDWR) < 0);
	ATF_CHECK_ERRNO(EACCES, openat(fd, "", O_EMPTY_PATH | O_EXEC) < 0);
}

ATF_TC_WITHOUT_HEAD(open_empty_path_regain_write);
ATF_TC_BODY(open_empty_path_regain_write, tc)
{
	int fd;
	ATF_REQUIRE(try_creat("f") >= 0);
	ATF_REQUIRE(unveil("f", "w") >= 0);
	check_access("f", "w");
	ATF_REQUIRE((fd = open("f", O_PATH)) >= 0);
	ATF_CHECK(openat(fd, "", O_EMPTY_PATH | O_WRONLY) >= 0);
	ATF_CHECK_ERRNO(EACCES, openat(fd, "", O_EMPTY_PATH | O_RDONLY) < 0);
	ATF_CHECK_ERRNO(EACCES, openat(fd, "", O_EMPTY_PATH | O_RDWR) < 0);
	ATF_CHECK_ERRNO(EACCES, openat(fd, "", O_EMPTY_PATH | O_EXEC) < 0);
}

ATF_TC_WITHOUT_HEAD(open_empty_path_regain_exec);
ATF_TC_BODY(open_empty_path_regain_exec, tc)
{
	int fd;
	ATF_REQUIRE(try_creat("f") >= 0);
	ATF_REQUIRE(chmod("f", 0755) >= 0);
	ATF_REQUIRE(unveil("f", "x") >= 0);
	check_access("f", "x");
	ATF_REQUIRE((fd = open("f", O_PATH)) >= 0);
	ATF_CHECK(openat(fd, "", O_EMPTY_PATH | O_EXEC) >= 0);
	ATF_CHECK_ERRNO(EACCES, openat(fd, "", O_EMPTY_PATH | O_RDONLY) < 0);
	ATF_CHECK_ERRNO(EACCES, openat(fd, "", O_EMPTY_PATH | O_WRONLY) < 0);
	ATF_CHECK_ERRNO(EACCES, openat(fd, "", O_EMPTY_PATH | O_RDWR) < 0);
}


ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, open_empty_path_rdonly_allow);
	ATF_TP_ADD_TC(tp, open_empty_path_rdonly_deny);
	ATF_TP_ADD_TC(tp, open_empty_path_wronly_allow);
	ATF_TP_ADD_TC(tp, open_empty_path_wronly_deny);
	ATF_TP_ADD_TC(tp, open_empty_path_exec_allow);
	ATF_TP_ADD_TC(tp, open_empty_path_exec_deny);
	ATF_TP_ADD_TC(tp, open_empty_path_search_allow);
	ATF_TP_ADD_TC(tp, open_empty_path_search_deny);
	ATF_TP_ADD_TC(tp, open_empty_path_regain_read);
	ATF_TP_ADD_TC(tp, open_empty_path_regain_write);
	ATF_TP_ADD_TC(tp, open_empty_path_regain_exec);
	return (atf_no_error());
}
