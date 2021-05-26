#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <pledge.h>

#define CHECK_HARDER
#include "path-utils.h"

ATF_TC_WITHOUT_HEAD(chmod_deny);
ATF_TC_BODY(chmod_deny, tc)
{
	ATF_REQUIRE(try_creat("test") >= 0);
	ATF_REQUIRE(unveil("test", "rm") >= 0);
	ATF_CHECK_ERRNO(EACCES, chmod("test", 0755) < 0);
}

ATF_TC_WITHOUT_HEAD(chmod_allow);
ATF_TC_BODY(chmod_allow, tc)
{
	ATF_REQUIRE(try_creat("test") >= 0);
	ATF_REQUIRE(unveil("test", "rw") >= 0);
	ATF_CHECK(chmod("test", 0755) >= 0);
}

ATF_TC_WITHOUT_HEAD(fchmod_deny);
ATF_TC_BODY(fchmod_deny, tc)
{
	int fd;
	ATF_REQUIRE(try_creat("test") >= 0);
	ATF_REQUIRE(unveil("test", "rm") >= 0);
	ATF_REQUIRE((fd = open("test", O_RDWR)) >= 0);
	ATF_CHECK_ERRNO(EBADF, fchmod(fd, 0755) < 0);
}

ATF_TC_WITHOUT_HEAD(fchmod_allow);
ATF_TC_BODY(fchmod_allow, tc)
{
	int fd;
	ATF_REQUIRE(try_creat("test") >= 0);
	ATF_REQUIRE(unveil("test", "rw") >= 0);
	ATF_REQUIRE((fd = open("test", O_RDWR)) >= 0);
	ATF_CHECK(fchmod(fd, 0755) >= 0);
}

ATF_TC_WITHOUT_HEAD(fchmod_devfd_deny);
ATF_TC_BODY(fchmod_devfd_deny, tc)
{
	int fd, saved_fd;
	char *p;
	ATF_REQUIRE(try_creat("test") >= 0);
	ATF_REQUIRE(unveil("test", "rm") >= 0);
	ATF_REQUIRE(unveil("/dev/fd", "rw") >= 0);
	ATF_REQUIRE((fd = open("test", O_RDWR)) >= 0);
	ATF_REQUIRE((saved_fd = dup(STDOUT_FILENO)) >= 0);
	ATF_REQUIRE(dup2(fd, STDOUT_FILENO) == STDOUT_FILENO);
	ATF_REQUIRE(asprintf(&p, "/dev/fd/%d", STDOUT_FILENO) > 0);
	ATF_REQUIRE((fd = open(p, O_RDWR)) >= 0);
	ATF_CHECK_ERRNO(EBADF, fchmod(fd, 0755) < 0);
	ATF_CHECK(dup2(saved_fd, STDOUT_FILENO) == STDOUT_FILENO);
}

ATF_TC_WITHOUT_HEAD(fchmod_devfd_allow);
ATF_TC_BODY(fchmod_devfd_allow, tc)
{
	int fd, saved_fd;
	char *p;
	ATF_REQUIRE(try_creat("test") >= 0);
	ATF_REQUIRE(unveil("test", "rw") >= 0);
	ATF_REQUIRE(unveil("/dev/fd", "rw") >= 0);
	ATF_REQUIRE((fd = open("test", O_RDWR)) >= 0);
	ATF_REQUIRE((saved_fd = dup(STDOUT_FILENO)) >= 0);
	ATF_REQUIRE(dup2(fd, STDOUT_FILENO) == STDOUT_FILENO);
	ATF_REQUIRE(asprintf(&p, "/dev/fd/%d", STDOUT_FILENO) > 0);
	ATF_REQUIRE((fd = open(p, O_RDWR)) >= 0);
	ATF_CHECK(fchmod(fd, 0755) >= 0);
	ATF_CHECK(dup2(saved_fd, STDOUT_FILENO) == STDOUT_FILENO);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, chmod_deny);
	ATF_TP_ADD_TC(tp, chmod_allow);
	ATF_TP_ADD_TC(tp, fchmod_deny);
	ATF_TP_ADD_TC(tp, fchmod_allow);
	ATF_TP_ADD_TC(tp, fchmod_devfd_deny);
	ATF_TP_ADD_TC(tp, fchmod_devfd_allow);
	return (atf_no_error());
}
