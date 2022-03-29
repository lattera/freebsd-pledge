#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <atf-c.h>
#include <pledge.h>

#include "path-utils.h"

static const mode_t chmod_mode = 0755;
static const int chflags_flags = UF_READONLY;
static const struct timeval *utimes_tvp = NULL;
static const struct timespec *utimes_tsp = NULL;

static void
check_path_deny(const char *path)
{
	ATF_CHECK_ERRNO(EACCES, chmod(path, chmod_mode) < 0);
	ATF_CHECK_ERRNO(EACCES, fchmodat(AT_FDCWD, path, chmod_mode, 0) < 0);
	ATF_CHECK_ERRNO(EACCES, chflags(path, chflags_flags) < 0);
	ATF_CHECK_ERRNO(EACCES, chflagsat(AT_FDCWD, path, chflags_flags, 0) < 0);
	ATF_CHECK_ERRNO(EACCES, utimes(path, utimes_tvp) < 0);
	ATF_CHECK_ERRNO(EACCES, utimensat(AT_FDCWD, path, utimes_tsp, 0) < 0);
}

static void
check_path_allow(const char *path)
{
	ATF_CHECK(chmod(path, chmod_mode) >= 0);
	ATF_CHECK(fchmodat(AT_FDCWD, path, chmod_mode, 0) >= 0);
	ATF_CHECK(chflags(path, chflags_flags) >= 0);
	ATF_CHECK(chflagsat(AT_FDCWD, path, chflags_flags, 0) >= 0);
	ATF_CHECK(utimes(path, utimes_tvp) >= 0);
	ATF_CHECK(utimensat(AT_FDCWD, path, utimes_tsp, 0) >= 0);
}

static void
check_fd_deny(int fd)
{
	ATF_CHECK_ERRNO(EACCES, fchmod(fd, chmod_mode) < 0);
	ATF_CHECK_ERRNO(EACCES, fchflags(fd, chflags_flags) < 0);
	ATF_CHECK_ERRNO(EACCES, futimes(fd, utimes_tvp) < 0);
	ATF_CHECK_ERRNO(EACCES, futimens(fd, utimes_tsp) < 0);
}

static void
check_fd_allow(int fd)
{
	ATF_CHECK(fchmod(fd, chmod_mode) >= 0);
	ATF_CHECK(fchflags(fd, chflags_flags) >= 0);
	ATF_CHECK(futimes(fd, utimes_tvp) >= 0);
	ATF_CHECK(futimens(fd, utimes_tsp) >= 0);
}

static void
check_fd_ep_deny(int fd)
{
	ATF_CHECK_ERRNO(EACCES, fchmodat(fd, "", chmod_mode, AT_EMPTY_PATH) < 0);
	ATF_CHECK_ERRNO(EACCES, chflagsat(fd, "", chflags_flags, AT_EMPTY_PATH) < 0);
	ATF_CHECK_ERRNO(EACCES, utimensat(fd, "", utimes_tsp, AT_EMPTY_PATH) < 0);
}

static void
check_fd_ep_allow(int fd)
{
	ATF_CHECK(fchmodat(fd, "", chmod_mode, AT_EMPTY_PATH) >= 0);
	ATF_CHECK(chflagsat(fd, "", chflags_flags, AT_EMPTY_PATH) >= 0);
	ATF_CHECK(utimensat(fd, "", utimes_tsp, AT_EMPTY_PATH) >= 0);
}


ATF_TC_WITHOUT_HEAD(fattr_path_deny);
ATF_TC_BODY(fattr_path_deny, tc)
{
	ATF_REQUIRE(try_creat("test") >= 0);
	ATF_REQUIRE(unveil("test", "rm") >= 0);
	check_path_deny("test");
}

ATF_TC_WITHOUT_HEAD(fattr_path_allow);
ATF_TC_BODY(fattr_path_allow, tc)
{
	ATF_REQUIRE(try_creat("test") >= 0);
	ATF_REQUIRE(unveil("test", "rw") >= 0);
	check_path_allow("test");
}

ATF_TC_WITHOUT_HEAD(fattr_fd_deny);
ATF_TC_BODY(fattr_fd_deny, tc)
{
	int fd;
	ATF_REQUIRE(try_creat("test") >= 0);
	ATF_REQUIRE(unveil("test", "rm") >= 0);
	ATF_REQUIRE((fd = open("test", O_RDWR)) >= 0);
	check_fd_deny(fd);
}

ATF_TC_WITHOUT_HEAD(fattr_fd_allow);
ATF_TC_BODY(fattr_fd_allow, tc)
{
	int fd;
	ATF_REQUIRE(try_creat("test") >= 0);
	ATF_REQUIRE(unveil("test", "rw") >= 0);
	ATF_REQUIRE((fd = open("test", O_RDWR)) >= 0);
	check_fd_allow(fd);
}

ATF_TC_WITHOUT_HEAD(fattr_fd_ep_deny);
ATF_TC_BODY(fattr_fd_ep_deny, tc)
{
	int fd;
	ATF_REQUIRE(try_creat("test") >= 0);
	ATF_REQUIRE(unveil("test", "rm") >= 0);
	ATF_REQUIRE((fd = open("test", O_RDWR)) >= 0);
	check_fd_ep_deny(fd);
}

ATF_TC_WITHOUT_HEAD(fattr_fd_ep_allow);
ATF_TC_BODY(fattr_fd_ep_allow, tc)
{
	int fd;
	ATF_REQUIRE(try_creat("test") >= 0);
	ATF_REQUIRE(unveil("test", "rw") >= 0);
	ATF_REQUIRE((fd = open("test", O_RDWR)) >= 0);
	check_fd_ep_allow(fd);
}

ATF_TC_WITHOUT_HEAD(fattr_devfd_deny);
ATF_TC_BODY(fattr_devfd_deny, tc)
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
	check_fd_deny(fd);
	check_fd_ep_deny(fd);
	ATF_CHECK(dup2(saved_fd, STDOUT_FILENO) == STDOUT_FILENO);
}

ATF_TC_WITHOUT_HEAD(fattr_devfd_allow);
ATF_TC_BODY(fattr_devfd_allow, tc)
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
	check_fd_allow(fd);
	check_fd_ep_allow(fd);
	ATF_CHECK(dup2(saved_fd, STDOUT_FILENO) == STDOUT_FILENO);
}


ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, fattr_path_deny);
	ATF_TP_ADD_TC(tp, fattr_path_allow);
	ATF_TP_ADD_TC(tp, fattr_fd_deny);
	ATF_TP_ADD_TC(tp, fattr_fd_allow);
	ATF_TP_ADD_TC(tp, fattr_fd_ep_deny);
	ATF_TP_ADD_TC(tp, fattr_fd_ep_allow);
	ATF_TP_ADD_TC(tp, fattr_devfd_deny);
	ATF_TP_ADD_TC(tp, fattr_devfd_allow);
	return (atf_no_error());
}
