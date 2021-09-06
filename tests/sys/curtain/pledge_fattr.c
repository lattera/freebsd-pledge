#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/stat.h>
#include <atf-c.h>
#include <pledge.h>


static bool
is_sugid(const char *p)
{
	struct stat st;
	ATF_REQUIRE(stat(p, &st) >= 0);
	return (st.st_mode & (S_ISGID|S_ISUID));
}

ATF_TC_WITHOUT_HEAD(chmod_sugid_allow);
ATF_TC_BODY(chmod_sugid_allow, tc)
{
	const char *p = "test";
	mode_t m = S_IRUSR|S_IWUSR;
	int fd;
	ATF_REQUIRE((fd = creat(p, m)) >= 0);
	ATF_REQUIRE(fchown(fd, geteuid(), getegid()) >= 0);
	ATF_CHECK(!is_sugid(p));
	ATF_REQUIRE(pledge("error stdio rpath fattr chmod_special", "") >= 0);

	ATF_CHECK(chmod(p, S_ISUID|m) >= 0);
	ATF_CHECK(is_sugid(p));
	ATF_CHECK(chmod(p, m) >= 0);
	ATF_CHECK(!is_sugid(p));
	ATF_CHECK(chmod(p, S_ISGID|m) >= 0);
	ATF_CHECK(is_sugid(p));
	ATF_CHECK(chmod(p, m) >= 0);
	ATF_CHECK(!is_sugid(p));

	ATF_CHECK(fchmod(fd, S_ISUID|m) >= 0);
	ATF_CHECK(is_sugid(p));
	ATF_CHECK(fchmod(fd, m) >= 0);
	ATF_CHECK(!is_sugid(p));
	ATF_CHECK(fchmod(fd, S_ISGID|m) >= 0);
	ATF_CHECK(is_sugid(p));
	ATF_CHECK(fchmod(fd, m) >= 0);
	ATF_CHECK(!is_sugid(p));

	ATF_CHECK(fchmodat(fd, "", S_ISUID|m, AT_EMPTY_PATH) >= 0);
	ATF_CHECK(is_sugid(p));
	ATF_CHECK(fchmodat(fd, "", m, AT_EMPTY_PATH) >= 0);
	ATF_CHECK(!is_sugid(p));
	ATF_CHECK(fchmodat(fd, "", S_ISGID|m, AT_EMPTY_PATH) >= 0);
	ATF_CHECK(is_sugid(p));
	ATF_CHECK(fchmodat(fd, "", m, AT_EMPTY_PATH) >= 0);
	ATF_CHECK(!is_sugid(p));

	ATF_CHECK(close(fd) >= 0);
}

ATF_TC_WITHOUT_HEAD(chmod_sugid_deny);
ATF_TC_BODY(chmod_sugid_deny, tc)
{
	const char *p = "test";
	mode_t m = S_IRUSR|S_IWUSR;
	int fd;
	ATF_REQUIRE((fd = creat(p, m)) >= 0);
	ATF_REQUIRE(fchown(fd, geteuid(), getegid()) >= 0);
	ATF_CHECK(!is_sugid(p));
	ATF_REQUIRE(pledge("error stdio rpath fattr", "") >= 0);

	ATF_CHECK(chmod(p, S_ISUID|m) >= 0);
	ATF_CHECK(!is_sugid(p));
	ATF_CHECK(chmod(p, S_ISGID|m) >= 0);
	ATF_CHECK(!is_sugid(p));

	ATF_CHECK(fchmod(fd, S_ISUID|m) >= 0);
	ATF_CHECK(!is_sugid(p));
	ATF_CHECK(fchmod(fd, S_ISGID|m) >= 0);
	ATF_CHECK(!is_sugid(p));

	ATF_CHECK(fchmodat(fd, "", S_ISUID|m, AT_EMPTY_PATH) >= 0);
	ATF_CHECK(!is_sugid(p));
	ATF_CHECK(fchmodat(fd, "", S_ISGID|m, AT_EMPTY_PATH) >= 0);
	ATF_CHECK(!is_sugid(p));

	ATF_CHECK(close(fd) >= 0);
}

ATF_TC_WITHOUT_HEAD(create_sugid_deny);
ATF_TC_BODY(create_sugid_deny, tc)
{
	const char *p = "test";
	mode_t m = S_IRUSR|S_IWUSR;
	int fd;
	mode_t old_umask;
	old_umask = umask(0);
	ATF_REQUIRE(pledge("error stdio rpath wpath cpath fattr", "") >= 0);

	ATF_REQUIRE((fd = creat(p, m)) >= 0);
	ATF_CHECK(!is_sugid(p));
	ATF_REQUIRE(unlink(p) >= 0);
	ATF_CHECK(close(fd) >= 0);

	ATF_REQUIRE((fd = creat(p, S_ISUID|m)) >= 0);
	ATF_CHECK(!is_sugid(p));
	ATF_REQUIRE(unlink(p) >= 0);
	ATF_CHECK(close(fd) >= 0);

	ATF_REQUIRE((fd = creat(p, S_ISGID|m)) >= 0);
	ATF_CHECK(!is_sugid(p));
	ATF_REQUIRE(unlink(p) >= 0);
	ATF_CHECK(close(fd) >= 0);

	umask(old_umask);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, chmod_sugid_allow);
	ATF_TP_ADD_TC(tp, chmod_sugid_deny);
	ATF_TP_ADD_TC(tp, create_sugid_deny);
	return (atf_no_error());
}
