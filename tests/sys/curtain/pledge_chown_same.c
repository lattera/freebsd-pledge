#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <atf-c.h>
#include <pledge.h>

#define	OTHER_UID	7
#define	OTHER_GID	13

ATF_TC_WITHOUT_HEAD(chown_same);
ATF_TC_BODY(chown_same, tc)
{
	const char *p = "chown-same-test";
	int fd;
	struct stat st;
	ATF_REQUIRE((fd = creat(p, 0600)) >= 0);
	ATF_REQUIRE(stat(p, &st) >= 0);
	ATF_REQUIRE(pledge("error stdio fattr", "") >= 0);
	ATF_REQUIRE( chown(p,  st.st_uid, st.st_gid) >= 0);
	ATF_REQUIRE(fchown(fd, st.st_uid, st.st_gid) >= 0);
	if (geteuid() == 0) {
		ATF_REQUIRE_ERRNO(EPERM,  chown(p,  OTHER_UID, st.st_gid) < 0);
		ATF_REQUIRE_ERRNO(EPERM, fchown(fd, OTHER_UID, st.st_gid) < 0);
		ATF_REQUIRE_ERRNO(EPERM,  chown(p,  st.st_uid, OTHER_GID) < 0);
		ATF_REQUIRE_ERRNO(EPERM, fchown(fd, st.st_uid, OTHER_GID) < 0);
	}
	ATF_CHECK(close(fd) >= 0);
}

ATF_TC_WITHOUT_HEAD(chown_diff);
ATF_TC_BODY(chown_diff, tc)
{
	const char *p = "chown-diff-test";
	int fd;
	struct stat st;
	if (geteuid() != 0)
		atf_tc_skip("need superuser");
	ATF_REQUIRE((fd = creat(p, 0600)) >= 0);
	ATF_REQUIRE(stat(p, &st) >= 0);
	ATF_REQUIRE(pledge("error stdio fattr chown", "") >= 0);
	ATF_REQUIRE( chown(p,  OTHER_UID, st.st_gid) >= 0);
	ATF_REQUIRE(fchown(fd, OTHER_UID, st.st_gid) >= 0);
	ATF_REQUIRE( chown(p,  st.st_uid, OTHER_GID) >= 0);
	ATF_REQUIRE(fchown(fd, st.st_uid, OTHER_GID) >= 0);
	ATF_CHECK(close(fd) >= 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, chown_same);
	ATF_TP_ADD_TC(tp, chown_diff);
	return (atf_no_error());
}
