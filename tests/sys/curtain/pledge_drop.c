#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pwd.h>
#include <atf-c.h>
#include <pledge.h>

ATF_TC_WITHOUT_HEAD(drop_rpath);
ATF_TC_BODY(drop_rpath, tc)
{
	int fd;
	ATF_REQUIRE(pledge("stdio error rpath", "stdio") >= 0);
	ATF_CHECK((fd = open("/etc/rc", O_RDONLY)) >= 0);
	ATF_CHECK(close(fd) >= 0);
	ATF_REQUIRE(pledge("stdio error", "stdio") >= 0);
	ATF_CHECK_ERRNO(ENOENT, (fd = open("/etc/rc", O_RDONLY)) < 0);
	ATF_REQUIRE(pledge("stdio error rpath", "stdio") >= 0);
	ATF_CHECK_ERRNO(ENOENT, (fd = open("/etc/rc", O_RDONLY)) < 0);
}

ATF_TC_WITHOUT_HEAD(drop_flock);
ATF_TC_BODY(drop_flock, tc)
{
	int fd;
	ATF_CHECK((fd = open("/etc/rc", O_RDONLY)) >= 0);
	ATF_REQUIRE(pledge("stdio error flock", "stdio") >= 0);
	ATF_CHECK(flock(fd, LOCK_SH) >= 0);
	ATF_CHECK(flock(fd, LOCK_UN) >= 0);
	ATF_REQUIRE(pledge("stdio error", "stdio") >= 0);
	ATF_CHECK_ERRNO(EPERM, flock(fd, LOCK_SH) < 0);
	ATF_REQUIRE(pledge("stdio error flock", "stdio") >= 0);
	ATF_CHECK_ERRNO(EPERM, flock(fd, LOCK_SH) < 0);
	ATF_CHECK(close(fd) >= 0);
}

ATF_TC_WITHOUT_HEAD(drop_getpw);
ATF_TC_BODY(drop_getpw, tc)
{
	uid_t uid = getuid();
	struct passwd *pwd;
	ATF_REQUIRE(pledge("stdio error getpw", "stdio") >= 0);
	ATF_CHECK((pwd = getpwuid(uid)) && pwd->pw_uid == uid);
	ATF_REQUIRE(pledge("stdio error", "stdio") >= 0);
	ATF_CHECK(getpwuid(uid) == NULL);
	ATF_REQUIRE(pledge("stdio error getpw", "stdio") >= 0);
	ATF_CHECK(getpwuid(uid) == NULL);
}


ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, drop_rpath);
	ATF_TP_ADD_TC(tp, drop_flock);
	ATF_TP_ADD_TC(tp, drop_getpw);
	return (atf_no_error());
}
