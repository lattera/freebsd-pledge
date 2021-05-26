#include <fcntl.h>
#include <errno.h>
#include <sysexits.h>
#include <sys/capsicum.h>
#include <atf-c.h>
#include <pledge.h>

ATF_TC_WITHOUT_HEAD(capsicum_after_pledge);
ATF_TC_BODY(capsicum_after_pledge, tc)
{
	int fd;
	ATF_REQUIRE(pledge("stdio error", "stdio") >= 0);
	/* this is allowed by the "stdio" pledge but not Capsicum */
	ATF_CHECK((fd = open("/dev/null", O_RDONLY)) >= 0);
	ATF_CHECK(close(fd) >= 0);
	ATF_REQUIRE(cap_enter() >= 0);
	ATF_CHECK_ERRNO(ECAPMODE, open("/dev/null", O_RDONLY) < 0);
	/* allowed by Capsicum but not pledge */
	ATF_CHECK_ERRNO(EPERM, flock(fd, LOCK_SH) < 0);
}

ATF_TC_WITHOUT_HEAD(pledge_after_capsicum);
ATF_TC_BODY(pledge_after_capsicum, tc)
{
	atf_tc_expect_exit(EX_OSERR, "pledge() after cap_enter() aborts");
	ATF_REQUIRE(cap_enter() >= 0);
	/*
	 * This could be supported, but I doubt it would have much use.
	 * Currently, the needed syscalls aren't even allowed under Capsicum
	 * (and ECAPMODE makes pledge() abort (unlike ENOSYS)).
	 */
	ATF_REQUIRE_ERRNO(ECAPMODE, pledge("stdio error rpath", "stdio") < 0);
	ATF_CHECK_ERRNO(ECAPMODE, open("/dev/null", O_RDONLY) < 0);
}


ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, capsicum_after_pledge);
	ATF_TP_ADD_TC(tp, pledge_after_capsicum);
	return (atf_no_error());
}
