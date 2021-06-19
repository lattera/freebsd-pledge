#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <sys/ttycom.h>
#include <atf-c.h>
#include <curtain.h>

#include "path-utils.h"

ATF_TC_WITHOUT_HEAD(sysfil_level_pass);
ATF_TC_BODY(sysfil_level_pass, tc)
{
	struct curtain_slot *slot;
	int fd;
	slot = curtain_slot();
	curtain_sysfil(slot, SYSFIL_STDIO, CURTAIN_PASS);
	curtain_sysfil(slot, SYSFIL_FLOCK, CURTAIN_PASS);
	ATF_REQUIRE((fd = creat("test", 0666)) >= 0);
	ATF_REQUIRE(curtain_enforce() >= 0);
	ATF_CHECK(flock(fd, LOCK_EX) >= 0);
}

ATF_TC_WITHOUT_HEAD(sysfil_level_deny);
ATF_TC_BODY(sysfil_level_deny, tc)
{
	struct curtain_slot *slot;
	int fd;
	slot = curtain_slot();
	curtain_sysfil(slot, SYSFIL_STDIO, CURTAIN_PASS);
	curtain_sysfil(slot, SYSFIL_FLOCK, CURTAIN_DENY);
	ATF_REQUIRE((fd = creat("test", 0666)) >= 0);
	ATF_REQUIRE(curtain_enforce() >= 0);
	ATF_CHECK_ERRNO(EPERM, flock(fd, LOCK_EX) < 0);
}

ATF_TC_WITHOUT_HEAD(sysfil_level_trap);
ATF_TC_BODY(sysfil_level_trap, tc)
{
	struct curtain_slot *slot;
	int fd;
	slot = curtain_slot();
	curtain_sysfil(slot, SYSFIL_STDIO, CURTAIN_PASS);
	curtain_sysfil(slot, SYSFIL_FLOCK, CURTAIN_TRAP);
	ATF_REQUIRE((fd = creat("test", 0666)) >= 0);
	atf_tc_expect_signal(SIGTRAP, "CURTAIN_TRAP");
	ATF_REQUIRE(curtain_enforce() >= 0);
	ATF_CHECK_ERRNO(EPERM, flock(fd, LOCK_EX) < 0);
}

ATF_TC_WITHOUT_HEAD(sysfil_level_kill);
ATF_TC_BODY(sysfil_level_kill, tc)
{
	struct curtain_slot *slot;
	int fd;
	slot = curtain_slot();
	curtain_sysfil(slot, SYSFIL_STDIO, CURTAIN_PASS);
	curtain_sysfil(slot, SYSFIL_FLOCK, CURTAIN_KILL);
	ATF_REQUIRE((fd = creat("test", 0666)) >= 0);
	atf_tc_expect_signal(SIGKILL, "CURTAIN_KILL");
	ATF_REQUIRE(curtain_enforce() >= 0);
	ATF_CHECK_ERRNO(EPERM, flock(fd, LOCK_EX) < 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, sysfil_level_pass);
	ATF_TP_ADD_TC(tp, sysfil_level_deny);
	ATF_TP_ADD_TC(tp, sysfil_level_trap);
	ATF_TP_ADD_TC(tp, sysfil_level_kill);
	return (atf_no_error());
}
