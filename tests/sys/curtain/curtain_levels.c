#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <sys/param.h>
#include <sys/ttycom.h>
#include <atf-c.h>
#include <curtain.h>

ATF_TC_WITHOUT_HEAD(ability_level_pass);
ATF_TC_BODY(ability_level_pass, tc)
{
	struct curtain_slot *slot;
	int fd;
	slot = curtain_slot();
	curtain_ability(slot, CURTAINABL_STDIO, CURTAIN_PASS);
	curtain_ability(slot, CURTAINABL_FLOCK, CURTAIN_PASS);
	ATF_REQUIRE((fd = creat("test", 0666)) >= 0);
	ATF_REQUIRE(curtain_apply() >= 0);
	ATF_CHECK(flock(fd, LOCK_EX) >= 0);
}

ATF_TC_WITHOUT_HEAD(ability_level_deny);
ATF_TC_BODY(ability_level_deny, tc)
{
	struct curtain_slot *slot;
	int fd;
	slot = curtain_slot();
	curtain_ability(slot, CURTAINABL_STDIO, CURTAIN_PASS);
	curtain_ability(slot, CURTAINABL_FLOCK, CURTAIN_DENY);
	ATF_REQUIRE((fd = creat("test", 0666)) >= 0);
	ATF_REQUIRE(curtain_apply() >= 0);
	ATF_CHECK_ERRNO(EPERM, flock(fd, LOCK_EX) < 0);
}

ATF_TC_WITHOUT_HEAD(ability_level_trap);
ATF_TC_BODY(ability_level_trap, tc)
{
	struct curtain_slot *slot;
	int fd;
	slot = curtain_slot();
	curtain_ability(slot, CURTAINABL_STDIO, CURTAIN_PASS);
	curtain_ability(slot, CURTAINABL_FLOCK, CURTAIN_TRAP);
	ATF_REQUIRE((fd = creat("test", 0666)) >= 0);
	atf_tc_expect_signal(SIGTRAP, "CURTAIN_TRAP");
	ATF_REQUIRE(curtain_apply() >= 0);
	ATF_CHECK_ERRNO(EPERM, flock(fd, LOCK_EX) < 0);
}

ATF_TC_WITHOUT_HEAD(ability_level_kill);
ATF_TC_BODY(ability_level_kill, tc)
{
	struct curtain_slot *slot;
	int fd;
	slot = curtain_slot();
	curtain_ability(slot, CURTAINABL_STDIO, CURTAIN_PASS);
	curtain_ability(slot, CURTAINABL_FLOCK, CURTAIN_KILL);
	ATF_REQUIRE((fd = creat("test", 0666)) >= 0);
	atf_tc_expect_signal(SIGKILL, "CURTAIN_KILL");
	ATF_REQUIRE(curtain_apply() >= 0);
	ATF_CHECK_ERRNO(EPERM, flock(fd, LOCK_EX) < 0);
}


ATF_TC_WITHOUT_HEAD(ability_raise_allow);
ATF_TC_BODY(ability_raise_allow, tc)
{
	struct curtain_slot *slot0, *slot1;
	int fd;
	ATF_REQUIRE((fd = creat("test", 0666)) >= 0);
	slot0 = curtain_slot();
	slot1 = curtain_slot();
	curtain_default(slot0, CURTAIN_DENY);
	curtain_ability(slot0, CURTAINABL_STDIO, CURTAIN_PASS);
	curtain_ability(slot0, CURTAINABL_CURTAIN, CURTAIN_PASS);
	curtain_state(slot1, CURTAIN_ON_SELF, CURTAIN_RESERVED);
	curtain_ability(slot1, CURTAINABL_FLOCK, CURTAIN_PASS);
	ATF_REQUIRE(curtain_apply() >= 0);
	ATF_CHECK_ERRNO(EPERM, flock(fd, LOCK_EX) < 0);
	curtain_state(slot1, CURTAIN_ON_SELF, CURTAIN_ENABLED);
	ATF_REQUIRE(curtain_apply() >= 0);
	ATF_CHECK(flock(fd, LOCK_EX) >= 0);
}

ATF_TC_WITHOUT_HEAD(ability_raise_block);
ATF_TC_BODY(ability_raise_block, tc)
{
	struct curtain_slot *slot0, *slot1;
	int fd;
	ATF_REQUIRE((fd = creat("test", 0666)) >= 0);
	slot0 = curtain_slot();
	slot1 = curtain_slot();
	curtain_state(slot1, CURTAIN_ON_SELF, CURTAIN_DISABLED);
	curtain_default(slot0, CURTAIN_DENY);
	curtain_ability(slot0, CURTAINABL_STDIO, CURTAIN_PASS);
	curtain_ability(slot0, CURTAINABL_CURTAIN, CURTAIN_PASS);
	curtain_ability(slot1, CURTAINABL_FLOCK, CURTAIN_PASS);
	ATF_REQUIRE(curtain_apply() >= 0);
	ATF_CHECK_ERRNO(EPERM, flock(fd, LOCK_EX) < 0);
	curtain_state(slot1, CURTAIN_ON_SELF, CURTAIN_ENABLED);
	ATF_REQUIRE(curtain_apply() >= 0);
	ATF_CHECK_ERRNO(EPERM, flock(fd, LOCK_EX) < 0);
}


ATF_TC_WITHOUT_HEAD(unrestrict_unveils);
ATF_TC_BODY(unrestrict_unveils, tc)
{
	struct curtain_slot *slot0, *slot1;
	slot0 = curtain_slot();
	slot1 = curtain_slot();
	curtain_state(slot0, CURTAIN_ON_SELF, CURTAIN_RESERVED);
	curtain_state(slot0, CURTAIN_ON_EXEC, CURTAIN_RESERVED);
	curtain_state(slot1, CURTAIN_ON_SELF, CURTAIN_ENABLED);
	curtain_state(slot1, CURTAIN_ON_EXEC, CURTAIN_ENABLED);
	curtain_default(slot0, CURTAIN_PASS);
	curtain_default(slot1, CURTAIN_DENY);
	curtain_ability(slot1, CURTAINABL_STDIO, CURTAIN_PASS);
	curtain_ability(slot1, CURTAINABL_CURTAIN, CURTAIN_PASS);
	ATF_REQUIRE(curtain_apply() >= 0);
	ATF_CHECK_ERRNO(EPERM, access("/etc/rc", R_OK) < 0);
	curtain_state(slot0, CURTAIN_ON_SELF, CURTAIN_ENABLED);
	curtain_state(slot0, CURTAIN_ON_EXEC, CURTAIN_ENABLED);
	ATF_REQUIRE(curtain_apply() >= 0);
	ATF_CHECK(access("/etc/rc", R_OK) >= 0);
}



ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, ability_level_pass);
	ATF_TP_ADD_TC(tp, ability_level_deny);
	ATF_TP_ADD_TC(tp, ability_level_trap);
	ATF_TP_ADD_TC(tp, ability_level_kill);
	ATF_TP_ADD_TC(tp, ability_raise_allow);
	ATF_TP_ADD_TC(tp, ability_raise_block);
	ATF_TP_ADD_TC(tp, unrestrict_unveils);
	return (atf_no_error());
}
