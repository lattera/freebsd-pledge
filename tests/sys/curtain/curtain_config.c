#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <atf-c.h>
#include <curtain.h>

#include "path-utils.h"

ATF_TC_WITHOUT_HEAD(basic_tags);
ATF_TC_BODY(basic_tags, tc)
{
	struct curtain_config *cfg;
	cfg = curtain_config_new(0);
	curtain_config_tag_push(cfg, "_default");
	curtain_config_tag_push(cfg, "_crude");
	curtain_config_load(cfg);
	ATF_REQUIRE(curtain_apply() >= 0);
	check_access("/dev/null", "rw");
	check_access("/dev/random", "r");
	check_access("/dev/mem", "");
	curtain_config_free(cfg);
}

ATF_TC_WITHOUT_HEAD(drop_tags);
ATF_TC_BODY(drop_tags, tc)
{
	struct curtain_config *cfg;
	cfg = curtain_config_new(0);
	curtain_config_verbosity(cfg, 3);

	curtain_config_tag_push(cfg, "_default");
	curtain_config_tag_push(cfg, "_crude");
	curtain_config_tag_push(cfg, "_network");
	curtain_config_tag_push(cfg, "_tty");
	curtain_config_tag_push(cfg, "curtain");
	ATF_REQUIRE(curtain_config_apply(cfg) >= 0);
	check_access("/dev/null", "rw");
	check_access("/dev/random", "r");
	check_access("/dev/mem", "");
	check_access("/etc/termcap", "r");
	check_access("/etc/hosts", "r");
	check_access("/etc/services", "r");

	curtain_config_tag_drop(cfg, "_network");
	ATF_REQUIRE(curtain_config_apply(cfg) >= 0);
	check_access("/dev/null", "rw");
	check_access("/dev/random", "r");
	check_access("/dev/mem", "");
	check_access("/etc/termcap", "r");
	check_access("/etc/hosts", "");
	check_access("/etc/services", "");

	curtain_config_tag_drop(cfg, "_tty");
	ATF_REQUIRE(curtain_config_apply(cfg) >= 0);
	check_access("/dev/null", "rw");
	check_access("/dev/random", "r");
	check_access("/dev/mem", "");
	check_access("/etc/termcap", "");
	check_access("/etc/hosts", "");
	check_access("/etc/services", "");

	curtain_config_tag_drop(cfg, "curtain");
	curtain_config_tag_push(cfg, "_tty");
	ATF_REQUIRE(curtain_config_apply(cfg) >= 0);
	check_access("/dev/null", "rw");
	check_access("/dev/random", "r");
	check_access("/dev/mem", "");
	check_access("/etc/termcap", "");
	check_access("/etc/hosts", "");
	check_access("/etc/services", "");

	curtain_config_free(cfg);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, basic_tags);
	ATF_TP_ADD_TC(tp, drop_tags);
	return (atf_no_error());
}
