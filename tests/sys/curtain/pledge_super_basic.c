#include <stdio.h>
#include <atf-c.h>
#include <pledge.h>

ATF_TC_WITHOUT_HEAD(super_basic);
ATF_TC_BODY(super_basic, tc)
{
	ATF_REQUIRE(pledge("stdio", "stdio") >= 0);
	ATF_CHECK(puts("ok!") >= 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, super_basic);
	return (atf_no_error());
}
