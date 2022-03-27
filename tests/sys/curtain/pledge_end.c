#include <stdlib.h>
#include <sys/sysctl.h>
#include <err.h>
#include <atf-c.h>
#include <pledge.h>

#include "path-utils.h"

static size_t
getnfds()
{
	size_t len;
	int mib[4], nfds;
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_NFDS;
	mib[3] = 0;
	len = sizeof(nfds);
	ATF_REQUIRE(sysctl(mib, 4, &nfds, &len, NULL, 0) >= 0);
	return (nfds);
}

ATF_TC_WITHOUT_HEAD(pledge_end);
ATF_TC_BODY(pledge_end, tc)
{
	size_t nfds = getnfds();
	ATF_REQUIRE(pledge("stdio inet", "stdio tty") >= 0);
	pledge_end();
	ATF_REQUIRE(getnfds() == nfds);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, pledge_end);
	return (atf_no_error());
}
