#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/curtain.h>
#include <sys/sysfil.h>
#include <sys/param.h>
#include <atf-c.h>

ATF_TC_WITHOUT_HEAD(curtainctl_sanity);
ATF_TC_BODY(curtainctl_sanity, tc)
{
	int sysfils[] = { SYSFIL_STDIO };
	struct curtainreq reqs[] = {
		{
			.type = CURTAINTYP_SYSFIL,
			.flags = CURTAINREQ_ON_SELF,
			.data = sysfils,
			.size = sizeof sysfils,
		}
	};
	int flags = CURTAINCTL_ENFORCE|CURTAINCTL_ON_SELF|CURTAINCTL_ON_EXEC;
	ATF_REQUIRE(curtainctl(flags, nitems(reqs), reqs) >= 0);
	ATF_CHECK(write(STDOUT_FILENO, "Hello?", 6) == 6);
}

ATF_TC_WITHOUT_HEAD(curtainctl_overflow_reqs);
ATF_TC_BODY(curtainctl_overflow_reqs, tc)
{
	int sysfils[] = { SYSFIL_STDIO };
	struct curtainreq reqs[CURTAINCTL_MAX_REQS + 1];
	int flags = CURTAINCTL_ENFORCE|CURTAINCTL_ON_SELF|CURTAINCTL_ON_EXEC;
	for (size_t i = 0; i < nitems(reqs); i++)
		reqs[i] = (struct curtainreq){
			.type = CURTAINTYP_SYSFIL,
			.flags = CURTAINREQ_ON_SELF,
			.data = sysfils,
			.size = sizeof sysfils,
		};
	ATF_CHECK_ERRNO(EINVAL, curtainctl(flags, nitems(reqs), reqs) < 0);
}

ATF_TC_WITHOUT_HEAD(curtainctl_overflow_size);
ATF_TC_BODY(curtainctl_overflow_size, tc)
{
	int sysfils[CURTAINCTL_MAX_SIZE / sizeof (int) / 8];
	struct curtainreq reqs[32];
	int flags = CURTAINCTL_ENFORCE|CURTAINCTL_ON_SELF|CURTAINCTL_ON_EXEC;
	for (size_t i = 0; i < nitems(sysfils); i++)
		sysfils[i] = SYSFIL_STDIO;
	for (size_t i = 0; i < nitems(reqs); i++)
		reqs[i] = (struct curtainreq){
			.type = CURTAINTYP_SYSFIL,
			.flags = CURTAINREQ_ON_SELF,
			.data = sysfils,
			.size = sizeof sysfils,
		};
	ATF_CHECK_ERRNO(EINVAL, curtainctl(flags, nitems(reqs), reqs) < 0);
}

ATF_TC_WITHOUT_HEAD(curtainctl_overflow_items);
ATF_TC_BODY(curtainctl_overflow_items, tc)
{
	int sysfils[] = { SYSFIL_STDIO };
	unsigned long ioctls[CURTAINCTL_MAX_ITEMS + 1];
	struct curtainreq reqs[] = {
		{
			.type = CURTAINTYP_SYSFIL,
			.flags = CURTAINREQ_ON_SELF,
			.data = sysfils,
			.size = sizeof sysfils,
		},
		{
			.type = CURTAINTYP_IOCTL,
			.flags = CURTAINREQ_ON_SELF,
			.data = ioctls,
			.size = sizeof ioctls,
		},
	};
	int flags = CURTAINCTL_ENFORCE|CURTAINCTL_ON_SELF|CURTAINCTL_ON_EXEC;
	for (size_t i = 0; i < nitems(ioctls); i++)
		ioctls[i] = 1 + i;
	ATF_CHECK_ERRNO(EINVAL, curtainctl(flags, nitems(reqs), reqs) < 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, curtainctl_sanity);
	ATF_TP_ADD_TC(tp, curtainctl_overflow_reqs);
	ATF_TP_ADD_TC(tp, curtainctl_overflow_size);
	ATF_TP_ADD_TC(tp, curtainctl_overflow_items);
	return (atf_no_error());
}
