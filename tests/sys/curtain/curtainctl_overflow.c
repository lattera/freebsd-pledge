#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <sys/curtain.h>
#include <sys/unveil.h>
#include <sys/param.h>
#include <atf-c.h>

ATF_TC_WITHOUT_HEAD(curtainctl_sanity);
ATF_TC_BODY(curtainctl_sanity, tc)
{
	enum curtain_ability abilities[] = { CURTAINABL_STDIO };
	struct curtainreq reqs[] = {
		{
			.type = CURTAINTYP_ABILITY,
			.flags = CURTAINREQ_ON_SELF,
			.data = abilities,
			.size = sizeof abilities,
		}
	};
	int flags = CURTAINCTL_THIS_VERSION | CURTAINCTL_REPLACE;
	ATF_REQUIRE(curtainctl(flags, nitems(reqs), reqs) >= 0);
	ATF_CHECK(write(STDOUT_FILENO, "Hello?", 6) == 6);
}

ATF_TC_WITHOUT_HEAD(curtainctl_overflow_reqs);
ATF_TC_BODY(curtainctl_overflow_reqs, tc)
{
	enum curtain_ability abilities[] = { CURTAINABL_STDIO };
	struct curtainreq reqs[CURTAINCTL_MAX_REQS + 1];
	int flags = CURTAINCTL_THIS_VERSION | CURTAINCTL_REPLACE;
	for (size_t i = 0; i < nitems(reqs); i++)
		reqs[i] = (struct curtainreq){
			.type = CURTAINTYP_ABILITY,
			.flags = CURTAINREQ_ON_SELF,
			.data = abilities,
			.size = sizeof abilities,
		};
	ATF_CHECK_ERRNO(E2BIG, curtainctl(flags, nitems(reqs), reqs) < 0);
}

ATF_TC_WITHOUT_HEAD(curtainctl_overflow_size);
ATF_TC_BODY(curtainctl_overflow_size, tc)
{
	enum curtain_ability abilities[CURTAINCTL_MAX_SIZE / sizeof (int) / 8];
	struct curtainreq reqs[32];
	int flags = CURTAINCTL_THIS_VERSION | CURTAINCTL_REPLACE;
	for (size_t i = 0; i < nitems(abilities); i++)
		abilities[i] = CURTAINABL_STDIO;
	for (size_t i = 0; i < nitems(reqs); i++)
		reqs[i] = (struct curtainreq){
			.type = CURTAINTYP_ABILITY,
			.flags = CURTAINREQ_ON_SELF,
			.data = abilities,
			.size = sizeof abilities,
		};
	ATF_CHECK_ERRNO(E2BIG, curtainctl(flags, nitems(reqs), reqs) < 0);
}

ATF_TC_WITHOUT_HEAD(curtainctl_overflow_items);
ATF_TC_BODY(curtainctl_overflow_items, tc)
{
	enum curtain_ability abilities[] = { CURTAINABL_STDIO };
	unsigned long ioctls[CURTAINCTL_MAX_ITEMS + 1];
	struct curtainreq reqs[] = {
		{
			.type = CURTAINTYP_ABILITY,
			.flags = CURTAINREQ_ON_SELF,
			.data = abilities,
			.size = sizeof abilities,
		},
		{
			.type = CURTAINTYP_IOCTL,
			.flags = CURTAINREQ_ON_SELF,
			.data = ioctls,
			.size = sizeof ioctls,
		},
	};
	int flags = CURTAINCTL_THIS_VERSION | CURTAINCTL_REPLACE;
	for (size_t i = 0; i < nitems(ioctls); i++)
		ioctls[i] = 1 + i;
	ATF_CHECK_ERRNO(E2BIG, curtainctl(flags, nitems(reqs), reqs) < 0);
}

#if 0

ATF_TC_WITHOUT_HEAD(unveilreg_overflow);
ATF_TC_BODY(unveilreg_overflow, tc)
{
	int r, i;
	for (i = 0, r = 0; i < 1024; i++) {
		char path[32];
		struct unveilreg reg = { .atfd = AT_FDCWD, .path = path };
		ATF_CHECK(sprintf(path, "test-%u", i) > 0);
		r = unveilreg(UNVEILREG_THIS_VERSION | UNVEILREG_REGISTER |
		    UNVEILREG_NONDIRBYNAME, &reg);
		if (r < 0)
			break;
	}
	ATF_CHECK_ERRNO(E2BIG, r < 0);
}

#endif

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, curtainctl_sanity);
	ATF_TP_ADD_TC(tp, curtainctl_overflow_reqs);
	ATF_TP_ADD_TC(tp, curtainctl_overflow_size);
	ATF_TP_ADD_TC(tp, curtainctl_overflow_items);
#if 0
	ATF_TP_ADD_TC(tp, unveilreg_overflow);
#endif
	return (atf_no_error());
}
