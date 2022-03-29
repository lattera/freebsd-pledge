#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <sys/param.h>
#include <atf-c.h>

#include <sys/curtainctl.h>
#include <security/mac_curtain/ability.h>
#include <security/mac_curtain/unveil.h>

ATF_TC_WITHOUT_HEAD(curtainctl_sanity);
ATF_TC_BODY(curtainctl_sanity, tc)
{
	int abilities[] = { CURTAINABL_STDIO };
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
	int abilities[] = { CURTAINABL_STDIO };
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
	int abilities[CURTAINCTL_MAX_SIZE / sizeof (int) / 8];
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
	int abilities[] = { CURTAINABL_STDIO };
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

ATF_TC_WITHOUT_HEAD(curtainctl_overflow_unveils);
ATF_TC_BODY(curtainctl_overflow_unveils, tc)
{
	int abilities[] = { CURTAINABL_STDIO };
	struct curtainent_unveil *unveils;
	size_t unveils_count = CURTAINCTL_MAX_UNVEILS + 1, unveils_space;
	unveils_space = (sizeof *unveils + 7 + 1) * unveils_count;
	ATF_REQUIRE((unveils = malloc(unveils_space)) != NULL);
	struct curtainreq reqs[] = {
		{
			.type = CURTAINTYP_ABILITY,
			.flags = CURTAINREQ_ON_SELF,
			.data = abilities,
			.size = sizeof abilities,
		},
		{
			.type = CURTAINTYP_UNVEIL,
			.flags = CURTAINREQ_ON_SELF,
			.data = unveils,
			.size = unveils_space,
		},
	};
	int flags = CURTAINCTL_THIS_VERSION | CURTAINCTL_REPLACE, fd;
	ATF_REQUIRE((fd = open(".", O_RDONLY|O_DIRECTORY)) >= 0);
	char *p = (void *)unveils;
	for (unsigned i = 0; i < unveils_count; i++) {
		struct curtainent_unveil *ent = (void *)p;
		int r;
		*ent = (struct curtainent_unveil){ .dir_fd = fd };
		ATF_REQUIRE((r = sprintf(ent->name, "%07u", i)) == 7);
		p += sizeof *ent + r + 1;

	}
	ATF_CHECK_ERRNO(E2BIG, curtainctl(flags, nitems(reqs), reqs) < 0);
	ATF_CHECK(close(fd) >= 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, curtainctl_sanity);
	ATF_TP_ADD_TC(tp, curtainctl_overflow_reqs);
	ATF_TP_ADD_TC(tp, curtainctl_overflow_size);
	ATF_TP_ADD_TC(tp, curtainctl_overflow_items);
	ATF_TP_ADD_TC(tp, curtainctl_overflow_unveils);
	return (atf_no_error());
}
