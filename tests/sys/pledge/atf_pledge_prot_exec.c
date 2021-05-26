#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <errno.h>
#include <atf-c.h>
#include <pledge.h>

static void
try_stuff(bool should_work, int fl, int fds[])
{
	void *p;

	ATF_REQUIRE_EQ((p = mmap(NULL, PAGE_SIZE, PROT_EXEC, fl, fds[0], 0)) != MAP_FAILED, should_work);
	if (should_work) {
		ATF_CHECK(mprotect(p, PAGE_SIZE, PROT_EXEC) >= 0);
		ATF_CHECK(munmap(p, PAGE_SIZE) >= 0);
	}

	ATF_REQUIRE((p = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_MAX(PROT_READ|PROT_EXEC), fl, fds[1], 0)) != MAP_FAILED);
	ATF_CHECK_EQ(mprotect(p, PAGE_SIZE, PROT_EXEC) >= 0, should_work);
	ATF_CHECK(munmap(p, PAGE_SIZE) >= 0);

	ATF_REQUIRE_EQ((p = mmap(NULL, PAGE_SIZE, PROT_EXEC, MAP_ANON | fl, -1, 0)) != MAP_FAILED, should_work);
	if (should_work) {
		ATF_CHECK(mprotect(p, PAGE_SIZE, PROT_EXEC) >= 0);
		ATF_CHECK(munmap(p, PAGE_SIZE) >= 0);
	}

	ATF_REQUIRE_EQ((p = mmap(NULL, PAGE_SIZE, PROT_EXEC | PROT_READ, MAP_ANON | fl, -1, 0)) != MAP_FAILED, should_work);
	if (should_work) {
		ATF_CHECK(mprotect(p, PAGE_SIZE, PROT_EXEC) >= 0);
		ATF_CHECK(munmap(p, PAGE_SIZE) >= 0);
	}

	ATF_REQUIRE((p = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_MAX(PROT_READ|PROT_EXEC), MAP_ANON | fl, -1, 0)) != MAP_FAILED);
	ATF_CHECK_EQ(mprotect(p, PAGE_SIZE, PROT_EXEC) >= 0, should_work);
	ATF_CHECK(munmap(p, PAGE_SIZE) >= 0);

	ATF_REQUIRE((p = aligned_alloc(PAGE_SIZE, PAGE_SIZE)));
	ATF_CHECK_EQ(mprotect(p, PAGE_SIZE, PROT_EXEC) >= 0, should_work);
	free(p);
}

ATF_TC_WITHOUT_HEAD(allow);
ATF_TC_BODY(allow, tc)
{
	int fds[2];
	ATF_REQUIRE((fds[0] = open("/bin/sh", O_EXEC)) >= 0);
	ATF_REQUIRE((fds[1] = open("/bin/sh", O_RDONLY)) >= 0);
	ATF_REQUIRE(pledge("error stdio prot_exec", NULL) >= 0);
	try_stuff(true, MAP_SHARED, fds);
	try_stuff(true, MAP_PRIVATE, fds);
	ATF_REQUIRE(close(fds[0]) >= 0);
	ATF_REQUIRE(close(fds[1]) >= 0);
}

ATF_TC_WITHOUT_HEAD(deny);
ATF_TC_BODY(deny, tc)
{
	int fds[2];
	ATF_REQUIRE((fds[0] = open("/bin/sh", O_EXEC)) >= 0);
	ATF_REQUIRE((fds[1] = open("/bin/sh", O_RDONLY)) >= 0);
	ATF_REQUIRE(pledge("error stdio", NULL) >= 0);
	try_stuff(false, MAP_SHARED, fds);
	try_stuff(false, MAP_PRIVATE, fds);
	ATF_REQUIRE(close(fds[0]) >= 0);
	ATF_REQUIRE(close(fds[1]) >= 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, allow);
	ATF_TP_ADD_TC(tp, deny);
	return (atf_no_error());
}

