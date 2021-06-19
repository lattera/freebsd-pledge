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
try_stuff_0(bool should_work, int fl)
{
	void *p;

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
}

static void
try_stuff_1(bool should_work, int fl, int fd)
{
	void *p;

	ATF_REQUIRE_EQ((p = mmap(NULL, PAGE_SIZE, PROT_EXEC, fl, fd, 0)) != MAP_FAILED, should_work);
	if (should_work) {
		ATF_CHECK(mprotect(p, PAGE_SIZE, PROT_EXEC) >= 0);
		ATF_CHECK(munmap(p, PAGE_SIZE) >= 0);
	}
}

static void
try_stuff_2(bool should_work, int fl, int fd)
{
	void *p;

	ATF_REQUIRE((p = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_MAX(PROT_READ|PROT_EXEC), fl, fd, 0)) != MAP_FAILED);
	ATF_CHECK_EQ(mprotect(p, PAGE_SIZE, PROT_EXEC) >= 0, should_work);
	ATF_CHECK(munmap(p, PAGE_SIZE) >= 0);

}


ATF_TC_WITHOUT_HEAD(mmap_allow);
ATF_TC_BODY(mmap_allow, tc)
{
	int fds[2];
	ATF_REQUIRE((fds[0] = open("/bin/sh", O_EXEC)) >= 0);
	ATF_REQUIRE((fds[1] = open("/bin/sh", O_RDONLY)) >= 0);
	ATF_REQUIRE(pledge("error stdio prot_exec", NULL) >= 0);
	for (int i = 0; i < 2; i++) {
		int fl = i == 0 ? MAP_SHARED : MAP_PRIVATE;
		try_stuff_0(true, fl);
		try_stuff_1(true, fl, fds[0]);
		try_stuff_1(true, fl, fds[1]);
		try_stuff_2(true, fl, fds[1]);
	}
	ATF_REQUIRE(close(fds[0]) >= 0);
	ATF_REQUIRE(close(fds[1]) >= 0);
}

ATF_TC_WITHOUT_HEAD(mmap_deny);
ATF_TC_BODY(mmap_deny, tc)
{
	int fds[2];
	ATF_REQUIRE((fds[0] = open("/bin/sh", O_EXEC)) >= 0);
	ATF_REQUIRE((fds[1] = open("/bin/sh", O_RDONLY)) >= 0);
	ATF_REQUIRE(pledge("error stdio", NULL) >= 0);
	for (int i = 0; i < 2; i++) {
		int fl = i == 0 ? MAP_SHARED : MAP_PRIVATE;
		try_stuff_0(false, fl);
		try_stuff_1(false, fl, fds[0]);
		try_stuff_1(false, fl, fds[1]);
		try_stuff_2(false, fl, fds[1]);
	}
	ATF_REQUIRE(close(fds[0]) >= 0);
	ATF_REQUIRE(close(fds[1]) >= 0);
}


ATF_TC_WITHOUT_HEAD(pshm_allow);
ATF_TC_BODY(pshm_allow, tc)
{
	int fd;
	ATF_REQUIRE((fd = shm_open(SHM_ANON, O_RDWR, 0)) >= 0);
	ATF_REQUIRE(ftruncate(fd, PAGE_SIZE) >= 0);
	ATF_REQUIRE(pledge("error stdio prot_exec", NULL) >= 0);
	for (int i = 0; i < 2; i++) {
		int fl = i == 0 ? MAP_SHARED : MAP_PRIVATE;
		try_stuff_1(true, fl, fd);
		try_stuff_2(true, fl, fd);
	}
	ATF_CHECK(close(fd) >= 0);
}

ATF_TC_WITHOUT_HEAD(pshm_deny);
ATF_TC_BODY(pshm_deny, tc)
{
	int fd;
	ATF_REQUIRE((fd = shm_open(SHM_ANON, O_RDWR, 0)) >= 0);
	ATF_REQUIRE(ftruncate(fd, PAGE_SIZE) >= 0);
	ATF_REQUIRE(pledge("error stdio", NULL) >= 0);
	for (int i = 0; i < 2; i++) {
		int fl = i == 0 ? MAP_SHARED : MAP_PRIVATE;
		try_stuff_1(false, fl, fd);
		try_stuff_2(false, fl, fd);
	}
	ATF_CHECK(close(fd) >= 0);
}


ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, mmap_allow);
	ATF_TP_ADD_TC(tp, mmap_deny);
	ATF_TP_ADD_TC(tp, pshm_allow);
	ATF_TP_ADD_TC(tp, pshm_deny);
	return (atf_no_error());
}

