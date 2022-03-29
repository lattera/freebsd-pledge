#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <errno.h>
#include <err.h>
#include <atf-c.h>
#include <pledge.h>

static void
test_mmap_anon_1(bool should_work, int extra_prots, int extra_flags)
{
	void *p;

	warnx("%s: %u %u %u", __func__, should_work, extra_prots, extra_flags);

	p = mmap(NULL, PAGE_SIZE, PROT_EXEC | extra_prots, MAP_ANON | extra_flags, -1, 0);
	ATF_REQUIRE_EQ(p != MAP_FAILED, should_work);
	if (should_work) {
		ATF_CHECK(mprotect(p, PAGE_SIZE, PROT_EXEC | extra_prots) >= 0);
		ATF_CHECK(munmap(p, PAGE_SIZE) >= 0);
	}

	p = mmap(NULL, PAGE_SIZE, PROT_NONE | PROT_MAX(PROT_EXEC | extra_prots), MAP_ANON | extra_flags, -1, 0);
	ATF_REQUIRE(p != MAP_FAILED);
	ATF_CHECK_EQ(mprotect(p, PAGE_SIZE, PROT_EXEC | extra_prots) >= 0, should_work);
	ATF_CHECK(munmap(p, PAGE_SIZE) >= 0);
}

static void
test_mmap_anon(bool should_work)
{
	test_mmap_anon_1(should_work, PROT_NONE, MAP_PRIVATE);
	test_mmap_anon_1(should_work, PROT_READ, MAP_PRIVATE);
	test_mmap_anon_1(should_work, PROT_WRITE, MAP_PRIVATE);
	test_mmap_anon_1(should_work, PROT_READ | PROT_WRITE, MAP_PRIVATE);
}

static void
test_mmap_file_1(bool should_work, bool try_mprotect, int fd, int extra_prots, int extra_flags)
{
	void *p;

	warnx("%s: %u %u %u", __func__, should_work, extra_prots, extra_flags);

	p = mmap(NULL, PAGE_SIZE, PROT_EXEC | extra_prots, extra_flags, fd, 0);
	ATF_REQUIRE_EQ(p != MAP_FAILED, should_work);
	if (should_work) {
		if (try_mprotect)
			ATF_CHECK(mprotect(p, PAGE_SIZE, PROT_EXEC | extra_prots) >= 0);
		ATF_CHECK(munmap(p, PAGE_SIZE) >= 0);
	}

	if (try_mprotect) {
		p = mmap(NULL, PAGE_SIZE, PROT_NONE | PROT_MAX(PROT_EXEC | extra_prots), extra_flags, fd, 0);
		ATF_REQUIRE(p != MAP_FAILED);
		ATF_CHECK_EQ(mprotect(p, PAGE_SIZE, PROT_EXEC | extra_prots) >= 0, should_work);
		ATF_CHECK(munmap(p, PAGE_SIZE) >= 0);
	}
}

static void
test_mmap_file(bool should_work, bool wx_should_work, int fd)
{
	/* mprotect() not always allowed due to implementation limitations */
	bool try_mprotect = should_work == wx_should_work;
	test_mmap_file_1(should_work, try_mprotect, fd, PROT_NONE, MAP_PRIVATE);
	test_mmap_file_1(should_work, try_mprotect, fd, PROT_READ, MAP_PRIVATE);
	test_mmap_file_1(wx_should_work, try_mprotect, fd, PROT_WRITE, MAP_PRIVATE);
	test_mmap_file_1(wx_should_work, try_mprotect, fd, PROT_READ | PROT_WRITE, MAP_PRIVATE);
}

static void
test_anon(bool should_work, const char *promises)
{
	int fd;
	ATF_REQUIRE(pledge(promises, "") >= 0);
	ATF_REQUIRE((fd = shm_open(SHM_ANON, O_RDWR, 0)) >= 0);
	ATF_REQUIRE(ftruncate(fd, PAGE_SIZE) >= 0);
	test_mmap_anon(should_work);
	test_mmap_file(should_work, should_work, fd);
	ATF_CHECK(close(fd) >= 0);
}

static void
test_file(bool should_work, bool wx_should_work, bool add_unveil, const char *promises)
{
	int fd;
	ATF_REQUIRE(pledge(promises, "") >= 0);
	atf_utils_create_file("test", "TEST!\n");
	if (add_unveil) {
		ATF_REQUIRE(unveil("test", "rwx") >= 0);
		ATF_REQUIRE(unveil(NULL, NULL) >= 0);
	}
	ATF_REQUIRE((fd = open("test", O_RDWR)) >= 0);
	test_mmap_file(should_work, wx_should_work, fd);
	ATF_CHECK(close(fd) >= 0);
}


#define	BASE_PROMISES			"error stdio rpath wpath cpath"

#define TEST_CASE_EXPR(name, expr) ATF_TC_WITHOUT_HEAD(name); ATF_TC_BODY(name, tc) { expr; }

TEST_CASE_EXPR(allow_anon_prot_exec,
    test_anon(1, BASE_PROMISES " prot_exec"))
TEST_CASE_EXPR(deny_anon_prot_exec_looser,
    test_anon(0, BASE_PROMISES " prot_exec_looser"))
TEST_CASE_EXPR(deny_anon_prot_exec_loose,
    test_anon(0, BASE_PROMISES " prot_exec_loose"))
TEST_CASE_EXPR(deny_anon_no_prot_exec,
    test_anon(0, BASE_PROMISES))
TEST_CASE_EXPR(allow_file_prot_exec,
    test_file(1, 1, 0, BASE_PROMISES " prot_exec"))
TEST_CASE_EXPR(allow_file_prot_exec_looser,
    test_file(1, 0, 0, BASE_PROMISES " prot_exec_looser"))
TEST_CASE_EXPR(deny_file_prot_exec_loose,
    test_file(0, 0, 0, BASE_PROMISES " prot_exec_loose"))
TEST_CASE_EXPR(allow_file_prot_exec_loose_with_exec_and_no_unveils,
    test_file(1, 0, 0, BASE_PROMISES " exec prot_exec_loose"))
TEST_CASE_EXPR(allow_file_prot_exec_loose_with_exec_and_an_unveil,
    test_file(1, 0, 1, BASE_PROMISES " exec prot_exec_loose"))
TEST_CASE_EXPR(deny_file_no_prot_exec,
    test_file(0, 0, 0, BASE_PROMISES));

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, allow_anon_prot_exec);
	ATF_TP_ADD_TC(tp, deny_anon_prot_exec_looser);
	ATF_TP_ADD_TC(tp, deny_anon_prot_exec_loose);
	ATF_TP_ADD_TC(tp, deny_anon_no_prot_exec);
	ATF_TP_ADD_TC(tp, allow_file_prot_exec);
	ATF_TP_ADD_TC(tp, allow_file_prot_exec_looser);
	ATF_TP_ADD_TC(tp, deny_file_prot_exec_loose);
	ATF_TP_ADD_TC(tp, allow_file_prot_exec_loose_with_exec_and_no_unveils);
	ATF_TP_ADD_TC(tp, allow_file_prot_exec_loose_with_exec_and_an_unveil);
	ATF_TP_ADD_TC(tp, deny_file_no_prot_exec);
	return (atf_no_error());
}
