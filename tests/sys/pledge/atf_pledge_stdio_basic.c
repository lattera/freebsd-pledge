#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <time.h>
#include <atf-c.h>
#include <pledge.h>

/*
 * Very simple checks of things that should work with just "stdio" and not
 * cause any pledge violations.
 */

ATF_TC_WITHOUT_HEAD(misc_syscalls);
ATF_TC_BODY(misc_syscalls, tc)
{
	pid_t pid, ppid, pgrp, sid;
	size_t dtabsz;
	ATF_CHECK((pid = getpid()) > 0);
	ATF_CHECK((ppid = getppid()) > 0);
	ATF_CHECK((pgrp = getpgrp()) > 0);
	ATF_CHECK((sid = getsid(0)) > 0);
	dtabsz = (size_t)getdtablesize();
	ATF_REQUIRE(pledge("stdio", "") >= 0);
	ATF_CHECK(getpid() == pid);
	ATF_CHECK(getppid() == ppid);
	ATF_CHECK(getpgrp() == pgrp);
	ATF_CHECK(getsid(0) == sid);
	ATF_CHECK((size_t)getdtablesize() == dtabsz);
}

ATF_TC_WITHOUT_HEAD(id_syscalls);
ATF_TC_BODY(id_syscalls, tc)
{
	uid_t uid = getuid(), euid = geteuid();
	gid_t gid = getgid(), egid = getegid();
	bool tainted = issetugid() != 0;
	ATF_REQUIRE(pledge("stdio", "") >= 0);
	ATF_CHECK(getuid() == uid);
	ATF_CHECK(geteuid() == euid);
	ATF_CHECK(getgid() == gid);
	ATF_CHECK(getegid() == egid);
	ATF_CHECK((issetugid() != 0) == tainted);
}

ATF_TC_WITHOUT_HEAD(mmap_anon);
ATF_TC_BODY(mmap_anon, tc)
{
	void *p;
	ATF_REQUIRE(pledge("stdio", "") >= 0);
	ATF_REQUIRE((p = mmap(NULL, 1, PROT_READ|PROT_WRITE, MAP_ANON, -1, 0)) != MAP_FAILED);
	ATF_REQUIRE(mprotect(p, 1, PROT_READ) >= 0);
	ATF_REQUIRE(mprotect(p, 1, PROT_WRITE) >= 0);
	ATF_REQUIRE(mprotect(p, 1, PROT_READ|PROT_WRITE) >= 0);
	ATF_REQUIRE(madvise(p, 1, MADV_NORMAL) >= 0);
	ATF_REQUIRE(munmap(p, 1) >= 0);
}

ATF_TC_WITHOUT_HEAD(shm_open_anon);
ATF_TC_BODY(shm_open_anon, tc)
{
	int fd;
	ATF_REQUIRE((fd = shm_open(SHM_ANON, O_RDWR | O_CREAT, 0600)) >= 0);
	ATF_CHECK(close(fd) >= 0);
}

ATF_TC_WITH_CLEANUP(stdio_file);
ATF_TC_HEAD(stdio_file, tc) { }
ATF_TC_BODY(stdio_file, tc)
{
	FILE *f;
	ATF_REQUIRE((f = fopen("test.r", "w")));
	ATF_REQUIRE(fputs("test 1\n", f) >= 0);
	ATF_CHECK(fclose(f) >= 0);
	ATF_REQUIRE((f = fopen("test.w", "w")));
	ATF_REQUIRE(fputs("test 2\n", f) >= 0);
	ATF_CHECK(fclose(f) >= 0);
	ATF_REQUIRE((f = fopen("test.a", "w")));
	ATF_REQUIRE(fputs("test 3\n", f) >= 0);
	ATF_CHECK(fclose(f) >= 0);

	FILE *r, *w, *a;
	ATF_REQUIRE((r = fopen("test.r", "r")));
	ATF_REQUIRE((w = fopen("test.w", "w")));
	ATF_REQUIRE((a = fopen("test.a", "a")));

	ATF_REQUIRE(pledge("stdio", "") >= 0);

	char buf0[7];
	ATF_CHECK(fread(buf0, 1, sizeof buf0, r) == sizeof buf0);
	ATF_CHECK(memcmp(buf0, "test 1\n", sizeof buf0) == 0);

	char buf1[] = "test 4\n";
	ATF_CHECK(fwrite(buf1, 1, sizeof buf1, w) == sizeof buf1);

	char buf2[] = "test 5\n";
	ATF_CHECK(fwrite(buf2, 1, sizeof buf2, a) == sizeof buf2);

	ATF_CHECK(fclose(r) >= 0);
	ATF_CHECK(fclose(w) >= 0);
	ATF_CHECK(fclose(a) >= 0);
}
ATF_TC_CLEANUP(stdio_file, tc)
{
	FILE *f;
	char buf0[7], buf1[14];
	ATF_REQUIRE((f = fopen("test.r", "r")));
	ATF_CHECK(fread(buf0, 1, sizeof buf0, f) == sizeof buf0);
	ATF_CHECK(memcmp(buf0, "test 1\n", sizeof buf0) == 0);
	ATF_CHECK(fclose(f) >= 0);
	ATF_REQUIRE((f = fopen("test.w", "r")));
	ATF_CHECK(fread(buf0, 1, sizeof buf0, f) == sizeof buf0);
	ATF_CHECK(memcmp(buf0, "test 4\n", sizeof buf0) == 0);
	ATF_CHECK(fclose(f) >= 0);
	ATF_REQUIRE((f = fopen("test.a", "r")));
	ATF_CHECK(fread(buf1, 1, sizeof buf1, f) == sizeof buf1);
	ATF_CHECK(memcmp(buf1, "test 3\ntest 5\n", sizeof buf1) == 0);
	ATF_CHECK(fclose(f) >= 0);
}

ATF_TC_WITHOUT_HEAD(pipe_fork);
ATF_TC_BODY(pipe_fork, tc)
{
	pid_t pid;
	int fds[2], fd;
	ATF_REQUIRE(pipe(fds) >= 0);
	ATF_REQUIRE((pid = fork()) >= 0);
	if (pid == 0) {
		ATF_REQUIRE(pledge("stdio", "") >= 0);
		ATF_REQUIRE(close(fds[0]) >= 0);
		ATF_REQUIRE(write(fds[1], "!", 1) == 1);
		ATF_REQUIRE(close(fds[1]) >= 0);
		_exit(0);
	}
	ATF_REQUIRE(pledge("stdio", "") >= 0);
	ATF_CHECK((fd = dup(fds[0])) >= 0);
	ATF_CHECK(close(fds[0]) >= 0);
	ATF_CHECK(close(fds[1]) >= 0);
	char c;
	ATF_CHECK(read(fd, &c, sizeof c) == 1);
	ATF_CHECK_EQ('!', c);
	ATF_CHECK(close(fd) >= 0);
}

ATF_TC_WITHOUT_HEAD(isatty);
ATF_TC_BODY(isatty, tc)
{
	int v;
	ATF_REQUIRE((v = isatty(STDIN_FILENO)) >= 0);
	ATF_REQUIRE(pledge("stdio", "") >= 0);
	ATF_CHECK(isatty(STDIN_FILENO) == v);
}

ATF_TC_WITHOUT_HEAD(localtime);
ATF_TC_BODY(localtime, tc)
{
	time_t now;
	ATF_CHECK(time(&now));
	pid_t pid = atf_utils_fork();
	if (pid == 0) {
		struct tm *tm;
		ATF_REQUIRE(pledge("stdio", "") >= 0);
		ATF_REQUIRE((tm = localtime(&now)));
		char buf[256];
		ATF_REQUIRE(strftime(buf, sizeof buf, "%c", tm) > 0);
		ATF_CHECK(fputs(buf, stdout) >= 0);
		fflush(stdout);
		_exit(0);
	}
	struct tm *tm;
	ATF_REQUIRE((tm = localtime(&now)));
	char buf[256];
	ATF_REQUIRE(strftime(buf, sizeof buf, "%c", tm) > 0);
	atf_utils_wait(pid, 0, buf, "");
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, misc_syscalls);
	ATF_TP_ADD_TC(tp, id_syscalls);
	ATF_TP_ADD_TC(tp, mmap_anon);
	ATF_TP_ADD_TC(tp, shm_open_anon);
	ATF_TP_ADD_TC(tp, stdio_file);
	ATF_TP_ADD_TC(tp, pipe_fork);
	ATF_TP_ADD_TC(tp, isatty);
	ATF_TP_ADD_TC(tp, localtime);
	return (atf_no_error());
}
