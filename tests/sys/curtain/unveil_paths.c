#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <atf-c.h>
#include <pledge.h>

#include "path-utils.h"

/*
 * NOTE: When pledge() is not called, unveil() implicitly enables all sysfils
 * known to the pledge()/unveil() library.
 */

ATF_TC_WITHOUT_HEAD(do_nothing);
ATF_TC_BODY(do_nothing, tc)
{
	/* unveil(NULL, NULL) does nothing if no unveils were done */
	ATF_REQUIRE(unveil(NULL, NULL) >= 0);
	check_access("/", "dr+");
	check_access("/dev", "dr+");
	check_access("/etc", "dr+");
	check_access("/var", "dr+");
	check_access(".", "drw");
}

ATF_TC_WITHOUT_HEAD(unveil_one_i);
ATF_TC_BODY(unveil_one_i, tc)
{
	atf_utils_create_file("test", "");
	ATF_REQUIRE(unveil("test", "i") >= 0);
	ATF_REQUIRE(unveil(NULL, NULL) >= 0);
	check_access("test", "i");
}

ATF_TC_WITHOUT_HEAD(unveil_one_r);
ATF_TC_BODY(unveil_one_r, tc)
{
	atf_utils_create_file("test", "");
	ATF_REQUIRE(unveil("test", "r") >= 0);
	ATF_REQUIRE(unveil(NULL, NULL) >= 0);
	check_access("test", "r");
}

ATF_TC_WITHOUT_HEAD(unveil_one_w);
ATF_TC_BODY(unveil_one_w, tc)
{
	atf_utils_create_file("test", "");
	ATF_REQUIRE(unveil("test", "w") >= 0);
	ATF_REQUIRE(unveil(NULL, NULL) >= 0);
	check_access("test", "w");
}

ATF_TC_WITHOUT_HEAD(unveil_one_c);
ATF_TC_BODY(unveil_one_c, tc)
{
	atf_utils_create_file("test", "");
	ATF_REQUIRE(unveil("test", "c") >= 0);
	ATF_REQUIRE(unveil(NULL, NULL) >= 0);
	check_access("test", "e");
	ATF_REQUIRE(unlink("test") >= 0);
}

ATF_TC_WITHOUT_HEAD(unveil_one_x);
ATF_TC_BODY(unveil_one_x, tc)
{
	atf_utils_create_file("test", "");
	ATF_REQUIRE(chmod("test", 0755) >= 0);
	ATF_REQUIRE(unveil("test", "x") >= 0);
	ATF_REQUIRE(unveil(NULL, NULL) >= 0);
	check_access("test", "x");
}

ATF_TC_WITHOUT_HEAD(unveil_one_b);
ATF_TC_BODY(unveil_one_b, tc)
{
	atf_utils_create_file("test", "");
	ATF_REQUIRE(unveil("test", "b") >= 0);
	ATF_REQUIRE(unveil(NULL, NULL) >= 0);
	check_access("test", "i");
}

ATF_TC_WITHOUT_HEAD(hide_all);
ATF_TC_BODY(hide_all, tc)
{
	ATF_REQUIRE(unveil_freeze() >= 0);
	check_access("/", "d");
	check_access("/dev", "d");
	check_access("/etc", "d");
	check_access("/var", "d");
}

ATF_TC_WITHOUT_HEAD(unveil_all_r);
ATF_TC_BODY(unveil_all_r, tc)
{
	ATF_REQUIRE(unveil("/", "r") >= 0);
	ATF_REQUIRE(unveil(NULL, NULL) >= 0);
	check_access("/", "dr");
	check_access("/dev", "dr");
	check_access("/etc", "dr");
	check_access("/var", "dr");
}

ATF_TC_WITHOUT_HEAD(descend_trivial);
ATF_TC_BODY(descend_trivial, tc)
{
	ATF_REQUIRE(try_mkdir("a") >= 0);
	ATF_REQUIRE(try_creat("a/0") >= 0);
	ATF_REQUIRE(try_mkdir("a/b") >= 0);
	ATF_REQUIRE(try_creat("a/b/1") >= 0);
	ATF_REQUIRE(try_mkdir("a/b/c") >= 0);
	ATF_REQUIRE(try_creat("a/b/c/2") >= 0);
	ATF_REQUIRE(unveil(".", "r") >= 0);
	ATF_REQUIRE(unveil("a/b/c", "rw") >= 0);
	ATF_REQUIRE(unveil(NULL, NULL) >= 0);
	check_access("a", "rd");
	check_access("a/0", "r");
	check_access("a/b", "rd");
	check_access("a/b/1", "r");
	check_access("a/b/c", "rwd");
	check_access("a/b/c/2", "rw");
}

ATF_TC_WITHOUT_HEAD(descend_trivial_extra_dots);
ATF_TC_BODY(descend_trivial_extra_dots, tc)
{
	ATF_REQUIRE(try_mkdir("a") >= 0);
	ATF_REQUIRE(try_creat("a/0") >= 0);
	ATF_REQUIRE(try_mkdir("a/b") >= 0);
	ATF_REQUIRE(try_creat("a/b/1") >= 0);
	ATF_REQUIRE(try_mkdir("a/b/c") >= 0);
	ATF_REQUIRE(try_creat("a/b/c/2") >= 0);
	ATF_REQUIRE(unveil(".", "r") >= 0);
	ATF_REQUIRE(unveil("a/b/c", "rw") >= 0);
	ATF_REQUIRE(unveil(NULL, NULL) >= 0);
	check_access("a/.", "rd");
	check_access("./a/0", "r");
	check_access("a/b/.", "rd");
	check_access("a/./b/./1", "r");
	check_access("a/./b/c", "rwd");
	check_access("./a/b/./c/2", "rw");
}

ATF_TC_WITHOUT_HEAD(descend_dotdots);
ATF_TC_BODY(descend_dotdots, tc)
{
	ATF_REQUIRE(try_mkdir("a") >= 0);
	ATF_REQUIRE(try_creat("a/0") >= 0);
	ATF_REQUIRE(try_mkdir("a/b") >= 0);
	ATF_REQUIRE(try_creat("a/b/1") >= 0);
	ATF_REQUIRE(try_mkdir("a/b/c") >= 0);
	ATF_REQUIRE(try_creat("a/b/c/2") >= 0);
	ATF_REQUIRE(unveil(".", "r") >= 0);
	ATF_REQUIRE(unveil("a/b/c", "rw") >= 0);
	ATF_REQUIRE(unveil(NULL, NULL) >= 0);
	check_access("..", "");
	check_access("a/..", "rd");
	check_access("a/../a/0", "r");
	check_access("a/../a/b/c/..", "rd");
	check_access("a/b/../b/../b/c/../1", "r");
	check_access("a/b/../b/../b/c/../c", "rwd");
	check_access("a/b/c/../../../a/b/../b/c/2", "rw");
}

ATF_TC_WITHOUT_HEAD(chdir0);
ATF_TC_BODY(chdir0, tc)
{
	ATF_REQUIRE(unveil("/dev", "r") >= 0);
	ATF_CHECK_ERRNO(ENOENT, chdir("/etc") < 0);
	ATF_REQUIRE(chdir("/dev") >= 0);
	check_access(".", "dr");
	check_access("null", "r");
}

ATF_TC_WITHOUT_HEAD(chdir1);
ATF_TC_BODY(chdir1, tc)
{
	ATF_REQUIRE(unveil("/", "i") >= 0);
	ATF_REQUIRE(unveil("/dev", "r") >= 0);
	ATF_REQUIRE(unveil("/var", "i") >= 0);
	ATF_REQUIRE(unveil("/var/db", "i") >= 0);
	ATF_REQUIRE(unveil("/etc", "r") >= 0);
	ATF_REQUIRE(unveil(NULL, NULL) >= 0);
	ATF_REQUIRE(chdir("/") >= 0);
	check_access(".", "di");
	check_access("dev", "dr");
	check_access("var", "di");
	check_access("etc", "dr");
	check_access("root", "d");
	ATF_REQUIRE(chdir("dev") >= 0);
	check_access(".", "dr");
	ATF_REQUIRE(chdir("../var") >= 0);
	ATF_CHECK_ERRNO(ENOENT, chdir("empty") < 0);
	ATF_REQUIRE(chdir("db") >= 0);
	check_access(".", "di");
	ATF_REQUIRE(chdir("../../etc") >= 0);
	check_access(".", "dr");
	check_access("rc", "r");
	ATF_CHECK_ERRNO(ENOENT, chdir("../root") < 0);
	ATF_REQUIRE(chdir("..") >= 0);
}

ATF_TC_WITHOUT_HEAD(cwd_deny);
ATF_TC_BODY(cwd_deny, tc)
{
	ATF_REQUIRE(unveil_freeze() >= 0);
	check_access(".", "d");
}

ATF_TC_WITHOUT_HEAD(openat1);
ATF_TC_BODY(openat1, tc)
{
	int fd1, fd2;
	ATF_REQUIRE(unveil("/etc", "r") >= 0);
	ATF_REQUIRE(unveil("/dev", "r") >= 0);
	ATF_REQUIRE((fd1 = open("/etc", O_SEARCH)) >= 0);
	ATF_REQUIRE((fd2 = open("/dev", O_SEARCH)) >= 0);
	check_accessat(fd1, ".", "dr");
	check_accessat(fd1, "rc", "r");
	check_accessat(fd1, "../dev/null", "r");
	check_accessat(fd2, ".", "dr");
	check_accessat(fd2, "null", "r");
	check_accessat(fd2, "../etc/rc", "r");
	ATF_CHECK(close(fd1) >= 0);
	ATF_CHECK(close(fd2) >= 0);
}

ATF_TC_WITHOUT_HEAD(openat2);
ATF_TC_BODY(openat2, tc)
{
	int fd1, fd2;
	ATF_REQUIRE(try_mkdir("a") >= 0);
	ATF_REQUIRE(try_creat("a/0") >= 0);
	ATF_REQUIRE(try_mkdir("b") >= 0);
	ATF_REQUIRE(try_creat("b/1") >= 0);
	ATF_REQUIRE(unveil("a", "r") >= 0);
	ATF_REQUIRE(unveil("b", "rw") >= 0);
	ATF_REQUIRE(unveil(NULL, NULL) >= 0);
	ATF_REQUIRE((fd1 = open("a", O_SEARCH)) >= 0);
	ATF_REQUIRE((fd2 = open("b", O_SEARCH)) >= 0);
	check_accessat(fd1, ".", "rd");
	check_accessat(fd1, "0", "r");
	check_accessat(fd1, "../b", "rwd");
	check_accessat(fd1, "../b/.", "rwd");
	check_accessat(fd1, "../b/1", "rw");
	check_accessat(fd1, "../b/../a", "rd");
	check_accessat(fd2, ".", "rwd");
	check_accessat(fd2, "1", "rw");
	check_accessat(fd2, "../a", "rd");
	check_accessat(fd2, "../a/.", "rd");
	check_accessat(fd2, "../a/0", "r");
	check_accessat(fd2, "../a/../b", "rwd");
	ATF_CHECK(close(fd1) >= 0);
	ATF_CHECK(close(fd2) >= 0);
}

ATF_TC_WITHOUT_HEAD(listing_allow);
ATF_TC_BODY(listing_allow, tc)
{
	DIR *d;
	struct dirent *e;
	bool found;
	ATF_REQUIRE(try_mkdir("d") >= 0);
	ATF_REQUIRE(try_creat("d/f") >= 0);
	ATF_REQUIRE(unveil("d", "b") >= 0);
	check_access("d", "rd");
	check_access("d/f", "i");
	ATF_REQUIRE((d = opendir("d")));
	found = false;
	while ((e = readdir(d)))
		if (strcmp(e->d_name, "f") == 0)
			found = true;
	ATF_CHECK(found);
}

ATF_TC_WITHOUT_HEAD(listing_deny);
ATF_TC_BODY(listing_deny, tc)
{
	ATF_REQUIRE(try_mkdir("d") >= 0);
	ATF_REQUIRE(try_creat("d/f") >= 0);
	ATF_REQUIRE(unveil("d", "w") >= 0);
	check_access("d", "wd");
	check_access("d/f", "w");
	ATF_CHECK_ERRNO(EACCES, !opendir("d"));
}

ATF_TC_WITHOUT_HEAD(symlink0);
ATF_TC_BODY(symlink0, tc)
{
	ATF_REQUIRE(try_creat("f") >= 0);
	ATF_REQUIRE(symlink("f", "l") >= 0);
	ATF_REQUIRE(unveil("l", "r") >= 0);
	check_access(".", "");
	check_access("f", "r");
	check_access("l", "r");
}

ATF_TC_WITHOUT_HEAD(symlink1);
ATF_TC_BODY(symlink1, tc)
{
	ATF_REQUIRE(try_mkdir("a") >= 0);
	ATF_REQUIRE(try_mkdir("a/b") >= 0);
	ATF_REQUIRE(try_mkdir("a/b/c") >= 0);
	ATF_REQUIRE(try_creat("a/b/c/f") >= 0);
	ATF_REQUIRE(symlink("../a/b", "a/l1") >= 0);
	ATF_REQUIRE(symlink("c/l3", "a/b/l2") >= 0);
	ATF_REQUIRE(symlink("..", "a/b/c/l3") >= 0);
	ATF_REQUIRE(symlink("f", "a/b/c/l4") >= 0);
	ATF_REQUIRE(unveil("a/l1/l2/c/f", "r") >= 0);
	check_access(".", "");
	check_access("a", "");
	check_access("a/1", "");
	check_access("a/b", "");
	check_access("a/b/l2", "");
	check_access("a/b/c", "");
	check_access("a/b/c/l3", "");
	check_access("a/b/c/l4", "");
	check_access("a/b/c/f", "r");
	check_access("a/l1/l2/c/l3/c/f", "r");
	check_access("a/l1/l2/c/l3/c/l4", "");
}

ATF_TC_WITHOUT_HEAD(symlink2);
ATF_TC_BODY(symlink2, tc)
{
	ATF_REQUIRE(try_mkdir("d") >= 0);
	ATF_REQUIRE(try_creat("d/f") >= 0);
	ATF_REQUIRE(symlink(".", "d/l") >= 0);
	ATF_REQUIRE(unveil("d", "r") >= 0);
	ATF_REQUIRE(unveil("d/l/f", "rw") >= 0);
	check_access(".", "");
	check_access("d", "dr");
	check_access("d/f", "rw");
	check_access("d/l", "dr");
	check_access("d/l/f", "rw");
	char buf[8];
	ATF_REQUIRE(readlink("d/l", buf, sizeof buf) >= 0);
	ATF_CHECK(memcmp(buf, ".", 1) == 0);
}

ATF_TC_WITHOUT_HEAD(symlink_opacity);
ATF_TC_BODY(symlink_opacity, tc)
{
	ATF_REQUIRE(try_creat("f") >= 0);
	ATF_REQUIRE(symlink("f", "l") >= 0);
	ATF_REQUIRE(unveil("l", "r") >= 0);
	char buf[8];
	ATF_CHECK_ERRNO(ENOENT, readlink("l", buf, sizeof buf) < 0);
}

ATF_TC_WITHOUT_HEAD(protect_file);
ATF_TC_BODY(protect_file, tc)
{
	ATF_REQUIRE(try_creat("p") >= 0); /* protected file */
	ATF_REQUIRE(try_creat("u") >= 0); /* unprotected file */
	ATF_REQUIRE(unveil("p", "r") >= 0);
	ATF_REQUIRE(unveil("u", "rwca") >= 0);
	ATF_REQUIRE(unveil(".", "rwca") >= 0);
	check_access(".", "drw");
	check_access("p", "r");
	check_access("u", "rw");
	/*
	 * Try various shenanigans that must not be allowed on a file even with
	 * full permissions on its containing directory.
	 */
	ATF_CHECK_ERRNO(EACCES, open("p", O_WRONLY|O_TRUNC) < 0);
	ATF_CHECK_ERRNO(EACCES, truncate("p", 0) < 0);
	ATF_CHECK_ERRNO(EACCES, unlink("p") < 0);
	ATF_CHECK_ERRNO(EACCES, rename("p", "o") < 0);
	ATF_CHECK_ERRNO(EACCES, rename("p", "u") < 0);
	ATF_CHECK_ERRNO(EACCES, rename("u", "p") < 0);
	/*
	 * Hard-linking a file under a path unveiled with higher permissions
	 * would allow to modify it.
	 */
	ATF_CHECK_ERRNO(EACCES, link("p", "o") < 0);
	/* Already wouldn't be allowed, but let's have a look at the errnos... */
	ATF_CHECK_ERRNO(EEXIST, link("p", "u") < 0);
	ATF_CHECK_ERRNO(EEXIST, link("u", "p") < 0);
	ATF_CHECK_ERRNO(EEXIST, symlink("x", "p") < 0);
}

ATF_TC_WITHOUT_HEAD(dev_stdin);
ATF_TC_BODY(dev_stdin, tc)
{
	ATF_REQUIRE(unveil("/dev/stdin", "r") >= 0); /* NOTE: may be a symlink */
	check_access("/dev/stdin", "r");
}

ATF_TC_WITHOUT_HEAD(dev_stdout);
ATF_TC_BODY(dev_stdout, tc)
{
	ATF_REQUIRE(unveil("/dev/stdout", "w") >= 0); /* NOTE: may be a symlink */
	check_access("/dev/stdout", "w");
}


ATF_TC_WITHOUT_HEAD(keep_stdio_hidden);
ATF_TC_BODY(keep_stdio_hidden, tc)
{
	ATF_REQUIRE(unveil_freeze() >= 0);
	/* Those files could be unveiled with a pledge, but must not be by default. */
	check_access("/dev/null", "");
	check_access("/dev/random", "");
}

ATF_TC_WITHOUT_HEAD(keep_stdio_unwritable);
ATF_TC_BODY(keep_stdio_unwritable, tc)
{
	ATF_REQUIRE(unveil("/", "r") >= 0);
	ATF_REQUIRE(unveil(NULL, NULL) >= 0);
	/* Could get "w" permission on /dev/null with a pledge, but it must not have it by default. */
	check_access("/dev/null", "r");
	check_access("/dev/random", "r");
}

ATF_TC_WITHOUT_HEAD(unveil_perm_drop);
ATF_TC_BODY(unveil_perm_drop, tc)
{
	atf_utils_create_file("test", "");
	/*
	 * Multiple unveil(NULL, NULL) calls are allowed and should work
	 * similarly to how multiple pledge() calls work: each call sets hard
	 * limits that cannot be raised by future calls.
	 */
	ATF_REQUIRE(unveil("test", "r") >= 0);
	ATF_REQUIRE(unveil(NULL, NULL) >= 0);
	check_access("test", "r");

	ATF_REQUIRE(unveil("test", "rw") >= 0);
	ATF_REQUIRE(unveil(NULL, NULL) >= 0);
	check_access("test", "r");

	ATF_REQUIRE(unveil("test", "i") >= 0);
	ATF_REQUIRE(unveil(NULL, NULL) >= 0);
	check_access("test", "i");

	ATF_REQUIRE(unveil("test", "") >= 0);
	ATF_REQUIRE(unveil(NULL, NULL) >= 0);
	check_access("test", "");
}

ATF_TC_WITHOUT_HEAD(unveil_perm_raise);
ATF_TC_BODY(unveil_perm_raise, tc)
{
	atf_utils_create_file("test", "");
	/* Can raise permissions when unveil(NULL, NULL) hasn't been called. */
	ATF_REQUIRE(unveil("test", "r") >= 0);
	check_access("test", "r");

	ATF_REQUIRE(unveil("test", "rw") >= 0);
	check_access("test", "rw");

	ATF_REQUIRE(unveil("test", "") >= 0);
	check_access("test", "");

	ATF_REQUIRE(unveil("test", "rw") >= 0);
	check_access("test", "rw");
}


ATF_TC_WITHOUT_HEAD(conceal_path);
ATF_TC_BODY(conceal_path, tc)
{
	ATF_REQUIRE(try_creat("f") >= 0);
	ATF_REQUIRE(try_mkdir("d") >= 0);
	ATF_REQUIRE(try_mkdir("h") >= 0);
	ATF_REQUIRE(try_creat("h/f") >= 0);
	ATF_REQUIRE(try_mkdir("h/d") >= 0);
	ATF_REQUIRE(try_creat("h/d/f") >= 0);
	ATF_REQUIRE(unveil(".", "rwcx") >= 0);
	ATF_REQUIRE(unveil("h", "") >= 0);
	check_access(".", "drw");
	check_access("h", "d");
	check_access("h/f", "");
	check_access("h/d", "d");
	check_access("h/d/f", "");

	/*
	 * NOTE: The current implementation doesn't allow to descend into
	 * hidden directories at all during path lookups, so these tests don't
	 * actually trigger the special conditions for most of those
	 * operation-specific errnos to be returned.
	 *
	 * This only works for directories that have no unveil permissions.
	 * Paths can still be discovered on write-only directories.  There are
	 * many more cases that would need to be tested if path concealment
	 * were to be implemented for write-only directories.
	 */

	ATF_CHECK_ERRNO(ENOENT, try_open("h/u", O_CREAT | O_WRONLY) < 0);
	ATF_CHECK_ERRNO(ENOENT, try_open("h/d/u", O_CREAT | O_WRONLY) < 0);
	ATF_CHECK_ERRNO(ENOENT, try_open("h/u", O_WRONLY) < 0);
	ATF_CHECK_ERRNO(ENOENT, try_open("h/d/u", O_WRONLY) < 0);
	/* EEXIST hidden */
	ATF_CHECK_ERRNO(ENOENT, try_open("h/f", O_CREAT | O_EXCL | O_WRONLY) < 0);
	ATF_CHECK_ERRNO(ENOENT, try_open("h/d/f", O_CREAT | O_EXCL | O_WRONLY) < 0);
	/* EISDIR hidden */
	ATF_CHECK_ERRNO(ENOENT, try_open("h/d", O_WRONLY) < 0);
	ATF_CHECK_ERRNO(ENOENT, try_open("h/d", O_CREAT | O_EXCL | O_WRONLY) < 0);
	/* ENOTDIR hidden */
	ATF_CHECK_ERRNO(ENOENT, try_open("h/f/", O_RDONLY) < 0);
	ATF_CHECK_ERRNO(ENOENT, try_open("h/f/u", O_RDONLY) < 0);
	ATF_CHECK_ERRNO(ENOENT, try_open("h/f/.", O_RDONLY) < 0);
	ATF_CHECK_ERRNO(ENOENT, try_open("h/f/..", O_RDONLY) < 0);
	ATF_CHECK_ERRNO(ENOENT, try_open("h/d/f/", O_RDONLY) < 0);
	ATF_CHECK_ERRNO(ENOENT, try_open("h/d/f/u", O_RDONLY) < 0);
	ATF_CHECK_ERRNO(ENOENT, try_open("h/d/f/.", O_RDONLY) < 0);
	ATF_CHECK_ERRNO(ENOENT, try_open("h/d/f/..", O_RDONLY) < 0);
	ATF_CHECK_ERRNO(ENOENT, try_open("h/d/../f/u", O_RDONLY) < 0);
	ATF_CHECK_ERRNO(ENOENT, try_open("h/d/../f/.", O_RDONLY) < 0);
	ATF_CHECK_ERRNO(ENOENT, try_open("h/d/../f/..", O_RDONLY) < 0);

	ATF_CHECK_ERRNO(ENOENT, chdir("h") < 0);
	ATF_CHECK_ERRNO(ENOENT, chdir("h/.") < 0);
	ATF_CHECK_ERRNO(ENOENT, chdir("h/../h") < 0);
	ATF_CHECK_ERRNO(ENOENT, chdir("h/d") < 0);
	ATF_CHECK_ERRNO(ENOENT, chdir("h/d/.") < 0);
	ATF_CHECK_ERRNO(ENOENT, chdir("h/d/..") < 0);
	ATF_CHECK_ERRNO(ENOENT, chdir("h/d/../d") < 0);
	/* ENOTDIR hidden */
	ATF_CHECK_ERRNO(ENOENT, chdir("h/f") < 0);
	ATF_CHECK_ERRNO(ENOENT, chdir("h/d/f") < 0);

	/* EEXIST hidden */
	ATF_CHECK_ERRNO(ENOENT, try_mkdir("h/f") < 0);
	ATF_CHECK_ERRNO(ENOENT, try_mkdir("h/f/u") < 0);
	ATF_CHECK_ERRNO(ENOENT, try_mkdir("h/f/.") < 0);
	ATF_CHECK_ERRNO(ENOENT, try_mkdir("h/f/..") < 0);
	ATF_CHECK_ERRNO(ENOENT, try_mkdir("h/d") < 0);
	ATF_CHECK_ERRNO(ENOENT, try_mkdir("h/d/u") < 0);
	ATF_CHECK_ERRNO(ENOENT, try_mkdir("h/d/.") < 0);
	ATF_CHECK_ERRNO(ENOENT, try_mkdir("h/d/..") < 0);
	ATF_CHECK_ERRNO(ENOENT, try_mkdir("h/d/../f") < 0);
	ATF_CHECK_ERRNO(ENOENT, try_mkdir("h/d/../d") < 0);
	ATF_CHECK_ERRNO(ENOENT, try_mkdir("h/d/../u") < 0);
	ATF_CHECK_ERRNO(ENOENT, try_mkdir("h/d/../.") < 0);
	ATF_CHECK_ERRNO(ENOENT, try_mkdir("h/d/../..") < 0);
	/* ENOTEMPTY hidden */
	ATF_CHECK_ERRNO(ENOENT, rmdir("h/d") < 0);
	/* ENOTDIR hidden */
	ATF_CHECK_ERRNO(ENOENT, rmdir("h/f") < 0);
	ATF_CHECK_ERRNO(ENOENT, rmdir("h/d/f") < 0);
	/* EINVAL hidden */
	ATF_CHECK_ERRNO(ENOENT, rmdir("h/d/.") < 0);

	/* EPERM hidden */
	ATF_CHECK_ERRNO(ENOENT, unlink("h/d") < 0);
	ATF_CHECK_ERRNO(ENOENT, unlink("h/d/.") < 0);
	ATF_CHECK_ERRNO(ENOENT, unlink("h/d/../d") < 0);

	/* EISDIR hidden */
	ATF_CHECK_ERRNO(ENOENT, truncate("h/d", 0) < 0);
	ATF_CHECK_ERRNO(ENOENT, truncate("h/d/.", 0) < 0);
	ATF_CHECK_ERRNO(ENOENT, truncate("h/d/../d", 0) < 0);

	ATF_CHECK_ERRNO(ENOENT, link("h/f", "t") < 0);
	ATF_CHECK_ERRNO(ENOENT, link("h/d", "t") < 0); /* EPERM hidden */
	ATF_CHECK_ERRNO(ENOENT, link("h/d/f", "t") < 0);
	/* EEXIST hidden */
	ATF_CHECK_ERRNO(ENOENT, symlink("t", "h/f") < 0);
	ATF_CHECK_ERRNO(ENOENT, symlink("t", "h/d") < 0);
	ATF_CHECK_ERRNO(ENOENT, symlink("t", "h/d/f") < 0);
	ATF_CHECK_ERRNO(ENOENT, link("f", "h/f") < 0);
	ATF_CHECK_ERRNO(ENOENT, link("f", "h/d") < 0);
	ATF_CHECK_ERRNO(ENOENT, link("f", "h/d/f") < 0);

	ATF_CHECK_ERRNO(ENOENT, rename("f", "h/u") < 0);
	ATF_CHECK_ERRNO(ENOENT, rename("f", "h/f") < 0);
	ATF_CHECK_ERRNO(ENOENT, rename("h/f", "u") < 0);
	ATF_CHECK_ERRNO(ENOENT, rename("h/f", "f") < 0);
	ATF_CHECK_ERRNO(ENOENT, rename("h/f", "h/u") < 0);
	ATF_CHECK_ERRNO(ENOENT, rename("h/f", "h/f") < 0);
	ATF_CHECK_ERRNO(ENOENT, rename("d", "h/u") < 0);
	ATF_CHECK_ERRNO(ENOENT, rename("d", "h/d") < 0);
	ATF_CHECK_ERRNO(ENOENT, rename("h/d", "u") < 0);
	ATF_CHECK_ERRNO(ENOENT, rename("h/d", "d") < 0);
	ATF_CHECK_ERRNO(ENOENT, rename("h/d", "h/u") < 0);
	ATF_CHECK_ERRNO(ENOENT, rename("h/d", "h/d") < 0);
	/* EISDIR hidden */
	ATF_CHECK_ERRNO(ENOENT, rename("f", "h/d") < 0);
	ATF_CHECK_ERRNO(ENOENT, rename("h/f", "h/d") < 0);
	/* ENOTDIR hidden */
	ATF_CHECK_ERRNO(ENOENT, rename("d", "h/f") < 0);
	ATF_CHECK_ERRNO(ENOENT, rename("h/d", "h/f") < 0);
}


ATF_TC_WITHOUT_HEAD(linkat_both_fds);
ATF_TC_BODY(linkat_both_fds, tc)
{
	int fd1, fd2;
	ATF_REQUIRE(try_mkdir("a") >= 0);
	ATF_REQUIRE(try_mkdir("b") >= 0);
	ATF_REQUIRE(try_creat("a/f") >= 0);
	ATF_REQUIRE(unveil(".", "rwcax") >= 0);
	ATF_REQUIRE((fd1 = open("a", O_RDONLY)) >= 0);
	ATF_REQUIRE((fd2 = open("b", O_RDONLY)) >= 0);
	ATF_CHECK(linkat(fd1, "f", fd2, "f", 0) >= 0);
}

ATF_TC_WITHOUT_HEAD(renameat_both_fds);
ATF_TC_BODY(renameat_both_fds, tc)
{
	int fd1, fd2;
	ATF_REQUIRE(try_mkdir("a") >= 0);
	ATF_REQUIRE(try_mkdir("b") >= 0);
	ATF_REQUIRE(try_creat("a/f") >= 0);
	ATF_REQUIRE(unveil(".", "rwcax") >= 0);
	ATF_REQUIRE((fd1 = open("a", O_RDONLY)) >= 0);
	ATF_REQUIRE((fd2 = open("b", O_RDONLY)) >= 0);
	ATF_CHECK(renameat(fd1, "f", fd2, "f") >= 0);
}


ATF_TC_WITHOUT_HEAD(open_o_path);
ATF_TC_BODY(open_o_path, tc)
{
	int fd, r;
	ATF_REQUIRE(try_mkdir("d") >= 0);
	ATF_REQUIRE(try_creat("d/u") >= 0);
	ATF_REQUIRE(try_creat("d/p") >= 0);
	ATF_CHECK((fd = open("d", O_PATH)) >= 0);
	ATF_REQUIRE(unveil("d/u", "r") >= 0);
	ATF_CHECK(openat(fd, ".", O_RDONLY) < 0);
	ATF_CHECK(openat(fd, "p", O_RDONLY) < 0);
	ATF_CHECK(openat(fd, "..", O_RDONLY) < 0);
	ATF_CHECK(openat(fd, "../d", O_RDONLY) < 0);
	ATF_CHECK(openat(fd, "../d/p", O_RDONLY) < 0);
	ATF_CHECK((r = openat(fd, "u", O_RDONLY)) >= 0);
	ATF_CHECK(close(r) >= 0);
	ATF_CHECK((r = openat(fd, "./u", O_RDONLY)) >= 0);
	ATF_CHECK(close(r) >= 0);
	ATF_CHECK(close(fd) >= 0);
}

static void
openat_before_unveil(bool list)
{
	int fda, fdc;
	ATF_REQUIRE(try_mkdir("a") >= 0);
	ATF_REQUIRE(try_mkdir("a/b") >= 0);
	ATF_REQUIRE(try_mkdir("a/b/c") >= 0);
	ATF_REQUIRE(try_mkdir("a/b/c/d") >= 0);
	ATF_REQUIRE(try_creat("a/0") >= 0);
	ATF_REQUIRE(try_creat("a/b/1") >= 0);
	ATF_REQUIRE(try_creat("a/b/c/2") >= 0);
	ATF_REQUIRE(try_creat("a/b/c/d/3") >= 0);
	ATF_CHECK((fda = open("a", O_RDONLY|O_DIRECTORY)) >= 0);
	ATF_CHECK((fdc = open("a/b/c", O_RDONLY|O_DIRECTORY)) >= 0);
	ATF_REQUIRE(unveil("a/b", list ? "li" : "r") >= 0);
	check_accessat(fda, NULL, "dr");
	check_accessat(fda, ".", "");
	check_accessat(fda, "..", "");
	check_accessat(fda, "../a", "");
	check_accessat(fda, "../a/0", "");
	check_accessat(fda, "0", "");
	check_accessat(fda, "b", "dr");
	check_accessat(fdc, NULL, "dr");
	check_accessat(fdc, ".", list ? "" : "dr");
	check_accessat(fdc, "..", list ? "" : "dr");
	check_accessat(fdc, "../1", list ? "" : "r");
	check_accessat(fdc, "../c", list ? "" : "dr");
	check_accessat(fdc, "2", list ? "" : "r");
	check_accessat(fdc, "d", list ? "" : "dr");
	check_accessat(fdc, "d/3", list ? "" : "r");
	check_accessat(fdc, "../..", "");
	check_accessat(fdc, "../../0", "");
	ATF_CHECK(close(fda) >= 0);
	ATF_CHECK(close(fdc) >= 0);
}

#define TEST_CASE_EXPR(name, expr) ATF_TC_WITHOUT_HEAD(name); ATF_TC_BODY(name, tc) { expr; }

TEST_CASE_EXPR(openat_before_unveil_with_read, openat_before_unveil(false))
TEST_CASE_EXPR(openat_before_unveil_with_list, openat_before_unveil(true))

ATF_TC_WITHOUT_HEAD(openat_cutoff);
ATF_TC_BODY(openat_cutoff, tc)
{
	/*
	 * What happens if we (try to) cutoff access to parent directories such
	 * that the covering unveils cannot be found for a pre-opened directory FD?
	 */
	int fd;
	ATF_REQUIRE(try_mkdir("a") >= 0);
	ATF_REQUIRE(try_mkdir("a/b") >= 0);
	ATF_REQUIRE(try_mkdir("a/b/c") >= 0);
	ATF_REQUIRE(try_creat("a/b/c/f") >= 0);
	ATF_CHECK((fd = open("a/b/c", O_RDONLY|O_DIRECTORY)) >= 0);
	ATF_REQUIRE(unveil("a", "a") >= 0);
	ATF_REQUIRE(chmod("a/b", 0) >= 0);
	ATF_REQUIRE(unveil("a", "") >= 0);
	check_accessat(fd, NULL, "dr");
	check_accessat(fd, ".", "d");
	check_accessat(fd, "f", "");
	ATF_REQUIRE(unveil("a", "a") >= 0);
	ATF_CHECK(chmod("a/b", 0755) >= 0); /* allow cleanup */
	ATF_CHECK(close(fd) >= 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, do_nothing);
	ATF_TP_ADD_TC(tp, unveil_one_i);
	ATF_TP_ADD_TC(tp, unveil_one_r);
	ATF_TP_ADD_TC(tp, unveil_one_w);
	ATF_TP_ADD_TC(tp, unveil_one_c);
	ATF_TP_ADD_TC(tp, unveil_one_x);
	ATF_TP_ADD_TC(tp, unveil_one_b);
	ATF_TP_ADD_TC(tp, hide_all);
	ATF_TP_ADD_TC(tp, unveil_all_r);
	ATF_TP_ADD_TC(tp, descend_trivial);
	ATF_TP_ADD_TC(tp, descend_trivial_extra_dots);
	ATF_TP_ADD_TC(tp, descend_dotdots);
	ATF_TP_ADD_TC(tp, chdir0);
	ATF_TP_ADD_TC(tp, chdir1);
	ATF_TP_ADD_TC(tp, cwd_deny);
	ATF_TP_ADD_TC(tp, openat1);
	ATF_TP_ADD_TC(tp, openat2);
	ATF_TP_ADD_TC(tp, listing_allow);
	ATF_TP_ADD_TC(tp, listing_deny);
	ATF_TP_ADD_TC(tp, symlink0);
	ATF_TP_ADD_TC(tp, symlink1);
	ATF_TP_ADD_TC(tp, symlink2);
	ATF_TP_ADD_TC(tp, symlink_opacity);
	ATF_TP_ADD_TC(tp, protect_file);
	ATF_TP_ADD_TC(tp, dev_stdin);
	ATF_TP_ADD_TC(tp, dev_stdout);
	ATF_TP_ADD_TC(tp, keep_stdio_hidden);
	ATF_TP_ADD_TC(tp, keep_stdio_unwritable);
	ATF_TP_ADD_TC(tp, unveil_perm_drop);
	ATF_TP_ADD_TC(tp, unveil_perm_raise);
	ATF_TP_ADD_TC(tp, conceal_path);
	ATF_TP_ADD_TC(tp, linkat_both_fds);
	ATF_TP_ADD_TC(tp, renameat_both_fds);
	ATF_TP_ADD_TC(tp, open_o_path);
	ATF_TP_ADD_TC(tp, openat_before_unveil_with_read);
	ATF_TP_ADD_TC(tp, openat_before_unveil_with_list);
	ATF_TP_ADD_TC(tp, openat_cutoff);
	return (atf_no_error());
}
