#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <atf-c.h>
#include <pledge.h>

static int __unused
try_creat(const char *path)
{
	int r;
	r = creat(path, 0666);
	if (r >= 0)
		close(r);
	return (r);
}

static int __unused
try_mkdir(const char *path)
{
	return (mkdir(path, 0777));
}

static int __unused
try_open(const char *path, int flags)
{
	int r;
	r = open(path, flags);
	if (r >= 0)
		close(r);
	return (r);
}

static int __unused
try_openat(int atfd, const char *path, int flags)
{
	int r, r2;
	r = openat(atfd, path, flags);
	if (r >= 0)
		close(r);
	if (atfd == AT_FDCWD) {
		r2 = try_open(path, flags);
		ATF_CHECK_EQ(r, r2);
	}
	return (r);
}

static int __unused
try_stat(const char *path)
{
	struct stat st;
	return (stat(path, &st));
}

static int __unused
try_statat(int atfd, const char *path)
{
	int r, r2;
	struct stat st;
	r = fstatat(atfd, path, &st, 0);
	if (atfd == AT_FDCWD) {
		r2 = try_stat(path);
		ATF_CHECK_EQ(r, r2);
	}
	return (r);
}

static int __unused
try_access(const char *path, int mode)
{
	return (eaccess(path, mode));
}

static int __unused
try_accessat(int atfd, const char *path, int mode)
{
	int r, r2;
	r = faccessat(atfd, path, mode, AT_EACCESS);
	if (atfd == AT_FDCWD) {
		r2 = try_access(path, mode);
		ATF_CHECK_EQ(r, r2);
	}
	return (r);
}

static void __unused
check_accessat(int atfd, const char *path, const char *flags)
{
	bool is_root;
	bool e, i, r, w, x, d, p;
	e = i = r = w = x = d = p = false;
	for (const char *ptr = flags; *ptr; ptr++)
		switch (*ptr) {
		case 'e':         e = true; break; /* not hiding existence */
		case 'i':     i = e = true; break; /* stat()-able/chdir()-able */
		case 'r': r = i = e = true; break; /* readable/searchable */
		case 'w': w =     e = true; break; /* writable */
		case 'x': x =     e = true; break; /* executable */
		case 'd': d =         true; break; /* is a directory */
		case '+': p =         true; break; /* may have extra permissions */
		default: assert(0); break;
		}
	is_root = atfd == AT_FDCWD && strcmp(path, "/") == 0;

	warnx("%s: %s %s", __FUNCTION__, path, flags);

	int expected_errno = e ? EACCES : ENOENT;

	if (i)
		ATF_CHECK(try_statat(atfd, path) >= 0);
		/*
		 * TODO: Test chdir()?  It should be possible to chdir into
		 * inspectable directories but not to access their content.
		 */
	else if (!p)
		ATF_CHECK_ERRNO(expected_errno, try_statat(atfd, path) < 0);

	/*
	 * NOTE: The pledge(3)/unveil(3) library currently always maintain
	 * UPERM_SEARCH on the root directory.
	 */
	if (r) {
		ATF_CHECK(try_accessat(atfd, path, R_OK) >= 0);
		ATF_CHECK(try_openat(atfd, path, O_RDONLY) >= 0);
		if (d || is_root) {
			ATF_CHECK(try_accessat(atfd, path, X_OK) >= 0);
			ATF_CHECK(try_openat(atfd, path, O_SEARCH) >= 0);
			ATF_CHECK(try_openat(atfd, path, O_PATH) >= 0);
			ATF_CHECK(try_openat(atfd, path, O_SEARCH|O_DIRECTORY) >= 0);
			ATF_CHECK(try_openat(atfd, path, O_PATH|O_DIRECTORY) >= 0);
		}
	} else if (!p) {
		ATF_CHECK_ERRNO(expected_errno, try_accessat(atfd, path, R_OK) < 0);
		ATF_CHECK_ERRNO(expected_errno, try_openat(atfd, path, O_RDONLY) < 0);
		if (d && !is_root) {
			ATF_CHECK_ERRNO(expected_errno, try_accessat(atfd, path, X_OK) < 0);
			ATF_CHECK_ERRNO(expected_errno, try_openat(atfd, path, O_SEARCH) < 0);
			ATF_CHECK_ERRNO(expected_errno, try_openat(atfd, path, O_PATH) < 0);
			ATF_CHECK_ERRNO(expected_errno, try_openat(atfd, path, O_SEARCH|O_DIRECTORY) < 0);
			ATF_CHECK_ERRNO(expected_errno, try_openat(atfd, path, O_PATH|O_DIRECTORY) < 0);
		}
	}

	if (w) {
		ATF_CHECK(try_accessat(atfd, path, W_OK) >= 0);
		if (r)
			ATF_CHECK(try_accessat(atfd, path, R_OK|W_OK) >= 0);
		if (!d) {
			ATF_CHECK(try_openat(atfd, path, O_WRONLY) >= 0);
			if (r)
				ATF_CHECK(try_openat(atfd, path, O_RDWR) >= 0);
			ATF_CHECK(try_openat(atfd, path, O_WRONLY|O_CREAT) >= 0);
			if (r)
				ATF_CHECK(try_openat(atfd, path, O_RDWR|O_CREAT) >= 0);
		}
	} else if (!p) {
		ATF_CHECK_ERRNO(expected_errno, try_accessat(atfd, path, W_OK) < 0);
		ATF_CHECK_ERRNO(expected_errno, try_accessat(atfd, path, R_OK|W_OK) < 0);
		if (!d) {
			ATF_CHECK_ERRNO(expected_errno, try_openat(atfd, path, O_WRONLY) < 0);
			ATF_CHECK_ERRNO(expected_errno, try_openat(atfd, path, O_RDWR) < 0);
		}
	}

	if (!d) {
		if (x) {
			ATF_CHECK(try_accessat(atfd, path, X_OK) >= 0);
			ATF_CHECK(try_openat(atfd, path, O_EXEC) >= 0);
		} else if (!p) {
			ATF_CHECK_ERRNO(expected_errno, try_accessat(atfd, path, X_OK) < 0);
			ATF_CHECK_ERRNO(expected_errno, try_openat(atfd, path, O_EXEC) < 0);
		}
	}
}

static void __unused
check_access(const char *path, const char *flags)
{
	return (check_accessat(AT_FDCWD, path, flags));
}
