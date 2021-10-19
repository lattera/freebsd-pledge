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
	r = creat(path, S_IRWXU | S_IRWXG | S_IRWXO);
	if (r >= 0)
		close(r);
	return (r);
}

static int __unused
try_mkdir(const char *path)
{
	return (mkdir(path, S_IRWXU | S_IRWXG | S_IRWXO));
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
	r = openat(atfd, path ? path : "", (path ? 0 : O_EMPTY_PATH) | flags);
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
	r = fstatat(atfd, path ? path : "", &st, path ? 0 : AT_EMPTY_PATH);
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
	r = faccessat(atfd, path ? path : "", mode,
	    (path ? 0 : AT_EMPTY_PATH) | AT_EACCESS);
	if (atfd == AT_FDCWD) {
		r2 = try_access(path, mode);
		ATF_CHECK_EQ(r, r2);
	}
	return (r);
}

static void __unused
check_accessat(int atfd, const char *path, const char *flags)
{
	bool e, /* not hiding existence */
	     s, /* searchable (for directories) */
	     i, /* stat()-able */
	     r, /* readable */
	     w, /* writable */
	     x, /* executable (for regular files) */
	     d, /* is a directory */
	     p, /* may have extra permissions */
	     a; /* fail with EPERM instead of EACCES */
	e = s = i = r = w = x = d = p = a = false;
	for (const char *ptr = flags; *ptr; ptr++)
		switch (*ptr) {
		case 's':         s     = true; break;
		case 'e':         s = e = true; break;
		case 'i':     i = s = e = true; break;
		case 'r': r = i = s = e = true; break;
		case 'w': w =     s = e = true; break;
		case 'x': x =     s = e = true; break;
		case 'd': d =             true; break;
		case '+': p =             true; break;
		case '*': a =             true; break;
		default: assert(0); break;
		}
	if (atfd == AT_FDCWD && path && strcmp(path, "/") == 0)
		/*
		 * This unveil() implementation always give some limited access
		 * to the root directory (see comments in libcurtain), but the
		 * deny errno is still ENOENT as if the path was not unveiled.
		 */
		s = true;
	if (a)
		/*
		 * The sysfil-level restrictions only allow chdir()/O_SEARCH
		 * when reading is allowed.
		 */
		s = i;

	warnx("%s: %i:\"%s\" %s", __FUNCTION__, atfd, path ? path : "", flags);

	int expected_errno = a ? EPERM : e ? EACCES : ENOENT;

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
	if (d && s) {
		ATF_CHECK(try_accessat(atfd, path, X_OK) >= 0);
		ATF_CHECK(try_openat(atfd, path, O_SEARCH) >= 0);
		ATF_CHECK(try_openat(atfd, path, O_PATH|O_EXEC) >= 0);
		ATF_CHECK(try_openat(atfd, path, O_SEARCH|O_DIRECTORY) >= 0);
		ATF_CHECK(try_openat(atfd, path, O_PATH|O_EXEC|O_DIRECTORY) >= 0);
	} else if (d && !s && !p) {
		ATF_CHECK_ERRNO(expected_errno, try_accessat(atfd, path, X_OK) < 0);
		ATF_CHECK_ERRNO(expected_errno, try_openat(atfd, path, O_SEARCH) < 0);
		ATF_CHECK_ERRNO(expected_errno, try_openat(atfd, path, O_PATH|O_EXEC) < 0);
		ATF_CHECK_ERRNO(expected_errno, try_openat(atfd, path, O_SEARCH|O_DIRECTORY) < 0);
		ATF_CHECK_ERRNO(expected_errno, try_openat(atfd, path, O_PATH|O_EXEC|O_DIRECTORY) < 0);
	}

	if (r) {
		ATF_CHECK(try_accessat(atfd, path, R_OK) >= 0);
		ATF_CHECK(try_openat(atfd, path, O_RDONLY) >= 0);
	} else if (!p) {
		ATF_CHECK_ERRNO(expected_errno, try_accessat(atfd, path, R_OK) < 0);
		ATF_CHECK_ERRNO(expected_errno, try_openat(atfd, path, O_RDONLY) < 0);
	}

	if (w) {
		ATF_CHECK(try_accessat(atfd, path, W_OK) >= 0);
		if (r)
			ATF_CHECK(try_accessat(atfd, path, R_OK|W_OK) >= 0);
		if (!d) {
			ATF_CHECK(try_openat(atfd, path, O_WRONLY) >= 0);
			if (r)
				ATF_CHECK(try_openat(atfd, path, O_RDWR) >= 0);
			if (path) {
				ATF_CHECK(try_openat(atfd, path, O_WRONLY|O_CREAT) >= 0);
				if (r)
					ATF_CHECK(try_openat(atfd, path, O_RDWR|O_CREAT) >= 0);
			}
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

	if (e && path) {
		int fd;
		ATF_CHECK((fd = openat(atfd, path, O_PATH)) >= 0);
		if (fd >= 0) {
			check_accessat(fd, NULL, flags);
			close(fd);
		}
	}
}

static void __unused
check_access(const char *path, const char *flags)
{
	return (check_accessat(AT_FDCWD, path, flags));
}
