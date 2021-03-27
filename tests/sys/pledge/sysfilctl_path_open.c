#include <stdio.h>
#include <fcntl.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/sysfil.h>

#include "util.h"

static void
test_rpath(bool should_work)
{
	int fd;
	TRY((fd = open("/", O_RDONLY)), should_work);
	if (should_work)
		EXPECT(close(fd));
	TRY((fd = open("/dev", O_RDONLY)), should_work);
	if (should_work)
		EXPECT(close(fd));
	TRY((fd = open("/dev/zero", O_RDONLY)), should_work);
	if (should_work)
		EXPECT(close(fd));
	TRY((fd = open("/dev/null", O_RDONLY)), should_work);
	if (should_work)
		EXPECT(close(fd));
}

static void
test_wpath(bool should_work)
{
	int fd;
	TRY((fd = open("/dev/null", O_WRONLY)), should_work);
	if (should_work)
		EXPECT(close(fd));
}

static void
test_cpath(bool should_work)
{
	int fd;
	TRY((fd = open("/dev/null", O_WRONLY|O_CREAT)), should_work);
	if (should_work)
		EXPECT(close(fd));
}

static void
test_xpath(bool should_work)
{
	int fd;
	TRY((fd = open("/bin/sh", O_EXEC)), should_work);
	if (should_work)
		EXPECT(close(fd));
}

#define	DO_SYSFILCTL(...) \
({ \
	int _sysfils[] = { SYSFIL_ERROR, __VA_ARGS__ }; \
	int _sels[nitems(_sysfils)]; \
	for (unsigned _i = 0; _i < nitems(_sysfils); _i++) \
		_sels[_i] = _sysfils[_i] | SYSFILSEL_ON_SELF; \
	sysfilctl(SYSFILCTL_RESTRICT | SYSFILCTL_ON_SELF, nitems(_sels), _sels); \
})

int
main()
{
	EXPECT(DO_SYSFILCTL(SYSFIL_STDIO, SYSFIL_PATH, SYSFIL_RPATH, SYSFIL_WPATH, SYSFIL_CPATH, SYSFIL_EXEC));
	test_rpath(true);
	test_wpath(true);
	test_cpath(true);
	test_xpath(true);
	EXPECT(DO_SYSFILCTL(SYSFIL_STDIO, SYSFIL_PATH, SYSFIL_RPATH, SYSFIL_WPATH, SYSFIL_EXEC));
	test_rpath(true);
	test_wpath(true);
	test_cpath(false);
	test_xpath(true);
	EXPECT(DO_SYSFILCTL(SYSFIL_STDIO, SYSFIL_PATH, SYSFIL_RPATH, SYSFIL_EXEC));
	test_rpath(true);
	test_wpath(false);
	test_cpath(false);
	test_xpath(true);
	EXPECT(DO_SYSFILCTL(SYSFIL_STDIO, SYSFIL_PATH, SYSFIL_EXEC));
	test_rpath(false);
	test_wpath(false);
	test_cpath(false);
	test_xpath(true);
	EXPECT(DO_SYSFILCTL(SYSFIL_STDIO, SYSFIL_PATH));
	test_rpath(false);
	test_wpath(false);
	test_cpath(false);
	test_xpath(false);
}
