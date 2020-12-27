#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/unveil.h>

#include "util.h"

static int
unveil_path(int flags, const char *path, unveil_perms_t uperms)
{
	struct unveilctl ctl = { .atfd = AT_FDCWD, .path = path, .uperms = uperms };
	return (unveilctl(flags | UNVEILCTL_UNVEIL, &ctl));
}

static int
unveil_op(int flags, unveil_perms_t uperms)
{
	struct unveilctl ctl = { .atfd = -1, .path = NULL, .uperms = uperms };
	return (unveilctl(flags, &ctl));
}

int
main()
{
	int fl = UNVEILCTL_FOR_CURR | UNVEILCTL_FOR_SLOT1;
	int fd;
	EXPECT(unveil_op(UNVEILCTL_FOR_ALL | UNVEILCTL_SWEEP, -1));
	EXPECT(unveil_path(fl, "/etc", UPERM_INSPECT));
	EXPECT(unveil_path(fl, "/dev", UPERM_INSPECT | UPERM_RPATH | UPERM_WPATH));
	EXPECT(unveil_op(fl | UNVEILCTL_ACTIVATE | UNVEILCTL_FREEZE, 0));
	REJECT(fd = open("/", O_RDONLY));
	REJECT(fd = open("/etc", O_RDONLY));
	EXPECT(fd = open("/dev", O_RDONLY)); EXPECT(close(fd));
	EXPECT(fd = open("/dev/zero", O_RDONLY)); EXPECT(close(fd));
	EXPECT(fd = open("/dev/null", O_RDONLY)); EXPECT(close(fd));
	EXPECT(fd = open("/dev/null", O_WRONLY)); EXPECT(close(fd));
	REJECT(unveil_path(fl, "/var", UPERM_INSPECT));
	REJECT(fd = open("/var", O_RDONLY));
	EXPECT(unveil_path(fl, "/etc", UPERM_INSPECT | UPERM_RPATH));
	REJECT(fd = open("/", O_RDONLY));
	REJECT(fd = open("/etc", O_RDONLY));
	EXPECT(unveil_path(fl, "/dev", UPERM_INSPECT | UPERM_RPATH));
	EXPECT(unveil_op(fl | UNVEILCTL_FREEZE, 0));
	EXPECT(unveil_path(fl, "/dev", UPERM_INSPECT | UPERM_RPATH | UPERM_WPATH));
	REJECT(fd = open("/", O_RDONLY));
	REJECT(fd = open("/etc", O_RDONLY));
	EXPECT(fd = open("/dev", O_RDONLY)); EXPECT(close(fd));
	EXPECT(fd = open("/dev/zero", O_RDONLY)); EXPECT(close(fd));
	EXPECT(fd = open("/dev/null", O_RDONLY)); EXPECT(close(fd));
	REJECT(fd = open("/dev/null", O_WRONLY));
	EXPECT(unveil_path(fl, "/dev", UPERM_INSPECT));
	EXPECT(unveil_op(fl | UNVEILCTL_FREEZE, 0));
	EXPECT(unveil_path(fl, "/dev", UPERM_INSPECT | UPERM_RPATH));
	REJECT(fd = open("/", O_RDONLY));
	REJECT(fd = open("/etc", O_RDONLY));
	REJECT(fd = open("/dev", O_RDONLY));
	REJECT(fd = open("/dev/zero", O_RDONLY));
	REJECT(fd = open("/dev/null", O_RDONLY));
	REJECT(fd = open("/dev/null", O_WRONLY));
}
