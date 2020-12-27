#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
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

	EXPECT(unveil_path(fl, "/etc", UPERM_RPATH));
	EXPECT(unveil_path(fl, "/etc/rc.conf", UPERM_RPATH));
	EXPECT(unveil_path(fl, "/etc/defaults", UPERM_RPATH));
	EXPECT(unveil_op(UNVEILCTL_FOR_ALL | UNVEILCTL_SWEEP | UNVEILCTL_ACTIVATE, -1));
	REJECT(fd = open("/", O_RDONLY));
	REJECT(fd = open("/COPYRIGHT", O_RDONLY));
	REJECT(fd = open("/etc", O_RDONLY));
	REJECT(fd = open("/etc/rc.conf", O_RDONLY));
	REJECT(fd = open("/etc/defaults", O_RDONLY));
	REJECT(fd = open("/etc/defaults/rc.conf", O_RDONLY));

	EXPECT(unveil_path(fl, "/etc", UPERM_RPATH));
	REJECT(fd = open("/", O_RDONLY));
	REJECT(fd = open("/COPYRIGHT", O_RDONLY));
	EXPECT(fd = open("/etc", O_RDONLY));
	EXPECT(close(fd));
	EXPECT(fd = open("/etc/rc.conf", O_RDONLY));
	EXPECT(close(fd));
	EXPECT(fd = open("/etc/defaults", O_RDONLY));
	EXPECT(close(fd));
	EXPECT(fd = open("/etc/defaults/rc.conf", O_RDONLY));
	EXPECT(close(fd));

	return (0);
}
