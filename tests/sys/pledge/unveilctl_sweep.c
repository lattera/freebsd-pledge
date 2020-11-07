#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/unveil.h>

#include "util.h"

int
main()
{
	int fl = UNVEILCTL_FOR_CURR | UNVEILCTL_FOR_SLOT1;
	int fd;

	EXPECT(unveilctl(AT_FDCWD, "/etc", fl, UPERM_RPATH));
	EXPECT(unveilctl(AT_FDCWD, "/etc/rc.conf", fl, UPERM_RPATH));
	EXPECT(unveilctl(AT_FDCWD, "/etc/defaults", fl, UPERM_RPATH));
	EXPECT(unveilctl(-1, NULL, UNVEILCTL_FOR_ALL | UNVEILCTL_SWEEP | UNVEILCTL_ACTIVATE, -1));
	REJECT(fd = open("/", O_RDONLY));
	REJECT(fd = open("/COPYRIGHT", O_RDONLY));
	REJECT(fd = open("/etc", O_RDONLY));
	REJECT(fd = open("/etc/rc.conf", O_RDONLY));
	REJECT(fd = open("/etc/defaults", O_RDONLY));
	REJECT(fd = open("/etc/defaults/rc.conf", O_RDONLY));

	EXPECT(unveilctl(AT_FDCWD, "/etc", fl, UPERM_RPATH));
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
