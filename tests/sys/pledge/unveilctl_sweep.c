#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/unveil.h>

#include "util.h"

int
main()
{
	int fd;

	EXPECT(unveilctl(AT_FDCWD, "/etc", 0, UNVEIL_PERM_RPATH, 0));
	EXPECT(unveilctl(AT_FDCWD, "/etc/rc.conf", 0, UNVEIL_PERM_RPATH, 0));
	EXPECT(unveilctl(AT_FDCWD, "/etc/defaults", 0, UNVEIL_PERM_RPATH, 0));
	EXPECT(unveilctl(-1, NULL, UNVEIL_FLAG_SWEEP, -1, -1));
	REJECT(fd = open("/", O_RDONLY));
	REJECT(fd = open("/etc", O_RDONLY));
	REJECT(fd = open("/etc/rc.conf", O_RDONLY));
	REJECT(fd = open("/etc/defaults", O_RDONLY));
	REJECT(fd = open("/etc/defaults/rc.conf", O_RDONLY));

	EXPECT(unveilctl(AT_FDCWD, "/etc", 0, UNVEIL_PERM_RPATH, 0));
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
