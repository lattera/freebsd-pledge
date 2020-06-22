#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/unveil.h>

#include "util.h"

int
main()
{
	int fl = UNVEIL_FLAG_FOR_CURR | UNVEIL_FLAG_FOR_SLOT0;
	int fd;

	EXPECT(unveilctl(AT_FDCWD, "/etc", fl, UNVEIL_PERM_RPATH));
	EXPECT(unveilctl(AT_FDCWD, "/etc/rc.conf", fl, UNVEIL_PERM_RPATH));
	EXPECT(unveilctl(AT_FDCWD, "/etc/defaults", fl, UNVEIL_PERM_RPATH));
	EXPECT(unveilctl(-1, NULL, fl | UNVEIL_FLAG_SWEEP, -1));
	REJECT(fd = open("/", O_RDONLY));
	REJECT(fd = open("/etc", O_RDONLY));
	REJECT(fd = open("/etc/rc.conf", O_RDONLY));
	REJECT(fd = open("/etc/defaults", O_RDONLY));
	REJECT(fd = open("/etc/defaults/rc.conf", O_RDONLY));

	EXPECT(unveilctl(AT_FDCWD, "/etc", fl, UNVEIL_PERM_RPATH));
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
