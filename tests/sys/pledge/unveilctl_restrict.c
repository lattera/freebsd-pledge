#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/unveil.h>

#include "util.h"

int
main()
{
	int fd;
	EXPECT(unveilctl(AT_FDCWD, "/dev", 0, UNVEIL_PERM_RPATH | UNVEIL_PERM_WPATH, 0));
	EXPECT(unveilctl(-1, NULL, UNVEIL_FLAG_RESTRICT, 0, 0));
	REJECT(fd = open("/", O_RDONLY));
	REJECT(fd = open("/etc", O_RDONLY));
	EXPECT(fd = open("/dev", O_RDONLY)); EXPECT(close(fd));
	EXPECT(fd = open("/dev/zero", O_RDONLY)); EXPECT(close(fd));
	EXPECT(fd = open("/dev/null", O_RDONLY)); EXPECT(close(fd));
	EXPECT(fd = open("/dev/null", O_WRONLY)); EXPECT(close(fd));
	EXPECT(unveilctl(AT_FDCWD, "/etc", 0, UNVEIL_PERM_RPATH, 0));
	REJECT(fd = open("/", O_RDONLY));
	REJECT(fd = open("/etc", O_RDONLY));
	EXPECT(unveilctl(AT_FDCWD, "/dev", 0, UNVEIL_PERM_RPATH, 0));
	EXPECT(unveilctl(-1, NULL, UNVEIL_FLAG_RESTRICT, 0, 0));
	EXPECT(unveilctl(AT_FDCWD, "/dev", 0, UNVEIL_PERM_RPATH | UNVEIL_PERM_WPATH, 0));
	REJECT(fd = open("/", O_RDONLY));
	REJECT(fd = open("/etc", O_RDONLY));
	EXPECT(fd = open("/dev", O_RDONLY)); EXPECT(close(fd));
	EXPECT(fd = open("/dev/zero", O_RDONLY)); EXPECT(close(fd));
	EXPECT(fd = open("/dev/null", O_RDONLY)); EXPECT(close(fd));
	REJECT(fd = open("/dev/null", O_WRONLY));
	EXPECT(unveilctl(AT_FDCWD, "/dev", 0, UNVEIL_PERM_NONE, 0));
	EXPECT(unveilctl(-1, NULL, UNVEIL_FLAG_RESTRICT, 0, 0));
	EXPECT(unveilctl(AT_FDCWD, "/dev", 0, UNVEIL_PERM_RPATH, 0));
	REJECT(fd = open("/", O_RDONLY));
	REJECT(fd = open("/etc", O_RDONLY));
	REJECT(fd = open("/dev", O_RDONLY));
	REJECT(fd = open("/dev/zero", O_RDONLY));
	REJECT(fd = open("/dev/null", O_RDONLY));
	REJECT(fd = open("/dev/null", O_WRONLY));
}
