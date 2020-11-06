#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/unveil.h>

#include "util.h"

int
main()
{
	int fl = UNVEIL_FLAG_FOR_CURR | UNVEIL_FLAG_FOR_SLOT1;
	int fd;
	EXPECT(unveilctl(-1, NULL, UNVEIL_FLAG_FOR_ALL | UNVEIL_FLAG_SWEEP, -1));
	EXPECT(unveilctl(AT_FDCWD, "/etc", fl, UNVEIL_PERM_INSPECT));
	EXPECT(unveilctl(AT_FDCWD, "/dev", fl, UNVEIL_PERM_INSPECT | UNVEIL_PERM_RPATH | UNVEIL_PERM_WPATH));
	EXPECT(unveilctl(-1, NULL, fl | UNVEIL_FLAG_ACTIVATE | UNVEIL_FLAG_FREEZE, 0));
	REJECT(fd = open("/", O_RDONLY));
	REJECT(fd = open("/etc", O_RDONLY));
	EXPECT(fd = open("/dev", O_RDONLY)); EXPECT(close(fd));
	EXPECT(fd = open("/dev/zero", O_RDONLY)); EXPECT(close(fd));
	EXPECT(fd = open("/dev/null", O_RDONLY)); EXPECT(close(fd));
	EXPECT(fd = open("/dev/null", O_WRONLY)); EXPECT(close(fd));
	REJECT(unveilctl(AT_FDCWD, "/var", fl, UNVEIL_PERM_INSPECT));
	REJECT(fd = open("/var", O_RDONLY));
	EXPECT(unveilctl(AT_FDCWD, "/etc", fl, UNVEIL_PERM_INSPECT | UNVEIL_PERM_RPATH));
	REJECT(fd = open("/", O_RDONLY));
	REJECT(fd = open("/etc", O_RDONLY));
	EXPECT(unveilctl(AT_FDCWD, "/dev", fl, UNVEIL_PERM_INSPECT | UNVEIL_PERM_RPATH));
	EXPECT(unveilctl(-1, NULL, fl | UNVEIL_FLAG_FREEZE, 0));
	EXPECT(unveilctl(AT_FDCWD, "/dev", fl, UNVEIL_PERM_INSPECT | UNVEIL_PERM_RPATH | UNVEIL_PERM_WPATH));
	REJECT(fd = open("/", O_RDONLY));
	REJECT(fd = open("/etc", O_RDONLY));
	EXPECT(fd = open("/dev", O_RDONLY)); EXPECT(close(fd));
	EXPECT(fd = open("/dev/zero", O_RDONLY)); EXPECT(close(fd));
	EXPECT(fd = open("/dev/null", O_RDONLY)); EXPECT(close(fd));
	REJECT(fd = open("/dev/null", O_WRONLY));
	EXPECT(unveilctl(AT_FDCWD, "/dev", fl, UNVEIL_PERM_INSPECT));
	EXPECT(unveilctl(-1, NULL, fl | UNVEIL_FLAG_FREEZE, 0));
	EXPECT(unveilctl(AT_FDCWD, "/dev", fl, UNVEIL_PERM_INSPECT | UNVEIL_PERM_RPATH));
	REJECT(fd = open("/", O_RDONLY));
	REJECT(fd = open("/etc", O_RDONLY));
	REJECT(fd = open("/dev", O_RDONLY));
	REJECT(fd = open("/dev/zero", O_RDONLY));
	REJECT(fd = open("/dev/null", O_RDONLY));
	REJECT(fd = open("/dev/null", O_WRONLY));
}
