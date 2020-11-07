#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/unveil.h>

#include "util.h"

int
main()
{
	int fl = UNVEILCTL_FOR_CURR | UNVEILCTL_FOR_SLOT1;
	int fd;
	EXPECT(unveilctl(-1, NULL, UNVEILCTL_FOR_ALL | UNVEILCTL_SWEEP, -1));
	EXPECT(unveilctl(AT_FDCWD, "/etc", fl, UPERM_INSPECT));
	EXPECT(unveilctl(AT_FDCWD, "/dev", fl, UPERM_INSPECT | UPERM_RPATH | UPERM_WPATH));
	EXPECT(unveilctl(-1, NULL, fl | UNVEILCTL_ACTIVATE | UNVEILCTL_FREEZE, 0));
	REJECT(fd = open("/", O_RDONLY));
	REJECT(fd = open("/etc", O_RDONLY));
	EXPECT(fd = open("/dev", O_RDONLY)); EXPECT(close(fd));
	EXPECT(fd = open("/dev/zero", O_RDONLY)); EXPECT(close(fd));
	EXPECT(fd = open("/dev/null", O_RDONLY)); EXPECT(close(fd));
	EXPECT(fd = open("/dev/null", O_WRONLY)); EXPECT(close(fd));
	REJECT(unveilctl(AT_FDCWD, "/var", fl, UPERM_INSPECT));
	REJECT(fd = open("/var", O_RDONLY));
	EXPECT(unveilctl(AT_FDCWD, "/etc", fl, UPERM_INSPECT | UPERM_RPATH));
	REJECT(fd = open("/", O_RDONLY));
	REJECT(fd = open("/etc", O_RDONLY));
	EXPECT(unveilctl(AT_FDCWD, "/dev", fl, UPERM_INSPECT | UPERM_RPATH));
	EXPECT(unveilctl(-1, NULL, fl | UNVEILCTL_FREEZE, 0));
	EXPECT(unveilctl(AT_FDCWD, "/dev", fl, UPERM_INSPECT | UPERM_RPATH | UPERM_WPATH));
	REJECT(fd = open("/", O_RDONLY));
	REJECT(fd = open("/etc", O_RDONLY));
	EXPECT(fd = open("/dev", O_RDONLY)); EXPECT(close(fd));
	EXPECT(fd = open("/dev/zero", O_RDONLY)); EXPECT(close(fd));
	EXPECT(fd = open("/dev/null", O_RDONLY)); EXPECT(close(fd));
	REJECT(fd = open("/dev/null", O_WRONLY));
	EXPECT(unveilctl(AT_FDCWD, "/dev", fl, UPERM_INSPECT));
	EXPECT(unveilctl(-1, NULL, fl | UNVEILCTL_FREEZE, 0));
	EXPECT(unveilctl(AT_FDCWD, "/dev", fl, UPERM_INSPECT | UPERM_RPATH));
	REJECT(fd = open("/", O_RDONLY));
	REJECT(fd = open("/etc", O_RDONLY));
	REJECT(fd = open("/dev", O_RDONLY));
	REJECT(fd = open("/dev/zero", O_RDONLY));
	REJECT(fd = open("/dev/null", O_RDONLY));
	REJECT(fd = open("/dev/null", O_WRONLY));
}
