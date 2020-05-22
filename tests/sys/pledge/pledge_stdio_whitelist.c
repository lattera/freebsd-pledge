#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <fcntl.h>

#include "util.h"

int
main()
{
	const char *p;
	int fd;
	EXPECT(pledge("error stdio", ""));
	p = "/etc/localtime";
	EXPECT(access(p, R_OK));
	EXPECT((fd = open(p, O_RDONLY)));
	if (fd >= 0)
		EXPECT(close(fd));
	p = "/dev/null";
	EXPECT(access(p, R_OK));
	EXPECT(access(p, W_OK));
	EXPECT(access(p, R_OK|W_OK));
	EXPECT((fd = open(p, O_RDONLY)));
	EXPECT(close(fd));
	EXPECT((fd = open(p, O_WRONLY)));
	EXPECT(close(fd));
	EXPECT((fd = open(p, O_RDWR)));
	EXPECT(close(fd));
	REJECT(open("/etc/pwd.db", O_RDONLY));
	REJECT(open("/etc/pwd.db", O_WRONLY));
	REJECT(open("/etc/pwd.db", O_RDWR));
	REJECT(open("/dev/tty", O_RDONLY));
	REJECT(open("/dev/tty", O_WRONLY));
	REJECT(open("/dev/tty", O_RDWR));
	return 0;
}
