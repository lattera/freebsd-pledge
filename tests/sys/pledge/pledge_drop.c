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
	int fd;
	EXPECT(pledge("error stdio getpw", ""));
	EXPECT(fd = open("/etc/localtime", O_RDONLY));
	EXPECT(close(fd));
	EXPECT(fd = open("/dev/null", O_RDONLY));
	EXPECT(close(fd));
	EXPECT(fd = open("/etc/pwd.db", O_RDONLY));
	EXPECT(close(fd));
	EXPECT(pledge("error stdio", ""));
	EXPECT(fd = open("/etc/localtime", O_RDONLY));
	EXPECT(close(fd));
	EXPECT(fd = open("/dev/null", O_RDONLY));
	EXPECT(close(fd));
	REJECT(open("/etc/pwd.db", O_RDONLY));
	return 0;
}
