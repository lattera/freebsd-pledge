#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "util.h"

int
main()
{
	int fd;
	EXPECT(unveil("/etc", "r"));
	EXPECT(unveil(NULL, NULL));

	REJECT(open("/COPYRIGHT", O_RDONLY));

	EXPECT(fd = open("/etc/rc.conf", O_RDONLY));
	EXPECT(close(fd));
	EXPECT(fd = open("/etc/defaults/rc.conf", O_RDONLY));
	EXPECT(close(fd));

	EXPECT(chdir("/etc"));
	EXPECT(fd = open("rc.conf", O_RDONLY));
	EXPECT(close(fd));
	EXPECT(fd = open("./rc.conf", O_RDONLY));
	EXPECT(close(fd));
	EXPECT(fd = open("defaults/rc.conf", O_RDONLY));
	EXPECT(close(fd));
	EXPECT(fd = open("./defaults/rc.conf", O_RDONLY));
	EXPECT(close(fd));

	EXPECT(chdir("defaults"));
	EXPECT(fd = open("rc.conf", O_RDONLY));
	EXPECT(close(fd));
	EXPECT(fd = open("./rc.conf", O_RDONLY));
	EXPECT(close(fd));
	EXPECT(fd = open("../rc.conf", O_RDONLY));
	EXPECT(close(fd));
	EXPECT(fd = open("./../rc.conf", O_RDONLY));
	EXPECT(close(fd));

	EXPECT(chdir("/etc/defaults"));
	EXPECT(fd = open("rc.conf", O_RDONLY));
	EXPECT(close(fd));
	EXPECT(fd = open("./rc.conf", O_RDONLY));
	EXPECT(close(fd));
	EXPECT(fd = open("../rc.conf", O_RDONLY));
	EXPECT(close(fd));
	EXPECT(fd = open("./../rc.conf", O_RDONLY));
	EXPECT(close(fd));

	return (0);
}
