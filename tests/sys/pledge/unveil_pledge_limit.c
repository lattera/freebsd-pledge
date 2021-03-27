#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <pledge.h>

#include "util.h"

int
main()
{
	int fd;
	EXPECT(pledge("stdio rpath wpath", NULL));
	EXPECT(unveil("/dev/zero", "rw"));
	EXPECT(unveil(NULL, NULL));
	EXPECT(fd = open("/dev/zero", O_RDONLY));
	EXPECT(close(fd));
	EXPECT(fd = open("/dev/zero", O_WRONLY));
	EXPECT(close(fd));
	EXPECT(fd = open("/dev/zero", O_RDWR));
	EXPECT(close(fd));
	EXPECT(pledge("stdio rpath", NULL));
	EXPECT(fd = open("/dev/zero", O_RDONLY));
	EXPECT(close(fd));
	REJECT(fd = open("/dev/zero", O_WRONLY));
	REJECT(fd = open("/dev/zero", O_RDWR));
	return (0);
}
