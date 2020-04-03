#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "util.h"

int
main()
{
	int fd;
	EXPECT(unveil("/dev/null", "rw"));
	EXPECT(unveil("/dev/zero", "r"));
	EXPECT(unveil(NULL, NULL));
	REJECT(unveil("/", "r"));
	EXPECT(fd = open("/dev/null", O_RDONLY));
	EXPECT(close(fd));
	EXPECT(fd = open("/dev/null", O_WRONLY));
	EXPECT(close(fd));
	EXPECT(fd = open("/dev/null", O_RDWR));
	EXPECT(close(fd));
	EXPECT(fd = open("/dev/zero", O_RDONLY));
	EXPECT(close(fd));
	REJECT(fd = open("/dev/zero", O_WRONLY));
	REJECT(fd = open("/dev/zero", O_RDWR));
	REJECT(open("/dev/random", O_RDONLY));
	return (0);
}
