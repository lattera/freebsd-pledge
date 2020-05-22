#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "util.h"

int
main()
{
	int fd;
	EXPECT(unveil("/dev/zero", "r"));
	EXPECT(unveil("/dev/null", "rw"));
	EXPECT(unveil(NULL, NULL));
	/* Our unveil() is allowed even after unveil(NULL, NULL), but it can
	 * only reduce permissions (and it returns success even when attempting
	 * to elevate permissions). */
	EXPECT(unveil("/dev/zero", "rw"));
	EXPECT(unveil("/dev/random", "r"));
	EXPECT(fd = open("/dev/null", O_RDONLY));
	EXPECT(close(fd));
	EXPECT(fd = open("/dev/null", O_WRONLY));
	EXPECT(close(fd));
	EXPECT(fd = open("/dev/null", O_RDWR));
	EXPECT(close(fd));
	EXPECT(fd = open("/dev/zero", O_RDONLY));
	EXPECT(close(fd));
	REJECT(open("/dev/zero", O_WRONLY));
	REJECT(open("/dev/zero", O_RDWR));
	REJECT(open("/dev/random", O_RDONLY));
	REJECT(open("/dev/random", O_WRONLY));
	REJECT(open("/dev/random", O_RDWR));
	return (0);
}
