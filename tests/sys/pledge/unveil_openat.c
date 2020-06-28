#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "util.h"

int
main()
{
	int fd1, fd2, fd;

	EXPECT(unveil("/etc", "rx")); /* XXX 'x' */
	EXPECT(unveil(NULL, NULL));

	EXPECT(fd1 = open("/etc", O_SEARCH));
	EXPECT(fd2 = open("/etc/defaults", O_SEARCH));

	EXPECT(fd = openat(fd1, ".", O_SEARCH));
	EXPECT(close(fd));
	EXPECT(fd = openat(fd1, "defaults", O_SEARCH));
	EXPECT(close(fd));
	EXPECT(fd = openat(fd2, ".", O_SEARCH));
	EXPECT(close(fd));

	EXPECT(fd = openat(fd1, "rc.conf", O_RDONLY));
	EXPECT(close(fd));
	EXPECT(fd = openat(fd1, "defaults/rc.conf", O_RDONLY));
	EXPECT(close(fd));
	EXPECT(fd = openat(fd2, "rc.conf", O_RDONLY));
	EXPECT(close(fd));

	return (0);
}
