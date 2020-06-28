#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "util.h"

int
main()
{
	int fd;
	EXPECT(pledge("stdio rpath", NULL));
	EXPECT(unveil("/etc", "r"));
	REJECT(open("/tmp", O_RDONLY));
	EXPECT(fd = open("/dev/null", O_RDONLY));
	EXPECT(close(fd));
	return (0);
}
