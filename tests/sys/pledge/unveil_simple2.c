#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "util.h"

int
main()
{
	int fd;
	EXPECT(unveil("/etc", "r"));
	EXPECT(unveil("/var", "r"));
	EXPECT(unveil(NULL, NULL));
	EXPECT(fd = open("/etc", O_DIRECTORY|O_RDONLY)); EXPECT(close(fd));
	EXPECT(fd = open("/var", O_DIRECTORY|O_RDONLY)); EXPECT(close(fd));
	REJECT(open("/", O_DIRECTORY|O_RDONLY));
	return (0);
}
