#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "util.h"

int
main()
{
	static const char *p = "/dev/zero";
	int fd;
	EXPECT(pledge("stdio rpath wpath unveil", NULL));
	EXPECT(unveil(p, "r"));
	EXPECT(fd = open(p, O_RDONLY)); EXPECT(close(fd));
	REJECT(fd = open(p, O_WRONLY));
	EXPECT(unveil(p, "rw"));
	EXPECT(fd = open(p, O_RDONLY)); EXPECT(close(fd));
	EXPECT(fd = open(p, O_WRONLY)); EXPECT(close(fd));
	EXPECT(unveil(p, "r"));
	EXPECT(fd = open(p, O_RDONLY)); EXPECT(close(fd));
	REJECT(fd = open(p, O_WRONLY));

	EXPECT(pledge("stdio rpath wpath unveil", NULL));
	EXPECT(fd = open(p, O_RDONLY)); EXPECT(close(fd));
	REJECT(fd = open(p, O_WRONLY));
	EXPECT(unveil(p, "r"));
	EXPECT(fd = open(p, O_RDONLY)); EXPECT(close(fd));
	REJECT(fd = open(p, O_WRONLY));
	EXPECT(unveil(p, "rw"));
	EXPECT(fd = open(p, O_RDONLY)); EXPECT(close(fd));
	EXPECT(fd = open(p, O_WRONLY)); EXPECT(close(fd));

	EXPECT(pledge("stdio rpath unveil", NULL));
	EXPECT(fd = open(p, O_RDONLY)); EXPECT(close(fd));
	REJECT(fd = open(p, O_WRONLY));
	EXPECT(unveil(p, ""));
	REJECT(fd = open(p, O_RDONLY));
	REJECT(fd = open(p, O_WRONLY));
	EXPECT(unveil(p, "r"));
	EXPECT(fd = open(p, O_RDONLY)); EXPECT(close(fd));
	REJECT(fd = open(p, O_WRONLY));
	EXPECT(unveil(p, ""));
	REJECT(fd = open(p, O_RDONLY));
	REJECT(fd = open(p, O_WRONLY));

	EXPECT(pledge("stdio rpath", NULL));
	REJECT(fd = open(p, O_RDONLY));
	REJECT(fd = open(p, O_WRONLY));
	REJECT(unveil(p, "r"));
	REJECT(fd = open(p, O_RDONLY));
	REJECT(fd = open(p, O_WRONLY));

	return (0);
}
