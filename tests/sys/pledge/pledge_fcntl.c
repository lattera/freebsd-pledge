#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pledge.h>

#define EXPECT(expr) do { \
	if ((expr) < 0) \
		err(1, "%s", #expr); \
} while (0)

#define REJECT(expr) do { \
	if (!((expr) < 0)) \
		errx(1, "%s: shouldn't have worked!", #expr); \
} while (0)


int
main()
{
	int fds[2], fd;
	EXPECT(pledge("error stdio proc", NULL));
	EXPECT(pipe(fds));
	fd = fds[0];
	EXPECT(fcntl(fd, F_SETOWN, getpid()));
	EXPECT(pledge("error stdio", NULL));
	REJECT(fcntl(fd, F_SETOWN, getpid()));
	EXPECT((fd = fcntl(fd, F_DUPFD, 0)));
	EXPECT(close(fd));
	EXPECT(close(fds[0]));
	EXPECT(close(fds[1]));
	return 0;
}
