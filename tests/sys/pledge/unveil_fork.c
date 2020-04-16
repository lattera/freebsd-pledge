#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

#include "util.h"

int
main()
{
	int fd;
	pid_t pid;
	EXPECT(unveil("/dev/null", "rw"));
	EXPECT(unveil("/dev/zero", "r"));
	EXPECT((pid = fork()));
	err_set_exit(_exit);
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
	if (pid) {
		int r, status;
		r = waitpid(pid, &status, WEXITED);
		if (r < 0)
			err(1, "waitpid");
		if (r != pid || status)
			errx(1, "child process failed: status %d", status);
	}
	_exit(0);
}
