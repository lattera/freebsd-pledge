#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <stdbool.h>
#include <signal.h>
#include <errno.h>

#include "util.h"

int
main()
{
	int r, status;
	int fds[2];
	char buf[1];
	pid_t pid;
	EXPECT(pledge("stdio error proc_child", ""));
	EXPECT(pipe(fds));
	pid = fork();
	if (pid < 0)
		err(1, "fork");
	if (pid == 0) {
		err_set_exit(_exit);
		REJECT(kill(getppid(), SIGHUP));
		EXPECT(close(fds[0]));
		EXPECT(close(fds[1]));
		while (true)
			sleep(60);
		_exit(0);
	}
	EXPECT(close(fds[1]));
	EXPECT(read(fds[0], buf, sizeof buf)); /* wait for child to try to kill */
	EXPECT(close(fds[0]));
	EXPECT(kill(pid, SIGTERM));
	EXPECT((r = waitpid(pid, &status, WEXITED)));
	if (r != pid || !WIFSIGNALED(status) || WTERMSIG(status) != SIGTERM)
		errx(1, "child process did not terminate with the right signal");
	return 0;
}
