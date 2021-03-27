#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <signal.h>

int
main()
{
	int r, status;
	pid_t pid;
	pid = fork();
	if (pid < 0)
		err(1, "fork");
	if (pid == 0) {
		err_set_exit(_exit);
		r = pledge("stdio", "");
		if (r < 0)
			err(1, "pledge");
		r = kill(getppid(), SIGTERM);
		if (r < 0)
			err(1, "kill");
		_exit(0);
	}
	r = waitpid(pid, &status, WEXITED);
	if (r < 0)
		err(1, "waitpid");
	if (r != pid || !WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL)
		errx(1, "child process did not terminate with SIGKILL");
	return 0;
}
