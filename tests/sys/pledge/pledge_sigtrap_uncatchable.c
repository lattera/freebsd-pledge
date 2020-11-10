#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <signal.h>
#include <errno.h>

static void
ontrap(int sig)
{
	errx(1, "child caught signal #%d!", sig);
}

int
main()
{
	int r, status;
	pid_t pid;
	pid = fork();
	if (pid < 0)
		err(1, "fork");
	if (pid == 0) {
		sig_t osig;
		sigset_t oset, nset;
		err_set_exit(_exit);
		osig = signal(SIGTRAP, ontrap);
		if (osig == SIG_ERR)
			warn("signal");
		r = pledge("stdio", "");
		if (r < 0)
			err(1, "pledge");
#if 0
		osig = signal(SIGTRAP, ontrap);
		if (osig == SIG_ERR && errno != EINVAL)
			warn("signal");
#endif
		sigemptyset(&nset);
		sigaddset(&nset, SIGTRAP);
		r = sigprocmask(SIG_BLOCK, &nset, &oset);
		if (r < 0)
			warn("sigprocmask");
		r = kill(getppid(), SIGTERM);
		if (r < 0)
			err(1, "kill");
		_exit(0);
	}
	r = waitpid(pid, &status, WEXITED);
	if (r < 0)
		err(1, "waitpid");
	if (r != pid || !WIFSIGNALED(status) || WTERMSIG(status) != SIGTRAP)
		errx(1, "child process did not terminate with SIGTRAP");
	return 0;
}
