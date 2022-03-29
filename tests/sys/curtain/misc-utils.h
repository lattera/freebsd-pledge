#include <unistd.h>
#include <sys/wait.h>
#include <atf-c.h>

static void __unused
fork_deleg()
{
	pid_t pid;
	int status;
	ATF_REQUIRE((pid = fork()) >= 0);
	if (pid) {
		ATF_REQUIRE(waitpid(pid, &status, WEXITED) == pid);
		ATF_REQUIRE(WIFEXITED(status));
		_exit(WEXITSTATUS(status));
	}
}

