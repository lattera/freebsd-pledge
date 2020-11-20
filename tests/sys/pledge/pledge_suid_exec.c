#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <errno.h>
#include <sysexits.h>
#include <string.h>
#include <libgen.h>

#include "util.h"

const char *suid_check_path;

static void
setup_no_pledge()
{
}

static void
setup_curr_pledge()
{
	EXPECT(pledge("stdio exec", NULL));
}

static void
setup_exec_pledge()
{
	EXPECT(pledge(NULL, "stdio rpath"));
}

static void
setup_curr_exec_pledge()
{
	EXPECT(pledge("stdio exec", "stdio rpath"));
}

static void
setup_unveil_unfrozen()
{
	EXPECT(unveil("/", "rx"));
	EXPECT(unveil("/etc", ""));
}

static void
setup_unveil_frozen()
{
	EXPECT(unveil("/", "rx"));
	EXPECT(unveil("/etc", ""));
	EXPECT(unveil(NULL, NULL));
}

static void
run(const char *name, int expected_exit, void (*setup)(void))
{
	pid_t pid;
	int status;
	pid = fork();
	if (pid < 0)
		err(1, "fork");
	if (pid == 0) {
		err_set_exit(_exit);
		setup();
		execl(suid_check_path, suid_check_path, (char *)NULL);
		err(1, "%s", suid_check_path);
	}
	EXPECT(waitpid(pid, &status, WEXITED));
	if (WIFSIGNALED(status))
		errx(1, "%s: child unexpected signal", name);
	if (WEXITSTATUS(status) != expected_exit)
		errx(1, "%s: child exited with %d instead of expected %d",
		    name, WEXITSTATUS(status), expected_exit);
}
#define	RUN(e, f) run(#f, e, f)

int
main(int argc, char **argv)
{
	char *s = "/suid-check", *p, *q;
	p = malloc(strlen(argv[0]) + strlen(s) + 1);
	if (!p)
		err(EX_TEMPFAIL, "malloc");
	strcpy(p, argv[0]);
	q = dirname(p);
	if (!q)
		err(EX_TEMPFAIL, "dirname");
	if (q != p)
		strcpy(p, q);
	strcat(p, s);
	suid_check_path = p;

	if (geteuid() == 0)
		errx(0, "skipping tests when run as root");

	RUN(0, setup_no_pledge);
	RUN(0, setup_curr_pledge);
	RUN(1, setup_exec_pledge);
	RUN(1, setup_curr_exec_pledge);
	RUN(3, setup_unveil_unfrozen);
	RUN(3, setup_unveil_frozen);
	return (0);
}
