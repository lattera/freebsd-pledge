#include <curtain.h>
#include <err.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <unistd.h>

#include "common.h"

static const char dbus_cmd_name[] = "dbus-daemon";
static char *session_dbus_socket = NULL;
static pid_t session_dbus_pid = -1;

static void
cleanup_dbus(void)
{
	int r;
	if (session_dbus_pid > 0) {
		int status;
		r = kill(session_dbus_pid, SIGTERM);
		if (r < 0)
			warn("kill");
		r = waitpid(session_dbus_pid, &status, 0);
		session_dbus_pid = -1;
		if (r < 0) {
			warn("waitpid");
		} else if (!(WIFEXITED(status) && WEXITSTATUS(status) == 0)) {
			if (WIFSIGNALED(status))
				warnx("%s terminated with signal %d",
				    dbus_cmd_name, WTERMSIG(status));
			warnx("%s exited with code %d",
			    dbus_cmd_name, WEXITSTATUS(status));
		}
		r = unlink(session_dbus_socket);
		if (r < 0 && errno != ENOENT)
			warn("%s", session_dbus_socket);
		free(session_dbus_socket);
		session_dbus_socket = NULL;
	}
}

int
curtain_config_setup_dbus(struct curtain_config *cfg)
{
	int r;
	char *p;

	r = asprintf(&p, "%s/%s.dbus.XXXXXXXXXXXX",
	    cfg->old_tmpdir, getprogname());
	if (r < 0)
		err(EX_TEMPFAIL, "asprintf");
	if (!mktemp(p)) {
		free(p);
		warn("mktemp");
		return (-1);
	}

	session_dbus_socket = p;
	r = setenv("CURTAIN_DBUS_SOCKET", session_dbus_socket, 1);
	if (r < 0)
		err(EX_TEMPFAIL, "setenv");
	return (0);
}

int
curtain_config_spawn_dbus(struct curtain_config *cfg __unused)
{
	char buf[1024], *dbus_path, *pipe_fd_str;
	int r, pipe_fds[2];

	r = pipe(pipe_fds);
	if (r < 0)
		err(EX_OSERR, "pipe");

	r = asprintf(&dbus_path, "unix:path=%s", session_dbus_socket);
	if (r < 0)
		err(EX_TEMPFAIL, "asprintf");
	r = asprintf(&pipe_fd_str, "%d", pipe_fds[1]);
	if (r < 0)
		err(EX_TEMPFAIL, "asprintf");

	session_dbus_pid = vfork();
	if (session_dbus_pid < 0)
		err(EX_TEMPFAIL, "vfork");
	if (session_dbus_pid == 0) {
		err_set_exit(_exit);
		close(pipe_fds[0]);
		execlp(dbus_cmd_name, dbus_cmd_name,
		    "--nofork", "--session",
		    "--print-address", pipe_fd_str,
		    "--address", dbus_path, NULL);
		err(EX_OSERR, dbus_cmd_name);
	}
	err_set_exit(NULL);
	close(pipe_fds[1]);

	atexit(cleanup_dbus);

	/*
	 * Don't need to get the address from the daemon since we picked it
	 * ourself, but reading on the pipe until EOF will hopefully make us
	 * wait until it's ready to serve requests before spawning clients.
	 */
	while ((r = read(pipe_fds[0], buf, sizeof buf)) > 0);
	if (r < 0)
		err(EX_IOERR, "pipe from %s", dbus_cmd_name);
	close(pipe_fds[0]);

	r = setenv("DBUS_SESSION_BUS_ADDRESS", dbus_path, 1);
	if (r < 0)
		err(EX_TEMPFAIL, "setenv");
	free(dbus_path);
	dbus_path = NULL;
	return (0);
}

