#include <curtain.h>
#include <err.h>
#include <paths.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <unistd.h>

static char *tmp_xauth_file = NULL;
static char *display_unix_socket = NULL;

static void
cleanup_x11(void)
{
	int r;
	if (tmp_xauth_file) {
		r = unlink(tmp_xauth_file);
		if (r < 0)
			warn("%s", tmp_xauth_file);
		free(tmp_xauth_file);
		tmp_xauth_file = NULL;
	}
	if (display_unix_socket) {
		free(display_unix_socket);
		display_unix_socket = NULL;
	}
}

static void
prepare_x11(struct curtain_slot *slot, bool trusted)
{
	int r;
	char *p, *display;
	pid_t pid;
	int status;

	p = getenv("DISPLAY");
	if (!p || !*p) {
		warnx("DISPLAY environment variable not set");
		return;
	}
	display = p;
	if (display[0] == ':')
		p = display + 1;
	else if (strncmp(display, "unix:", 5) == 0)
		p = display + 5;
	else
		p = NULL;
	if (p) {
		r = asprintf(&display_unix_socket, "%s/X%.*s",
		    "/tmp/.X11-unix", (unsigned)strspn(p, "0123456789"), p);
		if (r < 0)
			err(EX_TEMPFAIL, "asprintf");
	}

	p = getenv("TMPDIR");
	r = asprintf(&p, "%s/%s.xauth.XXXXXXXXXXXX",
	    p && *p ? p : "/tmp", getprogname());
	if (r < 0)
		err(EX_TEMPFAIL, "asprintf");
	r = mkstemp(p);
	if (r < 0)
		err(EX_OSERR, "mkstemp");
	r = close(r);
	if (r < 0)
		warn("%s", p);
	tmp_xauth_file = p;
	atexit(cleanup_x11);

	pid = vfork();
	if (pid < 0)
		err(EX_TEMPFAIL, "fork");
	if (pid == 0) {
		err_set_exit(_exit);
		if (trusted)
			execlp("xauth", "xauth",
			    "extract", tmp_xauth_file, display, NULL);
		else
			execlp("xauth", "xauth", "-f", tmp_xauth_file,
			    "generate", display, ".", "untrusted",
			    "timeout", "0", NULL);
		err(EX_OSERR, "xauth");
	}
	err_set_exit(NULL);

	r = waitpid(pid, &status, 0);
	if (r < 0)
		err(EX_OSERR, "waitpid");
	if (!(WIFEXITED(status) && WEXITSTATUS(status) == 0)) {
		if (WIFSIGNALED(status))
			errx(EX_UNAVAILABLE, "xauth terminated with signal %d",
			    WTERMSIG(status));
		errx(EX_UNAVAILABLE, "xauth exited with code %d", WEXITSTATUS(status));
	}

	r = setenv("XAUTHORITY", tmp_xauth_file, 1);
	if (r < 0)
		err(EX_TEMPFAIL, "setenv");

	if (display_unix_socket) {
		r = curtain_unveil(slot, display_unix_socket,
		    CURTAIN_UNVEIL_INSPECT, UPERM_CONNECT|UPERM_INSPECT);
		if (r < 0)
			err(EX_OSERR, "%s", display_unix_socket);
	}
	if (tmp_xauth_file) {
		r = curtain_unveil(slot, tmp_xauth_file,
		    CURTAIN_UNVEIL_INSPECT, UPERM_READ);
		if (r < 0)
			err(EX_OSERR, "%s", tmp_xauth_file);
	}
}


static void
prepare_wayland(struct curtain_slot *slot)
{
	const char *display;
	char *socket;
	int r;
	display = getenv("WAYLAND_DISPLAY");
	if (!display)
		display = "wayland-0";
	if (display[0] == '/') {
		socket = strdup(display);
		if (!socket)
			err(EX_TEMPFAIL, "strdup");
	} else {
		char *rundir;
		rundir = getenv("XDG_RUNTIME_DIR");
		if (!rundir) {
			warnx("XDG_RUNTIME_DIR environment variable not set");
			return;
		}
		r = asprintf(&socket, "%s/%s", rundir, display);
		if (r < 0)
			err(EX_TEMPFAIL, "asprintf");
	}
	r = curtain_unveil(slot, socket,
	    CURTAIN_UNVEIL_INSPECT, UPERM_CONNECT|UPERM_INSPECT);
	if (r < 0)
		err(EX_OSERR, "%s", socket);
	free(socket);
}


static struct curtain_slot *
get_slot(struct curtain_config *cfg)
{
	struct curtain_slot *slot;
	if (cfg->on_exec)
		curtain_enable((slot = curtain_slot_neutral()), CURTAIN_ON_EXEC);
	else
		slot = curtain_slot();
	return (slot);
}

int
curtain_config_gui(struct curtain_config *cfg)
{
	if (cfg->x11 || cfg->x11_trusted)
		prepare_x11(get_slot(cfg), cfg->x11_trusted);
	if (cfg->wayland)
		prepare_wayland(get_slot(cfg));
	return (0);
}
