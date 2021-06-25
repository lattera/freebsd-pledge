#include <assert.h>
#include <ctype.h>
#include <curtain.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <libutil.h>
#include <limits.h>
#include <paths.h>
#include <pledge.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/sysfil.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <termios.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "sysfiltab.h"
#include "privtab.h"
#include "pathexp.h"

struct config {
	const char **tags_base, **tags_last, **tags_fill, **tags_end;
	bool skip_default_tag;
	bool allow_unsafe;
};

struct parser {
	struct config *cfg;
	FILE *file;
	const char *file_name;
	off_t line_no;
	char *line;
	size_t line_size;
	bool skip;
	bool matched_section;
	bool error;
	struct curtain_slot *slot;
	unveil_perms uperms;
};

static const struct {
	const char name[16];
	const unsigned long *ioctls;
} ioctls_bundles[] = {
	{ "tty_basic", curtain_ioctls_tty_basic },
	{ "tty_pts", curtain_ioctls_tty_pts },
	{ "net_basic", curtain_ioctls_net_basic },
	{ "net_route", curtain_ioctls_net_route },
	{ "oss", curtain_ioctls_oss },
	{ "cryptodev", curtain_ioctls_cryptodev },
	{ "bpf", curtain_ioctls_bpf_all },
};


static int
strmemcmp(const char *s, const char *b, size_t n)
{
	while (*s && n) {
		if (*s != *b)
			return ((unsigned)*s - (unsigned)*b);
		s++, b++, n--;
	}
	return (n ? -1 : *s ? 1 : 0);
}

static char *
strmemdup(const char *b, size_t n)
{
	char *s;
	s = malloc(n + 1);
	if (!s)
		return (NULL);
	memcpy(s, b, n);
	s[n] = '\0';
	return (s);
}

static void
parse_error(struct parser *par, const char *error)
{
	par->error = true;
	warnx("%s:%zu: %s", par->file_name, (uintmax_t)par->line_no, error);
}

static char *
skip_spaces(char *p)
{
	while (isspace(*p))
		p++;
	if (*p == '#')
		do p++;
		while (*p);
	return (p);
}

static inline char *
skip_word(char *p, const char *brk)
{
	while (*p) {
		if (*p == '\\') {
			p++;
			if (!*p)
				break;
		} else if (isspace(*p) || strchr(brk, *p))
			break;
		p++;
	}
	return (p);
}

static void
expect_eol(struct parser *par, char *p)
{
	if (*(p = skip_spaces(p)))
		parse_error(par, "unexpected characters at end of line");
}

static int load_config(const char *path, struct config *);

static void
parse_include(struct parser *par, char *p, bool apply)
{
	while (*(p = skip_spaces(p))) {
		char *w, c;
		p = skip_word((w = p), "");
		if (w == p)
			break;
		if (apply) {
			c = *p;
			*p = '\0';
			load_config(w, par->cfg);
			*p = c;
		}
	}
	return (expect_eol(par, p));
}


static char *
parse_merge_tags(struct parser *par, char *p, bool apply) {
	do {
		char *tag, *tag_end;
		bool found;
		tag = p = skip_spaces(p);
		tag_end = p = skip_word(p, ":]");
		if (tag == tag_end)
			break;
		if (apply) {
			found = false;
			for (const char **tagp = par->cfg->tags_base;
			    tagp < par->cfg->tags_last; tagp++)
				if (strmemcmp(*tagp, tag, tag_end - tag) == 0) {
					found = true;
					break;
				}
			if (!found) {
				if (par->cfg->tags_fill == par->cfg->tags_end) {
					parse_error(par, "too many tags in stack");
					return (NULL);
				}
				tag = strmemdup(tag, tag_end - tag);
				if (!tag)
					err(EX_TEMPFAIL, NULL);
				*par->cfg->tags_fill++ = tag;
			}
		}
	} while (true);
	return (p);
}

static void
parse_merge(struct parser *par, char *p, bool apply)
{
	p = parse_merge_tags(par, p, apply);
	if (!p)
		return;
	return (expect_eol(par, p));
}

static int
do_unveil_callback(void *ctx, char *path)
{
	struct parser *par = ctx;
	curtain_unveil(par->slot, path, CURTAIN_UNVEIL_INSPECT, par->uperms);
	return (0);
}

static void
do_unveil(struct parser *par, const char *pattern)
{
	char buf[PATH_MAX];
	int r;
	const char *error;
	r = pathexp(pattern, buf, sizeof buf, &error, do_unveil_callback, par);
	if (r < 0)
		parse_error(par, error);
}

static void
parse_unveil(struct parser *par, char *p, bool apply)
{
	char *pattern, *pattern_end, *perms, *perms_end;

	pattern = p = skip_spaces(p);
	pattern_end = p = skip_word(p, "");

	if (*(p = skip_spaces(p)) == ':') {
		int r;
		p = skip_spaces(++p);
		perms = p;
		while (*p && !isspace(*p))
			p++;
		perms_end = p;
		if (*(p = skip_spaces(p)))
			return (parse_error(par, "unexpected characters at end of line"));

		*pattern_end = '\0';
		if (!*pattern)
			return (parse_error(par, "empty pattern"));

		*perms_end = '\0';
		r = unveil_parse_perms(&par->uperms, perms);
		if (r < 0)
			return (parse_error(par, "invalid unveil permissions"));
	} else {
		if (*p)
			return (parse_error(par, "unexpected characters at end of line"));
		par->uperms = UPERM_READ;
	}

	return (apply ? do_unveil(par, pattern) : 0);
}

static void
parse_sysfil(struct parser *par, char *p, bool apply)
{
	while (*(p = skip_spaces(p))) {
		char *w;
		const struct sysfilent *e;
		p = skip_word((w = p), "");
		if (w == p)
			break;
		for (e = sysfiltab; e->name; e++)
			if (strmemcmp(e->name, w, p - w) == 0)
				break;
		if (!e->name)
			parse_error(par, "unknown sysfil");
		else if (apply)
			curtain_sysfil(par->slot, e->sysfil, 0);
	}
	return (expect_eol(par, p));
}

static void
parse_sysctl(struct parser *par, char *p, bool apply)
{
	while (*(p = skip_spaces(p))) {
		char *w, c;
		p = skip_word((w = p), "");
		if (w == p)
			break;
		if (apply) {
			c = *p;
			*p = '\0';
			curtain_sysctl(par->slot, w, 0);
			*p = c;
		}
	}
	return (expect_eol(par, p));
}

static void
parse_priv(struct parser *par, char *p, bool apply)
{
	while (*(p = skip_spaces(p))) {
		char *w;
		const struct privent *e;
		p = skip_word((w = p), "");
		if (w == p)
			break;
		for (e = privtab; e->name; e++)
			if (strmemcmp(e->name, w, p - w) == 0)
				break;
		if (!e->name)
			parse_error(par, "unknown privilege");
		else if (apply)
			curtain_priv(par->slot, e->priv, 0);
	}
	return (expect_eol(par, p));
}

static void
parse_ioctls(struct parser *par, char *p, bool apply)
{
	while (*(p = skip_spaces(p))) {
		char *w;
		const unsigned long *bundle;
		p = skip_word((w = p), "");
		if (w == p)
			break;
		bundle = NULL;
		for (size_t i = 0; i < nitems(ioctls_bundles); i++)
			if (strmemcmp(ioctls_bundles[i].name, w, p - w) == 0) {
				bundle = ioctls_bundles[i].ioctls;
				break;
			}
		if (!bundle)
			parse_error(par, "unknown ioctl bundle");
		else if (apply)
			curtain_ioctls(par->slot, bundle, 0);
	}
	return (expect_eol(par, p));
}

static const struct {
	const char name[8];
	void (*func)(struct parser *par, char *p, bool apply);
} directives[] = {
	{ "include", parse_include },
	{ "merge", parse_merge },
	{ "unveil", parse_unveil },
	{ "sysfil", parse_sysfil },
	{ "sysctl", parse_sysctl },
	{ "priv", parse_priv },
	{ "ioctls", parse_ioctls },
};

static void
parse_directive(struct parser *par, char *p)
{
	char *dir, *dir_end;
	bool unsafe;
	assert(*p == '.');
	p++;
	dir = p = skip_spaces(p);
	dir_end = p = skip_word(p, "!");
	if (*p == '!')
		p++, unsafe = true;
	else
		unsafe = false;
	for (size_t i = 0; i < nitems(directives); i++)
		if (strmemcmp(directives[i].name, dir, dir_end - dir) == 0)
			return (directives[i].func(par, p,
			    (!unsafe || par->cfg->allow_unsafe) &&
			    (directives[i].func == parse_include ?
			         par->matched_section : !par->skip)));
	parse_error(par, "unknown directive");
}

static void
parse_section(struct parser *par, char *p)
{
	char *tag, *tag_end;
	assert(*p == '[');
	p++;
	tag = p = skip_spaces(p);
	tag_end = p = skip_word(p, ":]");
	if (tag == tag_end) {
		par->matched_section = true;
		par->skip = par->cfg->skip_default_tag;
	} else {
		par->matched_section = false;
		par->skip = true;
		for (const char **tagp = par->cfg->tags_base;
		    tagp < par->cfg->tags_last; tagp++)
			if (strmemcmp(*tagp, tag, tag_end - tag) == 0) {
				par->matched_section = true;
				par->skip = false;
				break;
			}
	}

	p = skip_spaces(p);
	if (*p == ':') {
		p++;
		p = parse_merge_tags(par, p, par->matched_section);
		if (!p)
			return;
	}

	if (*p++ != ']')
		return (parse_error(par, "expected closing bracket"));
	if (*(p = skip_spaces(p)))
		return (parse_error(par, "unexpected characters at end of line"));
}

static void
parse_line(struct parser *par)
{
	char *p;
	p = skip_spaces(par->line);
	if (!*p)
		return;
	if (*p == '[')
		return (parse_section(par, p));
	if (p[0] == '.' && p[1] != '/')
		return (parse_directive(par, p));
	return (parse_unveil(par, p, !par->skip));
}

static void
parse_config(struct parser *par)
{
	while (getline(&par->line, &par->line_size, par->file) >= 0) {
		par->line_no++;
		parse_line(par);
	}
}

static int
load_config(const char *path, struct config *cfg)
{
	struct parser par = {
		.file_name = path,
		.matched_section = true,
		.skip = cfg->skip_default_tag,
		.cfg = cfg,
	};
	int saved_errno;
#if 0
	warnx("%s: %s", __FUNCTION__, path);
#endif
	curtain_enable((par.slot = curtain_slot_neutral()), CURTAIN_ON_EXEC);
	par.file = fopen(path, "r");
	if (!par.file) {
		if (errno != ENOENT)
			warn("%s", par.file_name);
		return (-1);
	}
	parse_config(&par);
	saved_errno = errno;
	fclose(par.file);
	errno = saved_errno;
	return (par.error ? -1 : 0);
}


static void
load_tags_d(const char *base, struct config *cfg)
{
	char path[PATH_MAX];
	for (const char **tagp = cfg->tags_base; tagp < cfg->tags_last; tagp++) {
		const char *tag = *tagp;
		DIR *dir;
		struct dirent *ent;
		int r;
		if (tag[0] == '.')
			continue;

		r = snprintf(path, sizeof path, "%s/%s.conf", base, tag);
		if (r < 0) {
			warn("snprintf");
			continue;
		}
		load_config(path, cfg);

		r = snprintf(path, sizeof path, "%s/%s.d", base, tag);
		if (r < 0) {
			warn("snprintf");
			continue;
		}
		dir = opendir(path);
		if (!dir) {
			if (errno != ENOENT)
				warn("%s", path);
			continue;
		}
		while ((ent = readdir(dir))) {
			if (ent->d_name[0] == '.')
				continue;
			if (ent->d_namlen < 5 ||
			    strcmp(ent->d_name + ent->d_namlen - 5, ".conf") != 0)
				continue;
			r = snprintf(path, sizeof path, "%s/%s.d/%s", base, tag, ent->d_name);
			if (r < 0) {
				warn("snprintf");
				continue;
			}
			load_config(path, cfg);
		}
		r = closedir(dir);
		if (r < 0)
			warn("%s", path);
	}
}

static void
load_tags(struct config *cfg)
{
	char path[PATH_MAX];
	const char *home;
	home = getenv("HOME");

	do {
		cfg->tags_last = cfg->tags_fill;

		load_config(_PATH_ETC "/curtain.conf", cfg);
		load_config(_PATH_LOCALBASE "/etc/curtain.conf", cfg);
		if (home) {
			strlcpy(path, home, sizeof path);
			strlcat(path, "/.curtain.conf", sizeof path);
			load_config(path, cfg);
		}

		cfg->skip_default_tag = false;

		load_tags_d(_PATH_ETC "/curtain.d", cfg);
		load_tags_d(_PATH_LOCALBASE "/etc/curtain.d", cfg);
		if (home) {
			strlcpy(path, home, sizeof path);
			strlcat(path, "/.curtain.d", sizeof path);
			load_tags_d(path, cfg);
		}

		cfg->skip_default_tag = true;
	} while (cfg->tags_last != cfg->tags_fill);
}


static char *new_tmpdir = NULL;

static void
cleanup_tmpdir(void)
{
	int r;
	r = rmdir(new_tmpdir);
	if (r < 0)
		warn("%s", new_tmpdir);
	free(new_tmpdir);
}

static void
prepare_tmpdir(struct curtain_slot *slot)
{
	char *p;
	int r;
	p = getenv("TMPDIR");
	r = asprintf(&p, "%s/%s.tmpdir.XXXXXXXXXXXX",
	    p && *p ? p : _PATH_TMP, getprogname());
	if (r < 0)
		err(EX_TEMPFAIL, "snprintf");
	new_tmpdir = mkdtemp(p);
	if (!new_tmpdir)
		err(EX_OSERR, "%s", p);
	atexit(cleanup_tmpdir);
	r = setenv("TMPDIR", new_tmpdir, 1);
	if (r < 0)
		err(EX_OSERR, "setenv");
	r = curtain_unveil(slot, new_tmpdir, CURTAIN_UNVEIL_INSPECT,
	    UPERM_READ | UPERM_WRITE | UPERM_SETATTR |
	    UPERM_CREATE | UPERM_DELETE | UPERM_UNIX |
	    UPERM_EXECUTE);
	if (r < 0)
		err(EX_OSERR, "%s", new_tmpdir);
}


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
		/* dbus-daemon doesn't always cleanup after itself */
		if (r < 0 && errno != ENOENT)
			warn("%s", session_dbus_socket);
	}
}

static void
prepare_dbus(struct curtain_slot *slot)
{
	char buf[1024];
	char *dbus_path, *pipe_fd_str;
	int r, pipe_fds[2];

	r = pipe(pipe_fds);
	if (r < 0)
		err(EX_OSERR, "pipe");

	session_dbus_socket = tempnam(NULL, "curtain.dbus");
	if (!session_dbus_socket)
		err(EX_OSERR, "tempnam");

	r = asprintf(&dbus_path, "unix:path=%s", session_dbus_socket);
	if (r < 0)
		err(EX_TEMPFAIL, "asprintf");
	r = asprintf(&pipe_fd_str, "%d", pipe_fds[1]);
	if (r < 0)
		err(EX_TEMPFAIL, "asprintf");

	session_dbus_pid = vfork();
	if (session_dbus_pid < 0)
		err(EX_TEMPFAIL, "fork");
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

	/*
	 * Don't need to get the address from the daemon since we picked it
	 * ourself, but reading on the pipe until EOF will hopefully make us
	 * wait until it's ready to serve requests before spawning clients.
	 */
	while ((r = read(pipe_fds[0], buf, sizeof buf)) > 0);
	if (r < 0)
		err(EX_IOERR, "pipe from %s", dbus_cmd_name);
	close(pipe_fds[0]);

	atexit(cleanup_dbus);

	r = setenv("DBUS_SESSION_BUS_ADDRESS", dbus_path, 1);
	if (r < 0)
		err(EX_TEMPFAIL, "setenv");
	free(dbus_path); dbus_path = NULL;

	r = curtain_unveil(slot, session_dbus_socket,
	    CURTAIN_UNVEIL_INSPECT, UPERM_CONNECT|UPERM_INSPECT);
	if (r < 0)
		err(EX_OSERR, "%s", session_dbus_socket);
}


static struct termios tty_saved_termios;
static int pty_master_fd, pty_slave_fd;

static void
restore_tty()
{
	int r;
	r = tcsetattr(STDIN_FILENO, TCSADRAIN, &tty_saved_termios);
	if (r < 0)
		warn("tcsetattr");
}

static void
handle_sigwinch(int sig)
{
	int r;
	struct winsize ws;
	(void)sig;
	if (pty_master_fd < 0)
		return;
	r = ioctl(STDIN_FILENO, TIOCGWINSZ, &ws);
	if (r >= 0)
		r = ioctl(pty_master_fd, TIOCSWINSZ, &ws);
	if (r < 0)
		warn("ioctl");
}

static void
pty_wrap_setup()
{
	bool has_tt, has_ws;
	struct termios tt;
	struct winsize ws;
	int r;
	r = tcgetattr(STDIN_FILENO, &tt);
	if (!(has_tt = r >= 0))
		warn("tcgetattr");
	r = ioctl(STDIN_FILENO, TIOCGWINSZ, &ws);
	if (!(has_ws = r >= 0))
		warn("ioctl");

	r = openpty(&pty_master_fd, &pty_slave_fd, NULL,
	    has_tt ? &tt : NULL, has_ws ? &ws : NULL);
	if (r < 0)
		err(EX_OSERR, "openpty");

	if (has_tt) {
		tty_saved_termios = tt;
		atexit(restore_tty);
		cfmakeraw(&tt);
		r = tcsetattr(STDIN_FILENO, TCSAFLUSH, &tt);
		if (r < 0)
			warn("tcsetattr");
	}
	if (has_ws)
		signal(SIGWINCH, handle_sigwinch);
}

static void
pty_wrap_loop()
{
	struct pollfd pfds[] = {
		{ .fd = STDIN_FILENO, .events = POLLIN },
		{ .fd = pty_master_fd, .events = POLLIN },
	};
	char buf[1024];
	int r;
	while (true) {
		r = poll(pfds, 2, INFTIM);
		if (r <= 0) {
			if (r < 0 && errno != EINTR)
				err(EX_OSERR, "poll");
			continue;
		}

		if (pfds[0].revents & POLLNVAL)
			errx(EX_OSERR, "poll POLLNVAL");
		if (pfds[0].revents & (POLLIN|POLLHUP|POLLERR)) {
			r = read(STDIN_FILENO, buf, sizeof buf);
			if (r < 0)
				err(EX_IOERR, "read");
			if (r == 0) {
				close(pty_master_fd);
				pty_master_fd = -1;
				break;
			}
			r = write(pty_master_fd, buf, r);
			if (r < 0)
				err(EX_IOERR, "write");
		}

		if (pfds[1].revents & POLLNVAL)
			errx(EX_OSERR, "poll POLLNVAL");
		if (pfds[1].revents & (POLLIN|POLLHUP|POLLERR)) {
			r = read(pty_master_fd, buf, sizeof buf);
			if (r < 0)
				err(EX_IOERR, "read");
			if (r == 0)
				break;
			r = write(STDOUT_FILENO, buf, r);
			if (r < 0)
				err(EX_IOERR, "write");
		}
	}
}


static pid_t child_pid;

static void
handle_exit(int sig)
{
	assert(child_pid >= 0);
	if (child_pid)
		kill(child_pid, sig);
}

static void
preexec_cleanup(void)
{
	closefrom(3); /* Prevent potentially unintended FD passing. */
}

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-fkgenaAXYWD] "
	    "[-t tag] [-p promises] [-u unveil ...] "
	    "[-Ssl] cmd [arg ...]\n",
	    getprogname());
	exit(EX_USAGE);
}

int
main(int argc, char *argv[])
{
	char *sh_argv[2];
	int ch, r;
	char *promises = NULL;
	bool autotag = false,
	     autotag_unsafe = false,
	     signaling = false,
	     no_fork = false,
	     run_shell = false,
	     login_shell = false,
	     new_session = false,
	     new_pgrp = false,
	     no_network = false,
	     no_protexec = false;
	enum { X11_NONE, X11_UNTRUSTED, X11_TRUSTED } x11_mode = X11_NONE;
	bool wayland = false;
	bool dbus = false;
	char *cmd_arg0 = NULL;
	char abspath[PATH_MAX];
	size_t abspath_len = 0;
	const char *tags_buf[64];
	struct config cfg;
	struct curtain_slot *unveils_slot, *main_slot;
	bool do_exec, pty_wrap;
	int status;

	cfg = (struct config){
		.tags_base = tags_buf,
		.tags_last = tags_buf,
		.tags_fill = tags_buf,
		.tags_end = &tags_buf[nitems(tags_buf)],
	};

	curtain_enable((main_slot = curtain_slot_neutral()), CURTAIN_ON_EXEC);
	curtain_enable((unveils_slot = curtain_slot_neutral()), CURTAIN_ON_EXEC);

	while ((ch = getopt(argc, argv, "fkgenaAt:p:u:0:SslXYWD")) != -1)
		switch (ch) {
		case 'k':
			signaling = true;
			break;
		case 'g':
			new_pgrp = true;
			break;
		case 'e':
			no_protexec = true;
			break;
		case 'n':
			no_network = true;
			break;
		case 'a':
			autotag = true;
			break;
		case 'A':
			autotag = autotag_unsafe = true;
			break;
		case 't':
			if (cfg.tags_fill == &tags_buf[nitems(tags_buf) / 2])
				errx(EX_USAGE, "too many tags");
			*cfg.tags_fill++ = optarg;
			break;
		case 'p':
			for (char *p = optarg; *p; p++)
				if (*p == ',')
					*p = ' ';
			promises = optarg;
			break;
		case 'u': {
			char *path, *perms;
			unveil_perms uperms;
			path = optarg;
			if ((perms = strrchr(path, ':')))
				*perms++ = '\0';
			else
				perms = __DECONST(char *, "rx");
			if (path[0] != '/') {
				size_t n, m;
				if (!abspath_len) {
					if (!getcwd(abspath, sizeof abspath - 1))
						err(EX_OSERR, "getcwd");
					abspath_len = strlen(abspath);
					abspath[abspath_len++] = '/';
				}
				n = (sizeof abspath) - abspath_len;
				m = strlcpy(abspath + abspath_len, path, n);
				if (m >= n)
					errc(EX_OSFILE, ENAMETOOLONG, "%s", path);
				path = abspath;
			}
			r = unveil_parse_perms(&uperms, perms);
			if (r < 0)
				errx(EX_USAGE, "invalid unveil permissions: %s", perms);
			r = curtain_unveil(unveils_slot, path,
			    CURTAIN_UNVEIL_INSPECT, uperms);
			if (r < 0 && errno != ENOENT)
				warn("%s", path);
			break;
		}
		case '0':
			  cmd_arg0 = optarg;
			  break;
		case 'S':
			  new_session = true;
			  run_shell = true;
			  break;
		case 's':
			  run_shell = true;
			  break;
		case 'l':
			  /* TODO: reset env? */
			  login_shell = true;
			  run_shell = true;
			  break;
		case 'f':
			  no_fork = true;
			  break;
		case 'X':
			  x11_mode = X11_UNTRUSTED;
			  break;
		case 'Y':
			  x11_mode = X11_TRUSTED;
			  break;
		case 'W':
			  wayland = true;
			  break;
		case 'D':
			  dbus = true;
			  break;
		default:
			usage();
		}
	argv += optind;
	argc -= optind;

	if (!signaling)
		curtain_default(main_slot, CURTAIN_DENY);
	if (!no_protexec)
		curtain_sysfil(main_slot, SYSFIL_PROT_EXEC, 0);
	if (!no_network) {
		/* TODO: this should be specified in config files */
		curtain_sockaf(main_slot, AF_UNIX, 0);
		/* XXX SO_SETFIB, SO_LABEL/SO_PEERLABEL */
		curtain_socklvl(main_slot, SOL_SOCKET, 0);
#ifdef AF_INET
		curtain_sockaf(main_slot, AF_INET, 0);
		curtain_socklvl(main_slot, IPPROTO_IP, 0);
#endif
#ifdef AF_INET6
		curtain_sockaf(main_slot, AF_INET6, 0);
		curtain_socklvl(main_slot, IPPROTO_IPV6, 0);
#endif
#if defined(AF_INET) || defined(AF_INET6)
		curtain_socklvl(main_slot, IPPROTO_TCP, 0);
		curtain_socklvl(main_slot, IPPROTO_UDP, 0);
#endif
		*cfg.tags_fill++ = "_network";
	}
	if (new_session) {
		curtain_sysfil(main_slot, SYSFIL_SAME_SESSION, 0);
		*cfg.tags_fill++ = "_session";
	}
	if (run_shell) {
		*cfg.tags_fill++ = "_shell";
	}
	if (new_pgrp) {
		curtain_sysfil(main_slot, SYSFIL_SAME_PGRP, 0);
		if (getpgid(0) != getpid()) {
			r = setpgid(0, 0);
			if (r < 0)
				err(EX_OSERR, "setpgid");
		}
	}
	if (x11_mode != X11_NONE) {
		if (no_fork)
			errx(EX_USAGE, "X11 mode incompatible with -f");
		*cfg.tags_fill++ = "_x11";
		*cfg.tags_fill++ = "_gui";
		prepare_x11(main_slot, x11_mode == X11_TRUSTED);
	};
	if (wayland) {
		*cfg.tags_fill++ = "_wayland";
		*cfg.tags_fill++ = "_gui";
		prepare_wayland(main_slot);
	}
	if (dbus) {
		if (no_fork)
			errx(EX_USAGE, "-D incompatible with -f");
		*cfg.tags_fill++ = "_dbus";
		/*
		 * XXX dbus-daemon currently being run unsandboxed.
		 */
		prepare_dbus(main_slot);
	}
	if (!no_fork) {
		prepare_tmpdir(main_slot);
	} else {
		/*
		 * XXX This can be very unsafe.  UPERM_TMPDIR disallows many
		 * operations on the temporary directory like listing the
		 * files, accessing subdirectories, or creating/connecting to
		 * local domain sockets, etc.  Files securely created with
		 * randomized filenames should be safe from other sandboxed
		 * processes using the same temporary directory.  But files
		 * with known or predictable filenames are not.  KRB5's
		 * krb5cc_<uid> is a pretty bad example of this.
		 */
		const char *tmpdir;
		if (!(tmpdir = getenv("TMPDIR")))
			tmpdir = _PATH_TMP;
		r = curtain_unveil(main_slot, tmpdir,
		    CURTAIN_UNVEIL_INSPECT, UPERM_TMPDIR);
		if (r < 0)
			warn("%s", tmpdir);
	}

	if (autotag && argc)
		*cfg.tags_fill++ = argv[0];
	cfg.allow_unsafe = autotag_unsafe;
	load_tags(&cfg);

	if (promises) {
		r = pledge(NULL, promises);
		if (r < 0)
			err(EX_NOPERM, "pledge");
		r = unveilexec(NULL, NULL);
		if (r < 0)
			err(EX_NOPERM, "unveil");
	} else {
		r = curtain_enforce();
		if (r < 0)
			err(EX_NOPERM, "curtain_enforce");
	}


	if (argc == 0) {
		char *shell;
		if (!run_shell)
			usage();
		shell = getenv("SHELL");
		if (!shell) {
			struct passwd *pw;
			errno = 0;
			pw = getpwuid(getuid());
			if (pw) {
				if (pw->pw_shell && *pw->pw_shell)
					shell = pw->pw_shell;
			} else if (errno)
				err(EX_OSERR, "getpwuid");
			shell = strdup(shell ? shell : _PATH_BSHELL);
			if (!shell)
				err(EX_TEMPFAIL, "strdup");
			endpwent();
		}
		sh_argv[0] = shell;
		sh_argv[1] = NULL;
		argv = sh_argv;
		argc = 1;
	}

	if (login_shell) { /* prefix arg0 with "-" */
		char *p, *q;
		q = (p = strrchr(argv[0], '/')) ? p + 1 : argv[0];
		p = malloc(1 + strlen(q) + 1);
		if (!p)
			err(EX_TEMPFAIL, "malloc");
		p[0] = '-';
		strcpy(p + 1, q);
		cmd_arg0 = p;
	}

	if (new_session && no_fork)
		errx(EX_USAGE, "-S is incompatible with -f");
	pty_wrap = false;

	if (!(do_exec = no_fork)) {
		bool do_setsid;
		do_setsid = false;
		if (new_session) {
			if (isatty(STDIN_FILENO) > 0) {
				pty_wrap_setup();
				pty_wrap = true;
			} else
				do_setsid = true;
		}

		child_pid = 0;
		signal(SIGHUP, handle_exit);
		signal(SIGINT, handle_exit);
		signal(SIGQUIT, handle_exit);
		signal(SIGTERM, handle_exit);

		child_pid = vfork();
		if (child_pid < 0)
			err(EX_TEMPFAIL, "fork");
		if ((do_exec = child_pid == 0)) {
			err_set_exit(_exit);
			if (pty_wrap) {
				close(pty_master_fd);
				r = login_tty(pty_slave_fd);
				if (r < 0)
					err(EX_OSERR, "login_tty");
			} else if (do_setsid) {
				r = setsid();
				if (r < 0)
					err(EX_OSERR, "setsid");
			}
		} else {
			err_set_exit(NULL);
			if (pty_wrap)
				close(pty_slave_fd);
		}
	}
	if (do_exec) {
		char *file;
		file = argv[0];
		if (cmd_arg0)
			argv[0] = cmd_arg0;
		preexec_cleanup();
		execvp(file, argv);
		err(EX_OSERR, "%s", file);
	}
	assert(!no_fork && child_pid > 0);

	if (pty_wrap)
		pty_wrap_loop();

	r = waitpid(child_pid, &status, 0);
	if (r < 0)
		err(EX_OSERR, "waitpid");
	child_pid = 0;
	/* shell-like exit status */
	exit(WIFSIGNALED(status) ? 128 + WTERMSIG(status) : WEXITSTATUS(status));
}
