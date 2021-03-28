#include <assert.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <paths.h>
#include <pledge.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <unistd.h>

static const char *default_promises =
    "stdio "
    "thread "
    "rlimit "
    "rpath wpath cpath dpath "
    "exec "
    "flock fattr chown id "
    "proc_child ps_child "
    "tty "
    "posixrt "
    "unix recvfd sendfd ";

static const char *pgrp_promises = "proc_pgrp ps_pgrp";

static const char *shell_promises = "proc_session ps_session";

static const char *network_promises = "ssl dns inet";

static const char *x11_promises = "";

static const char *protexec_promises = "prot_exec";

static const char *error_promises = "error";

struct unveil_entry {
	const char *path;
	const char *perms;
};

static const struct unveil_entry default_unveils[] = {
	/*
	 * NOTE:
	 * - "m" permission is "w" without the implied "a" (change attributes).
	 * - On this implementation, open(2) with O_CREAT works with just "w"
	 *   (or "m") unveil permissions if the file already exists.
	 */
	{ _PATH_DEVNULL, "rm" },
	{ _PATH_DEV "/fd", "rm" },
	{ _PATH_DEV "/stdin", "r" },
	{ _PATH_DEV "/stdout", "rm" },
	{ _PATH_DEV "/stderr", "rm" },
	{ _PATH_DEV "/full", "rm" },
	{ _PATH_DEV "/zero", "rm" },
	{ _PATH_ETC "/termcap", "r" },
	{ "/lib", "rx" },
	{ "/usr/lib", "rx" },
	{ _PATH_LOCALBASE "/lib", "rx" },
	{ "/libexec", "rx" },
	{ "/usr/libexec", "rx" },
	{ _PATH_LOCALBASE "/libexec", "rx" },
	{ "/bin", "rx" },
	{ "/sbin", "rx" },
	{ "/usr/bin", "rx" },
	{ "/usr/sbin", "rx" },
	{ _PATH_LOCALBASE "/bin", "rx" },
	{ _PATH_LOCALBASE "/sbin", "rx" },
	{ "/usr/share", "r" },
	/* NOTE: some packages install executables in /usr/local/share */
	{ _PATH_LOCALBASE "/share", "rx" },
};

static const struct unveil_entry x11_unveils[] = {
	{ _PATH_LOCALBASE "/etc/fonts", "r" },
};


static void
do_pledge(const char **base, const char **fill)
{
	size_t size;
	const char **iter;
	for (size = 0, iter = base; iter != fill; iter++)
		size += strlen(*iter) + 1;
	char buf[size], *ptr;
	for (ptr = buf, iter = base; iter != fill; iter++) {
		ptr = stpcpy(ptr, *iter);
		*ptr++ = ' ';
	}
	*ptr = '\0';

	int r;
	r = pledge(NULL, buf);
	if (r < 0)
		err(EX_NOPERM, "pledge");
}

static void
do_unveils(size_t count, const struct unveil_entry *table)
{
	int r;
	const struct unveil_entry *entry;
	for (entry = table; entry != &table[count]; entry++) {
		r = unveilexec(entry->path, entry->perms);
		if (r < 0 && errno != ENOENT)
			warn("%s", entry->path);
	}
}

static void
finish_unveils(void)
{
	int r;
	r = unveilexec(NULL, NULL);
	if (r < 0)
		err(EX_OSERR, "unveil");
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
prepare_tmpdir(void)
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
}


static char *tmp_xauth_file = NULL;

static void
cleanup_x11(void)
{
	int r;
	r = unlink(tmp_xauth_file);
	if (r < 0)
		warn("%s", tmp_xauth_file);
	free(tmp_xauth_file);
	tmp_xauth_file = NULL;
}

static void
prepare_x11(bool trusted)
{
	int r;
	char *p, *display;
	pid_t pid;
	int status;

	p = getenv("DISPLAY");
	if (!p || !*p)
		errx(EX_DATAERR, "DISPLAY environment variable not set");
	display = p;

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
		if (trusted) {
			execlp("xauth", "xauth",
			    "extract", tmp_xauth_file, display, NULL);
		} else {
			execlp("xauth", "xauth", "-f", tmp_xauth_file,
			    "generate", display, ".", "untrusted", NULL);
		}
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
}


static pid_t child_pid;

static void
signal_handler(int sig)
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

static pid_t
exec_shell(bool wrap, bool login_shell)
{
	const char *run, *name;

	run = getenv("SHELL");
	if (!run || !*run) {
		struct passwd *pw;
		run = _PATH_BSHELL;
		errno = 0;
		pw = getpwuid(getuid());
		if (pw) {
			if (pw->pw_shell && *pw->pw_shell) {
				run = strdup(pw->pw_shell);
				if (!run)
					err(EX_TEMPFAIL, "strdup");
			}
		} else if (errno)
			err(EX_OSERR, "getpwuid");
		endpwent();
	}

	if (login_shell) {
		char *p;
		const char *q;
		q = (p = strrchr(run, '/')) ? p + 1 : run;
		p = malloc(1 + strlen(q) + 1);
		if (!p)
			err(EX_TEMPFAIL, "malloc");
		p[0] = '-';
		strcpy(p + 1, q);
		name = p;
	} else
		name = run;

	if (wrap) {
		pid_t pid;
		pid = vfork();
		if (pid < 0)
			err(EX_TEMPFAIL, "fork");
		if (pid != 0) {
			err_set_exit(NULL);
			return (pid);
		}
		err_set_exit(_exit);
	}

	preexec_cleanup();
	execlp(run, name, (char *)NULL);
	err(EX_OSERR, "%s", run);
}

static pid_t
exec_cmd(bool wrap, char *cmd_name, char **argv)
{
	if (wrap) {
		pid_t pid;
		pid = vfork();
		if (pid < 0)
			err(EX_TEMPFAIL, "fork");
		if (pid != 0) {
			err_set_exit(NULL);
			return (pid);
		}
		err_set_exit(_exit);
	}
	preexec_cleanup();
	execvp(cmd_name, argv);
	err(EX_OSERR, "%s", cmd_name);
}

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-kgenwXY] [-p promises] [-u unveil ...] [-sS] cmd [arg ...]\n", getprogname());
	exit(EX_USAGE);
}


int
main(int argc, char *argv[])
{
	int ch, r;
	const char *promises_base[10], **promises_fill = promises_base,
	     *custom_promises = NULL;
	struct unveil_entry custom_unveils_base[argc],
	    *custom_unveils_fill = custom_unveils_base;
	bool wrap = false;
	int status;
	bool signaling = false,
	     run_shell = false,
	     login_shell = false,
	     new_pgrp = false,
	     no_network = false,
	     no_protexec = false;
	enum { X11_NONE, X11_UNTRUSTED, X11_TRUSTED } x11_mode = X11_NONE;
	char *cmd_arg0 = NULL;
	char abspath[PATH_MAX];
	size_t abspath_len = 0;

	while ((ch = getopt(argc, argv, "kgenp:u:0:sSwXY")) != -1)
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
		case 'p': {
			char *p;
			for (p = optarg; *p; p++)
				if (*p == ',')
					*p = ' ';
			custom_promises = optarg;
			break;
		}
		case 'u': {
			char *path, *perms;
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
			*custom_unveils_fill++ = (struct unveil_entry){ path, perms };
			break;
		}
		case '0':
			  cmd_arg0 = optarg;
			  break;
		case 'S':
			  login_shell = true;
			  /* FALLTHROUGH */
		case 's':
			  run_shell = true;
			  break;
		case 'w':
			  wrap = true;
			  break;
		case 'X':
			  x11_mode = X11_UNTRUSTED;
			  wrap = true;
			  break;
		case 'Y':
			  x11_mode = X11_TRUSTED;
			  wrap = true;
			  break;
		default:
			usage();
		}
	argv += optind;
	argc -= optind;

	if (run_shell == (argc != 0))
		usage();

	*promises_fill++ = default_promises;
	if (!no_network)
		*promises_fill++ = network_promises;
	if (custom_promises)
		*promises_fill++ = custom_promises;

	if (wrap)
		prepare_tmpdir();
	else
		*promises_fill++ = "tmppath";
	if (!signaling)
		*promises_fill++ = error_promises;
	if (run_shell)
		*promises_fill++ = shell_promises;
	if (new_pgrp) {
		*promises_fill++ = pgrp_promises;
		if (getpgid(0) != getpid()) {
			r = setpgid(0, 0);
			if (r < 0)
				err(EX_OSERR, "setpgid");
		}
	}
	if (x11_mode != X11_NONE) {
		*promises_fill++ = x11_promises;
		prepare_x11(x11_mode == X11_TRUSTED);
	};
	if (!no_protexec)
		*promises_fill++ = protexec_promises;

	*promises_fill++ = "unveil";
	do_pledge(promises_base, promises_fill);

	do_unveils(nitems(default_unveils), default_unveils);
	if (x11_mode != X11_NONE) {
		r = unveilexec(tmp_xauth_file, "r");
		if (r < 0)
			err(EX_OSERR, "%s", tmp_xauth_file);
		do_unveils(nitems(x11_unveils), x11_unveils);
	}
	if (wrap) {
		r = unveilexec(new_tmpdir, "rwc");
		if (r < 0)
			err(EX_OSERR, "%s", new_tmpdir);
	}
	do_unveils(custom_unveils_fill - custom_unveils_base, custom_unveils_base);
	finish_unveils();

	if (wrap) {
		child_pid = 0;
		signal(SIGHUP, signal_handler);
		signal(SIGINT, signal_handler);
		signal(SIGQUIT, signal_handler);
		signal(SIGTERM, signal_handler);
	}

	if (run_shell) {
		child_pid = exec_shell(wrap, login_shell);
	} else {
		char *cmd_name;
		cmd_name = argv[0];
		if (cmd_arg0)
			argv[0] = cmd_arg0;
		child_pid = exec_cmd(wrap, cmd_name, argv);
	}

	assert(wrap);
	r = waitpid(child_pid, &status, 0);
	if (r < 0)
		err(EX_OSERR, "waitpid");
	child_pid = 0;
	/* shell-like exit status */
	exit(WIFSIGNALED(status) ? 128 + WTERMSIG(status) : WEXITSTATUS(status));
}
