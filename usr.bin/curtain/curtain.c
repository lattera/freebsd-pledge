#include <assert.h>
#include <ctype.h>
#include <curtain.h>
#include <dirent.h>
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
#include <sys/sysfil.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <unistd.h>

#include "pathexp.h"

static const int default_sysfils[] = {
	SYSFIL_STDIO,
	SYSFIL_THREAD,
	SYSFIL_RLIMIT,
	SYSFIL_SCHED,
	SYSFIL_RPATH, SYSFIL_WPATH, SYSFIL_CPATH, SYSFIL_DPATH,
	SYSFIL_FATTR, SYSFIL_CHOWN, SYSFIL_FLOCK,
	SYSFIL_CHROOT,
	SYSFIL_UNIX, SYSFIL_SENDFD, SYSFIL_RECVFD,
	SYSFIL_EXEC,
	SYSFIL_PROC, SYSFIL_PS,
	SYSFIL_CHILD_PROCESS,
	SYSFIL_TTY,
	SYSFIL_POSIXRT,
	SYSFIL_ID,
	SYSFIL_UNVEIL,
};

static const int network_sysfils[] = {
	SYSFIL_INET,
	SYSFIL_ROUTE, /* XXX */
	SYSFIL_CRYPTODEV,
};


struct tags_stack {
	const char **base, **peek, **last, **fill, **end;
};

struct config {
	struct tags_stack *tags;
	FILE *file;
	const char *file_name;
	off_t line_no;
	char *line;
	size_t line_size;
	bool apply;
	struct curtain_slot *slot;
	unveil_perms uperms;
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

static int
parse_error(struct config *cfg, const char *error)
{
	warnx("%s:%zu: %s", cfg->file_name, (uintmax_t)cfg->line_no, error);
	return (-1);
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

static int
do_unveil_callback(void *ctx, char *path)
{
	struct config *cfg = ctx;
#if 0
	fprintf(stderr, "%s %u\n", path, cfg->uperms);
#endif
	curtain_unveil(cfg->slot, path, CURTAIN_UNVEIL_INSPECT, cfg->uperms);
	return (0);
}

static int
do_unveil(struct config *cfg, const char *pattern)
{
	char buf[PATH_MAX];
	int r;
	const char *error;
	r = pathexp(pattern, buf, sizeof buf, &error, do_unveil_callback, cfg);
	if (r < 0)
		return (parse_error(cfg, error));
	return (0);
}

static int
parse_unveil(struct config *cfg, char *p)
{
	char *pattern, *pattern_end, *perms, *perms_end;
	int r;

	pattern = p;
	while (*p) {
		if (*p == '\\') {
			p++;
			if (!*p)
				break;
		} else if (isspace(*p) || *p == ':')
			break;
		p++;
	}
	pattern_end = p;

	if (*(p = skip_spaces(p)) == ':') {
		p = skip_spaces(++p);
		perms = p;
		while (*p && !isspace(*p))
			p++;
		perms_end = p;
		if (*(p = skip_spaces(p)))
			return (parse_error(cfg, "unexpected characters at end of line"));

		*pattern_end = '\0';
		if (!*pattern)
			return (parse_error(cfg, "empty pattern"));

		*perms_end = '\0';
		r = unveil_parse_perms(&cfg->uperms, perms);
		if (r < 0)
			return (parse_error(cfg, "invalid unveil permissions"));
	} else
		cfg->uperms = UPERM_RPATH;

	if (!cfg->apply)
		return (0);
	return (do_unveil(cfg, pattern));
}

static int
parse_section(struct config *cfg, char *p)
{
	char *tag, *tag_end;
	p++;
	tag = p = skip_spaces(p);
	while (*p && !isblank(*p) && *p != ':' && *p != ']')
		p++;
	tag_end = p;
	if (tag == tag_end) {
		cfg->apply = true;
	} else {
		cfg->apply = false;
		for (const char **tagp = cfg->tags->base; tagp < cfg->tags->last; tagp++)
			if (strmemcmp(*tagp, tag, tag_end - tag) == 0) {
				cfg->apply = true;
				break;
			}
	}

	p = skip_spaces(p);
	if (*p == ':') {
		p++;
		do {
			bool found;
			tag = p = skip_spaces(p);
			while (*p && !isblank(*p) && *p != ':' && *p != ']')
				p++;
			tag_end = p;
			if (tag == tag_end)
				break;
			if (cfg->apply) {
				found = false;
				for (const char **tagp = cfg->tags->base; tagp < cfg->tags->last; tagp++)
					if (strmemcmp(*tagp, tag, tag_end - tag) == 0) {
						found = true;
						break;
					}
				if (!found) {
					if (cfg->tags->fill == cfg->tags->end)
						return (parse_error(cfg, "too many tags in stack"));
					tag = strmemdup(tag, tag_end - tag);
					if (!tag)
						err(EX_TEMPFAIL, NULL);
					*cfg->tags->fill++ = tag;
				}
			}
		} while (true);
	}

	if (*p++ != ']')
		return (parse_error(cfg, "expected closing bracket"));
	if (*(p = skip_spaces(p)))
		return (parse_error(cfg, "unexpected characters at end of line"));
	return (0);
}

static int
parse_line(struct config *cfg)
{
	char *p;
	p = skip_spaces(cfg->line);
	if (!*p)
		return (0);
	if (*p == '[')
		return (parse_section(cfg, p));
	return (parse_unveil(cfg, p));
}

static int
parse_config(struct config *cfg)
{
	bool errors = false;
	while (getline(&cfg->line, &cfg->line_size, cfg->file) >= 0) {
		int r;
		cfg->line_no++;
		r = parse_line(cfg);
		if (r < 0)
			errors = true;

	}
	return (errors ? -1 : 0);
}

static int
load_config(const char *path, struct tags_stack *tags)
{
	struct config cfg = {
		.file_name = path,
		.apply = true,
		.tags = tags,
	};
	int r, saved_errno;
#if 0
	warnx("%s: %s", __FUNCTION__, path);
#endif
	curtain_enable((cfg.slot = curtain_slot_neutral()), CURTAIN_ON_EXEC);
	cfg.file = fopen(path, "r");
	if (!cfg.file) {
		if (errno != ENOENT)
			warn("%s", cfg.file_name);
		return (-1);
	}
	r = parse_config(&cfg);
	saved_errno = errno;
	fclose(cfg.file);
	errno = saved_errno;
	return (r);
}


static void
load_tags_d(const char *base, struct tags_stack *tags)
{
	char path[PATH_MAX];
	for (const char **tagp = tags->base; tagp < tags->last; tagp++) {
		const char *tag = *tagp;
		DIR *dir;
		struct dirent *ent;
		int r;
		if (tag[0] == '.')
			continue;
		r = snprintf(path, sizeof path, "%s/%s", base, tag);
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
			r = snprintf(path, sizeof path, "%s/%s/%s", base, tag, ent->d_name);
			if (r < 0) {
				warn("snprintf");
				continue;
			}
			load_config(path, tags);
		}
		r = closedir(dir);
		if (r < 0)
			warn("%s", path);
	}
}

static void
load_tags(struct tags_stack *tags)
{
	char path[PATH_MAX];
	const char *home;
	home = getenv("HOME");

	do {
		tags->peek = tags->last;
		tags->last = tags->fill;

		load_config(_PATH_ETC "/curtain.conf", tags);
		load_config(_PATH_LOCALBASE "/etc/curtain.conf", tags);
		if (home) {
			strlcpy(path, home, sizeof path);
			strlcat(path, "/.curtain.conf", sizeof path);
			load_config(path, tags);
		}

		load_tags_d(_PATH_ETC "/curtain.d", tags);
		load_tags_d(_PATH_LOCALBASE "/etc/curtain.d", tags);
		if (home) {
			strlcpy(path, home, sizeof path);
			strlcat(path, "/.curtain.d", sizeof path);
			load_tags_d(path, tags);
		}
	} while (tags->last != tags->fill);
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
	r = curtain_unveil(slot, new_tmpdir,
	    CURTAIN_UNVEIL_INSPECT, UPERM_RPATH|UPERM_WPATH|UPERM_APATH|UPERM_CPATH);
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
			    "generate", display, ".", "untrusted", NULL);
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
		    CURTAIN_UNVEIL_INSPECT, UPERM_RPATH|UPERM_WPATH);
		if (r < 0)
			err(EX_OSERR, "%s", display_unix_socket);
	}
	if (tmp_xauth_file) {
		r = curtain_unveil(slot, tmp_xauth_file,
		    CURTAIN_UNVEIL_INSPECT, UPERM_RPATH);
		if (r < 0)
			err(EX_OSERR, "%s", tmp_xauth_file);
	}
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
#if 0
		/* XXX This makes /dev/tty not work. */
		pid = setsid();
		if (pid < 0)
			err(EX_OSERR, "setsid");
#endif
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
	fprintf(stderr, "usage: %s [-fkgenaXY] "
	    "[-t tag] [-p promises] [-u unveil ...] "
	    "[-sS] cmd [arg ...]\n",
	    getprogname());
	exit(EX_USAGE);
}

int
main(int argc, char *argv[])
{
	int ch, r;
	char *promises = NULL;
	bool autotag = false;
	bool nofork = false;
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
	const char *tags_buf[64];
	struct tags_stack tags;
	struct curtain_slot *unveils_slot, *main_slot;
	int status;

	tags.base = tags.last = tags.fill = tags_buf;
	tags.end = &tags_buf[nitems(tags_buf)];

	curtain_enable((main_slot = curtain_slot_neutral()), CURTAIN_ON_EXEC);
	curtain_enable((unveils_slot = curtain_slot_neutral()), CURTAIN_ON_EXEC);

	while ((ch = getopt(argc, argv, "fkgenat:p:u:0:sSXY")) != -1)
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
		case 't':
			if (tags.fill == &tags_buf[nitems(tags_buf) / 2])
				errx(EX_USAGE, "too many tags");
			*tags.fill++ = optarg;
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
			  login_shell = true;
			  /* FALLTHROUGH */
		case 's':
			  run_shell = true;
			  break;
		case 'f':
			  nofork = true;
			  break;
		case 'X':
			  x11_mode = X11_UNTRUSTED;
			  break;
		case 'Y':
			  x11_mode = X11_TRUSTED;
			  break;
		default:
			usage();
		}
	argv += optind;
	argc -= optind;

	if (run_shell == (argc != 0))
		usage();

	for (size_t i = 0; i < nitems(default_sysfils); i++)
		curtain_sysfil(main_slot, default_sysfils[i]);
	if (!no_network) {
		*tags.fill++ = "@network";
		for (size_t i = 0; i < nitems(network_sysfils); i++)
			curtain_sysfil(main_slot, network_sysfils[i]);
	}
	if (!signaling)
		curtain_sysfil(main_slot, SYSFIL_ERROR);
	if (run_shell)
		curtain_sysfil(main_slot, SYSFIL_SAME_SESSION);
	if (new_pgrp) {
		curtain_sysfil(main_slot, SYSFIL_SAME_PGRP);
		if (getpgid(0) != getpid()) {
			r = setpgid(0, 0);
			if (r < 0)
				err(EX_OSERR, "setpgid");
		}
	}
	if (x11_mode != X11_NONE) {
		if (nofork)
			errx(EX_USAGE, "X11 mode incompatible with -f");
		*tags.fill++ = "@x11";
		prepare_x11(main_slot, x11_mode == X11_TRUSTED);
	};
	if (!no_protexec)
		curtain_sysfil(main_slot, SYSFIL_PROT_EXEC);
	if (!nofork) {
		prepare_tmpdir(main_slot);
	} else {
		/*
		 * XXX This can be very unsafe.  UPERM_TMPPATH disallows many
		 * operations on the temporary directory like listing the
		 * files, accessing subdirectories, or creating/connecting to
		 * local domain sockets, etc.  Files securely created with
		 * randomized filenames should be safe from other sandboxed
		 * processes using the same temporary directory.  But files
		 * with known or predictable filenames are not.  KRB5's
		 * krb5cc_<uid> is a pretty bad example of this.
		 */
		const char *tmppath;
		if (!(tmppath = getenv("TMPDIR")))
			tmppath = _PATH_TMP;
		r = curtain_unveil(main_slot, tmppath,
		    CURTAIN_UNVEIL_INSPECT, UPERM_TMPPATH);
		if (r < 0)
			warn("%s", tmppath);
	}

	if (autotag && !run_shell)
		*tags.fill++ = argv[0];
	load_tags(&tags);

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

	if (!nofork) {
		child_pid = 0;
		signal(SIGHUP, signal_handler);
		signal(SIGINT, signal_handler);
		signal(SIGQUIT, signal_handler);
		signal(SIGTERM, signal_handler);
	}

	if (run_shell) {
		child_pid = exec_shell(!nofork, login_shell);
	} else {
		char *cmd_name;
		cmd_name = argv[0];
		if (cmd_arg0)
			argv[0] = cmd_arg0;
		child_pid = exec_cmd(!nofork, cmd_name, argv);
	}

	assert(!nofork);
	r = waitpid(child_pid, &status, 0);
	if (r < 0)
		err(EX_OSERR, "waitpid");
	child_pid = 0;
	/* shell-like exit status */
	exit(WIFSIGNALED(status) ? 128 + WTERMSIG(status) : WEXITSTATUS(status));
}
