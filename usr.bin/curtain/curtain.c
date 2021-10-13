#include <assert.h>
#include <curtain.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libutil.h>
#include <limits.h>
#include <paths.h>
#include <pledge.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
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
#include <termios.h>
#include <unistd.h>
#include <vis.h>

static struct termios tty_saved_termios;
static int pty_outer_fd, pty_master_fd, pty_slave_fd;

static void
restore_tty()
{
	int r;
	r = tcsetattr(pty_outer_fd, TCSADRAIN, &tty_saved_termios);
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
	r = ioctl(pty_outer_fd, TIOCGWINSZ, &ws);
	if (r >= 0)
		r = ioctl(pty_master_fd, TIOCSWINSZ, &ws);
	if (r < 0)
		warn("ioctl");
}

#define	PTY_WRAP_FDS 3
static bool pty_fds_pass[PTY_WRAP_FDS];

static void
pty_wrap_setup(bool partial)
{
	bool has_tt, has_ws;
	struct termios tt;
	struct winsize ws;
	int r;

	pty_outer_fd = open(_PATH_TTY, O_RDWR);
	if (pty_outer_fd < 0)
		err(EX_OSFILE, "%s", _PATH_TTY);

	for (int fd = 0; fd < PTY_WRAP_FDS; fd++) {
		pty_fds_pass[fd] = false;
		if (partial) {
			errno = 0;
			r = isatty(fd);
			if (r <= 0) {
				if (r < 0 || (errno && errno != ENOTTY))
					warn("isatty(%i)", fd);
				else
					pty_fds_pass[fd] = true;
			}
		}
	}

	r = tcgetattr(pty_outer_fd, &tt);
	if (!(has_tt = r >= 0))
		warn("tcgetattr");
	r = ioctl(pty_outer_fd, TIOCGWINSZ, &ws);
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
		r = tcsetattr(pty_outer_fd, TCSAFLUSH, &tt);
		if (r < 0)
			warn("tcsetattr");
	}
	if (has_ws)
		signal(SIGWINCH, handle_sigwinch);
}

static void
pty_wrap_child(bool partial)
{
	int r;
	close(pty_master_fd);
	close(pty_outer_fd);
	if (partial) {
		pid_t sid;
		sid = setsid();
		if (sid < 0)
			err(EX_OSERR, "setsid");
		if (tcsetsid(pty_slave_fd, sid) < 0)
			err(EX_OSERR, "tcsetsid");
		for (int fd = 0; fd < PTY_WRAP_FDS; fd++)
			if (!pty_fds_pass[fd]) {
				r = dup2(pty_slave_fd, fd);
				if (r < 0)
					err(EX_OSERR, "dup2");
			}
		if (pty_slave_fd >= PTY_WRAP_FDS)
			close(pty_slave_fd);
	} else {
		r = login_tty(pty_slave_fd);
		if (r < 0)
			err(EX_OSERR, "login_tty");
	}
}

static void
pty_wrap_loop(bool filter)
{
	struct pollfd pfds[] = {
		{ .fd = pty_outer_fd, .events = POLLIN },
		{ .fd = pty_master_fd, .events = POLLIN },
	};
	char buf[1024], visbuf[filter ? (sizeof buf) * 4 + 1 : 0];
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
			r = read(pty_outer_fd, buf, sizeof buf);
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
			if (filter) {
				r = strnvisx(visbuf, sizeof visbuf, buf, r,
				    VIS_SAFE | VIS_NOSLASH);
				if (r < 0)
					err(EX_IOERR, "strnvisx");
			}
			r = write(pty_outer_fd, filter ? visbuf : buf, r);
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

#define	DROP_FD_FROM	3

static void
init_harden(void)
{
	bool missing[DROP_FD_FROM], any_missing;
	int fd, r;
	for (fd = 0, any_missing = false; fd < DROP_FD_FROM; fd++) {
		r = fcntl(fd, F_GETFD);
		if (r < 0) {
			any_missing = missing[fd] = true;
			if (errno != EBADF)
				warn("fcntl fd#%i", fd);
		} else
			missing[fd] = false;
	}
	if (any_missing) {
		int dnfd;
		bool seen;
		dnfd = open(_PATH_DEVNULL, O_RDWR);
		if (dnfd < 0)
			err(EX_OSFILE, "%s", _PATH_DEVNULL);
		for (fd = 0, seen = false; fd < DROP_FD_FROM; fd++)
			if (dnfd != fd) {
				if (missing[fd]) {
					r = dup2(dnfd, fd);
					if (r < 0)
						err(EX_OSERR, "dup2 fd#%i", fd);
				}
			} else
				seen = true;
		if (!seen) {
			r = close(dnfd);
			if (r < 0)
				warn("close");
		}
	}
}

static void
preexec_cleanup(void)
{
	closefrom(DROP_FD_FROM); /* Prevent potentially unintended FD passing. */
}

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-vfkgneaAXYW] "
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
	unsigned unsafety = 0;
	bool extra = false,
	     autotag = false,
	     signaling = false,
	     no_fork = false,
	     run_shell = false,
	     login_shell = false,
	     pty_wrap = false,
	     pty_wrap_partial = false,
	     pty_filter = false,
	     new_sid = false,
	     new_pgrp = false,
	     no_network = false,
	     unenforced = false;
	enum { X11_NONE, X11_UNTRUSTED, X11_TRUSTED } x11_mode = X11_NONE;
	bool wayland = false;
	char *cmd_arg0 = NULL;
	char abspath[PATH_MAX];
	size_t abspath_len = 0;
	struct curtain_config *cfg;
	struct curtain_slot *main_slot, *args_slot;
	bool do_exec;
	int status;

	init_harden();

	cfg = curtain_config_new(CURTAIN_CONFIG_ON_EXEC_ONLY);

	curtain_enable((main_slot = curtain_slot_neutral()), CURTAIN_ON_EXEC);
	curtain_enable((args_slot = curtain_slot_neutral()), CURTAIN_ON_EXEC);

	while ((ch = getopt(argc, argv, "@:d:vfkneaA!o:t:p:u:0:SslUXYW")) != -1)
		switch (ch) {
		case 'o': {
			char *str, *tok;
			str = optarg;
			while ((tok = strsep(&str, ",")))
				if (strcmp(tok, "newpgrp") == 0) {
					new_pgrp = true;
				} else if (strcmp(tok, "newsid") == 0) {
					new_sid = true;
				} else if (strcmp(tok, "pty_partial") == 0) {
					pty_wrap = pty_wrap_partial = true;
				} else if (strcmp(tok, "pty_filter") == 0) {
					pty_filter = pty_wrap = pty_wrap_partial = true;
				} else {
					warnx("unknown option: %s", tok);
				}
			break;
		}
		case '@':
		case 'd':
			curtain_config_directive(cfg, args_slot, optarg);
			break;
		case 'v':
			curtain_config_verbosity(cfg, curtain_config_verbosity(cfg, 0) + 1);
			break;
		case 'k':
			signaling = true;
			break;
		case 'g':
			new_pgrp = true;
			break;
		case 'n':
			no_network = true;
			break;
		case 'e':
			extra = true;
			break;
		case 'a':
			autotag = true;
			break;
		case 'A':
			autotag = true;
			/* FALLTHROUGH */
		case '!':
			unsafety++;
			break;
		case 't': {
			char *p = optarg;
			if (*p == '-') {
				p++;
				curtain_config_tag_block(cfg, p);
			} else {
				if (*p == '+')
					p++;
				curtain_config_tag_push(cfg, p);
			}
			break;
		}
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
			r = curtain_parse_unveil_perms(&uperms, perms);
			if (r < 0)
				errx(EX_USAGE, "invalid unveil permissions: %s", perms);
			r = curtain_unveil(args_slot, path,
			    CURTAIN_UNVEIL_INSPECT, uperms);
			if (r < 0 && errno != ENOENT)
				warn("%s", path);
			break;
		}
		case '0':
			  cmd_arg0 = optarg;
			  break;
		case 'S':
			  new_sid = true;
			  pty_wrap = true;
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
		case 'U':
			  unenforced = true;
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
		default:
			usage();
		}
	argv += optind;
	argc -= optind;

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


	curtain_config_unsafety(cfg, unsafety);
	curtain_config_tags_from_env(cfg, NULL);
	curtain_config_tag_push(cfg, "_default");
	curtain_config_tag_push(cfg, "_basic");
	if (!signaling)
		curtain_default(main_slot, CURTAIN_DENY);
	if (extra)
		curtain_config_tag_push(cfg, "_extra");
	if (no_network)
		curtain_config_tag_block(cfg, "_network");
	if (new_sid)
		curtain_config_tag_push(cfg, "_session");
	if (run_shell)
		curtain_config_tag_push(cfg, "_shell");
	if (login_shell)
		curtain_config_tag_push(cfg, "_login_shell");
	if (new_pgrp)
		curtain_config_tag_push(cfg, "_pgrp");

	if (autotag && argc) {
		char *p;
		if ((p = strrchr(argv[0], '/')))
			p = p + 1;
		else
			p = argv[0];
		curtain_config_tag_push(cfg, p);
	}

	curtain_config_setup_tmpdir(cfg, !no_fork);
	if (x11_mode != X11_NONE) {
		if (no_fork)
			errx(EX_USAGE, "X11 mode incompatible with -f");
		curtain_config_tag_push(cfg, "_x11");
		curtain_config_tag_push(cfg,
		    x11_mode == X11_TRUSTED ? "_x11_trusted" : "_x11_untrusted");
		curtain_config_tag_push(cfg, "_gui");
		curtain_config_setup_x11(cfg, x11_mode == X11_TRUSTED);
	};
	if (wayland) {
		curtain_config_tag_push(cfg, "_wayland");
		curtain_config_tag_push(cfg, "_gui");
		curtain_config_setup_wayland(cfg);
	}

	curtain_config_load(cfg);

	if (promises) {
		r = pledge(NULL, promises);
		if (r < 0)
			err(EX_NOPERM, "pledge");
		r = unveil_exec(NULL, NULL);
		if (r < 0)
			err(EX_NOPERM, "unveil");
	} else {
		r = unenforced ? curtain_engage() : curtain_enforce();
		if (r < 0)
			err(EX_NOPERM, "curtain_enforce");
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

	if ((new_sid | pty_wrap) && no_fork)
		errx(EX_USAGE, "session/pty options incompatible with -f");

	if (!(do_exec = no_fork)) {
		if (pty_wrap) {
			pty_wrap_setup(pty_wrap_partial);
			if (pty_filter) {
				r = setenv("TERM", "dumb", 1);
				if (r < 0)
					warn("setenv");
			}
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
				pty_wrap_child(pty_wrap_partial);
			} else if (new_sid) {
				r = setsid();
				if (r < 0)
					err(EX_OSERR, "setsid");
			} else if (new_pgrp && getpgid(0) != getpid()) {
				r = setpgid(0, 0);
				if (r < 0)
					err(EX_OSERR, "setpgid");
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
		pty_wrap_loop(pty_filter);

	r = waitpid(child_pid, &status, 0);
	if (r < 0)
		err(EX_OSERR, "waitpid");
	child_pid = 0;
	/* shell-like exit status */
	exit(WIFSIGNALED(status) ? 128 + WTERMSIG(status) : WEXITSTATUS(status));
}
