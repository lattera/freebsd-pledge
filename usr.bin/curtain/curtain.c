#include <assert.h>
#include <curtain.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libutil.h>
#include <limits.h>
#include <locale.h>
#include <login_cap.h>
#include <getopt.h>
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

static char *
estrdup(const char *src)
{
	char *dst;
	dst = strdup(src);
	if (!dst)
		err(EX_TEMPFAIL, "strdup");
	return (dst);
}

static int
esetenv(const char *name, const char *value, int overwrite)
{
	int r;
	r = setenv(name, value, overwrite);
	if (r < 0)
		err(EX_OSERR, "setenv");
	return (r);
}

static int
eputenv(char *string)
{
	int r;
	r = putenv(string);
	if (r < 0)
		err(EX_OSERR, "putenv");
	return (r);
}


static struct termios tty_saved_termios;
static bool tty_made_raw;
static int pty_outer_read_fd, pty_outer_write_fd, pty_outer_ioctl_fd;
static int pty_master_fd, pty_slave_fd;

static void
restore_tty()
{
	int r;
	if (pty_outer_ioctl_fd >= 0 && tty_made_raw) {
		r = tcsetattr(pty_outer_ioctl_fd, TCSADRAIN, &tty_saved_termios);
		if (r < 0)
			warn("tcsetattr");
	}
}

static void
handle_sigwinch(int sig __unused)
{
	int r;
	struct winsize ws;
	if (pty_outer_ioctl_fd >= 0 && pty_master_fd >= 0) {
		r = ioctl(pty_outer_ioctl_fd, TIOCGWINSZ, &ws);
		if (r >= 0)
			r = ioctl(pty_master_fd, TIOCSWINSZ, &ws);
		if (r < 0)
			warn("ioctl");
	}
}

#define	PTY_WRAP_FDS 3
static bool pty_bypass_fds[PTY_WRAP_FDS], pty_bypass_any;

static bool
pty_wrap_setup(bool partial)
{
	bool has_tt, has_ws;
	struct termios tt;
	struct winsize ws;
	int r;

	if (partial) {
		pty_outer_read_fd = -1;
		pty_outer_write_fd = -1;
	} else {
		pty_outer_read_fd = STDIN_FILENO;
		pty_outer_write_fd = STDOUT_FILENO;
	}
	pty_outer_ioctl_fd = -1;

	pty_bypass_any = false;
	for (int fd = 0; fd < PTY_WRAP_FDS; fd++) {
		pty_bypass_fds[fd] = false;
		errno = 0;
		r = isatty(fd);
		if (r > 0) {
			pty_bypass_fds[fd] = false;
			if (pty_outer_ioctl_fd < 0)
				pty_outer_ioctl_fd = fd;
			if (pty_outer_read_fd < 0 &&
			    fd == STDIN_FILENO)
				pty_outer_read_fd = fd;
			if (pty_outer_write_fd < 0 &&
			    (fd == STDOUT_FILENO || fd == STDERR_FILENO))
				pty_outer_write_fd = fd;
		} else if (r < 0 || (errno && errno != ENOTTY)) {
			warn("isatty(%i)", fd);
			pty_bypass_fds[fd] = false;
		} else {
			if ((pty_bypass_fds[fd] = partial))
				pty_bypass_any = true;
		}
	}
	if (pty_outer_ioctl_fd < 0 && partial)
		return (false);
	if (pty_outer_read_fd < 0)
		pty_outer_read_fd = pty_outer_ioctl_fd;
	if (pty_outer_write_fd < 0)
		pty_outer_write_fd = pty_outer_ioctl_fd;

	if (pty_outer_ioctl_fd >= 0) {
		r = tcgetattr(pty_outer_ioctl_fd, &tt);
		if (!(has_tt = r >= 0))
			warn("tcgetattr");
		r = ioctl(pty_outer_ioctl_fd, TIOCGWINSZ, &ws);
		if (!(has_ws = r >= 0))
			warn("ioctl");
	} else
		has_tt = has_ws = false;

	r = openpty(&pty_master_fd, &pty_slave_fd, NULL,
	    has_tt ? &tt : NULL, has_ws ? &ws : NULL);
	if (r < 0)
		err(EX_OSERR, "openpty");

	tty_made_raw = false;
	if (has_tt && !pty_bypass_any &&
	    tcgetpgrp(pty_outer_ioctl_fd) == getpgrp()) {
		tty_saved_termios = tt;
		atexit(restore_tty);
		cfmakeraw(&tt);
		r = tcsetattr(pty_outer_ioctl_fd, TCSAFLUSH, &tt);
		if (r < 0)
			warn("tcsetattr");
		else
			tty_made_raw = true;
	}
	if (has_ws)
		signal(SIGWINCH, handle_sigwinch);

	return (true);
}

static void
pty_wrap_parent(void)
{
	close(pty_slave_fd);
}

static void
pty_wrap_child(bool partial)
{
	int r;
	close(pty_master_fd);
	if (partial) {
		pid_t sid;
		sid = setsid();
		if (sid < 0)
			err(EX_OSERR, "setsid");
		if (tcsetsid(pty_slave_fd, sid) < 0)
			err(EX_OSERR, "tcsetsid");
		for (int fd = 0; fd < PTY_WRAP_FDS; fd++)
			if (!pty_bypass_fds[fd]) {
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
pty_suspend(int sig)
{
	struct termios tt;
	bool has_tt;
	int r;
	if (tty_made_raw) {
		r = tcgetattr(pty_outer_ioctl_fd, &tt);
		if ((has_tt = r >= 0)) {
			r = tcsetattr(pty_outer_ioctl_fd, TCSADRAIN, &tty_saved_termios);
			if (r < 0)
				warn("tcsetattr");
		} else
			warn("tcgetattr");
	}
	r = kill(getpid(), sig);
	if (r < 0)
		warn("kill");
	if (tty_made_raw && has_tt) {
		r = tcsetattr(pty_outer_ioctl_fd, TCSADRAIN, &tt);
		if (r < 0)
			warn("tcsetattr");
	}
}

static bool
pty_wrap_relay(bool filter)
{
	char buf[1024], visbuf[filter ? (sizeof buf) * 4 + 1 : 0];
	struct pollfd pfds[2];
	int pfdc, r, i;
	pfdc = 0;
	if (pty_outer_read_fd >= 0 && pty_master_fd >= 0)
		pfds[pfdc++] = (struct pollfd){
			.fd = pty_outer_read_fd, .events = POLLIN
		};
	if (pty_master_fd >= 0 && pty_outer_write_fd >= 0)
		pfds[pfdc++] = (struct pollfd){
			.fd = pty_master_fd, .events = POLLIN
		};
	if (!pfdc)
		return (false);
	r = poll(pfds, pfdc, INFTIM);
	if (r <= 0) {
		if (r < 0 && errno != EINTR)
			err(EX_OSERR, "poll");
		return (true);
	}
	for (i = 0; i < pfdc; i++) {
		if (pfds[i].revents & POLLNVAL)
			errx(EX_OSERR, "poll POLLNVAL");
		if (!(pfds[i].revents & (POLLIN|POLLHUP|POLLERR)))
			continue;
		if (pfds[i].fd == pty_outer_read_fd) {
			r = read(pty_outer_read_fd, buf, sizeof buf);
			if (r < 0)
				err(EX_IOERR, "read");
			if (r == 0) {
				close(pty_master_fd);
				pty_master_fd = -1;
				return (false);
			}
			r = write(pty_master_fd, buf, r);
			if (r < 0)
				err(EX_IOERR, "write");
		} else if (pfds[i].fd == pty_master_fd) {
			r = read(pty_master_fd, buf, sizeof buf);
			if (r < 0)
				err(EX_IOERR, "read");
			if (r == 0)
				return (false);
			if (filter) {
				r = strnvisx(visbuf, sizeof visbuf, buf, r,
				    VIS_SAFE | VIS_NOSLASH);
				if (r < 0)
					err(EX_IOERR, "strnvisx");
			}
			r = write(pty_outer_write_fd, filter ? visbuf : buf, r);
			if (r < 0)
				err(EX_IOERR, "write");
		}
	}
	return (true);
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


static pid_t child_pid;

static void
forward_signal(int sig)
{
	assert(child_pid >= 0);
	if (child_pid > 0)
		kill(child_pid, sig);
}

static void
interrupt_signal(int sig __unused)
{
}

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-vfknaAXYW] "
	    "[-t tag] [-p path[:perms]] "
	    "[-Ssl] [name=value ...] cmd [arg ...]\n",
	    getprogname());
	exit(EX_USAGE);
}

#define	DEFAULT_LEVEL 3
#define	APP_TAG_LEVEL 1 /* usually lets the application print an error message */

int
main(int argc, char *argv[])
{
	enum {
		LONGOPT_NEWPGRP = CHAR_MAX + 1,
		LONGOPT_NEWSID,
		LONGOPT_CHROOT,
		LONGOPT_UNENFORCED,
		LONGOPT_SETUSER,
	};
	const struct option longopts[] = {
		{ "newpgrp", no_argument, NULL, LONGOPT_NEWPGRP },
		{ "newsid", no_argument, NULL, LONGOPT_NEWSID },
		{ "chroot", required_argument, NULL, LONGOPT_CHROOT },
		{ "unenforced", no_argument, NULL, LONGOPT_UNENFORCED },
		{ "setuser", required_argument, NULL, LONGOPT_SETUSER },
		{ 0 }
	};
	char *sh_argv[2];
	int ch, r;
	unsigned unsafety = 0;
	unsigned level = DEFAULT_LEVEL;
	bool has_level = false,
	     app_tag = false,
	     app_tag_unsafe = false,
	     signaling = false,
	     no_fork = false,
	     run_shell = false,
	     login_shell = false,
	     pty_wrap = true,
	     pty_wrap_partial = true,
	     pty_wrap_filter = true,
	     user_ctx = false,
	     clean_env = false,
	     new_sid = true,
	     new_pgrp = false,
	     no_network = false,
	     unenforced = false;
	enum { X11_NONE, X11_UNTRUSTED, X11_TRUSTED } x11_mode = X11_NONE;
	bool wayland = false;
	char *cmd_arg0 = NULL;
	const char *chroot_path = NULL;
	const char *setuser_name = NULL;
	char abspath[PATH_MAX];
	size_t abspath_len = 0;
	struct curtain_config *cfg;
	struct curtain_slot *main_slot, *args_slot;
	struct passwd *pw;
	bool do_exec;
	int status;

	init_harden();

	setlocale(LC_ALL, "");

	cfg = curtain_config_new(CURTAIN_CONFIG_ON_EXEC_ONLY);

	curtain_enable((main_slot = curtain_slot_neutral()), CURTAIN_ON_EXEC);
	curtain_enable((args_slot = curtain_slot_neutral()), CURTAIN_ON_EXEC);

	while ((ch = getopt_long(argc, argv, "+0123456789@:d:vfknaA!t:p:u:0:TRSslUXYW",
	    longopts, NULL)) != -1)
		switch (ch) {
		case '0' ... '9':
			level = ch - '0';
			has_level = true;
			break;
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
		case 'A':
			app_tag_unsafe = true;
			/* FALLTHROUGH */
		case 'a':
			app_tag = true;
			break;
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
		case 'u':
		case 'p': {
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
			    ch == 'p' ? CURTAIN_UNVEIL_INSPECT | CURTAIN_UNVEIL_LIST : 0,
			    uperms);
			if (r < 0 && errno != ENOENT)
				warn("%s", path);
			break;
		}
		case 'T':
			new_sid = false;
			pty_wrap = false;
			pty_wrap_partial = false;
			break;
		case 'R':
			pty_wrap_filter = false;
			break;
		case 'l':
			login_shell = true;
			/* FALLTHROUGH */
		case 'S':
			user_ctx = true;
			clean_env = true;
			new_sid = true;
			pty_wrap = true;
			pty_wrap_partial = false;
			/* FALLTHROUGH */
		case 's':
			run_shell = true;
			break;
		case 'f':
			no_fork = true;
			break;
		case LONGOPT_UNENFORCED:
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
		case LONGOPT_NEWPGRP:
			new_pgrp = true;
			break;
		case LONGOPT_NEWSID:
			new_sid = true;
			break;
		case LONGOPT_CHROOT:
			chroot_path = optarg;
			break;
		case LONGOPT_SETUSER:
			user_ctx = true;
			setuser_name = optarg;
			break;
		default:
			usage();
		}
	argv += optind;
	argc -= optind;


	if (app_tag) {
		unsafety = MAX(unsafety, app_tag_unsafe ? 1 : 0);
		if (!has_level)
			level = APP_TAG_LEVEL;
	}

	curtain_config_unsafety(cfg, unsafety);
	curtain_config_tags_from_env(cfg, NULL);
	curtain_config_tag_push(cfg, "_default");
	{
		char name[] = "_levelX";
		name[strlen(name) - 1] = '0' + level;
		curtain_config_tag_push(cfg, name);
	}
	if (!signaling)
		curtain_default(main_slot, CURTAIN_DENY);
	if (no_network)
		curtain_config_tag_block(cfg, "_network");
	if (new_sid)
		curtain_config_tag_push(cfg, "_newsid");
	if (run_shell)
		curtain_config_tag_push(cfg, "_shell");
	if (login_shell)
		curtain_config_tag_push(cfg, "_login_shell");
	if (new_pgrp)
		curtain_config_tag_push(cfg, "_newpgrp");

	if (app_tag && argc) {
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

	r = unenforced ? curtain_apply_soft() : curtain_apply();
	if (r < 0)
		err(EX_NOPERM, "curtain_apply");


	pw = NULL;

	if (user_ctx) {
		const char *set_home = NULL, *set_shell = NULL,
		      *set_user = NULL, *set_logname = NULL,
		      *set_term = NULL,
		      *set_tmpdir = NULL,
		      *set_display = NULL, *set_xauthority = NULL,
		      *set_wdisplay = NULL;
		static char *null_env[] = { NULL };
		extern char **environ;
		unsigned flags;

		if (!pw) {
			errno = 0;
			if (setuser_name)
				pw = getpwnam(setuser_name);
			else
				pw = getpwuid(getuid());
			if (!pw) {
				if (errno)
					err(EX_OSERR, "getpwuid");
				if (setuser_name)
					errx(EX_OSERR, "user not found: %s", setuser_name);
			}
		}

		flags = 0;

		if (clean_env) {
			if (login_shell) {
				set_home = pw ? pw->pw_dir : "/";
				set_shell = pw && pw->pw_shell && *pw->pw_shell ?
				    pw->pw_shell : _PATH_BSHELL;
				if (pw->pw_name)
					set_user = set_logname = pw->pw_name;
			} else {
				set_home = getenv("HOME");
				set_shell = getenv("SHELL");
				set_user = getenv("USER");
				set_logname = getenv("LOGNAME");
			}
			set_term = getenv("TERM");
			set_tmpdir = getenv("TMPDIR");
			if (x11_mode != X11_NONE) {
				set_display = getenv("DISPLAY");
				set_xauthority = getenv("XAUTHORITY");
			}
			if (wayland) {
				set_wdisplay = getenv("WAYLAND_DISPLAY");
			}

			environ = null_env;

			flags |= LOGIN_SETENV | LOGIN_SETPATH;
		}

		if (setuser_name) {
			flags |= LOGIN_SETUSER | LOGIN_SETGROUP;
			if (login_shell)
				flags |= LOGIN_SETLOGIN;
		}

		r = setusercontext(NULL, pw, pw ? pw->pw_uid : getuid(), flags);
		if (r < 0)
			err(EX_OSERR, "setusercontext()");

		if (clean_env) {
			if (set_home)
				esetenv("HOME", set_home, 1);
			if (set_shell)
				esetenv("SHELL", set_shell, 1);
			if (set_user)
				esetenv("USER", set_user, 1);
			if (set_logname)
				esetenv("LOGNAME", set_logname, 1);
			if (set_term)
				esetenv("TERM", set_term, 1);
			if (set_tmpdir)
				esetenv("TMPDIR", set_tmpdir, 1);
			if (set_display)
				esetenv("DISPLAY", set_display, 1);
			if (set_xauthority)
				esetenv("XAUTHORITY", set_xauthority, 1);
			if (set_wdisplay)
				esetenv("WAYLAND_DISPLAY", set_wdisplay, 1);
		}
	}

	while (argc && strchr(*argv, '=')) {
		eputenv(*argv);
		argc--, argv++;
	}

	/*
	 * WARNING: $HOME may now point to an untrusted directory!
	 */

	if (!argc) {
		char *shell;
		if (!run_shell)
			usage();
		shell = getenv("SHELL");
		if (!shell) {
			if (!pw) {
				errno = 0;
				pw = getpwuid(getuid());
				if (!pw && errno)
					err(EX_OSERR, "getpwuid");
			}
			if (pw && pw->pw_shell && *pw->pw_shell)
				shell = pw->pw_shell;
			shell = estrdup(shell ? shell : _PATH_BSHELL);
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

	endpwent();
	pw = NULL;

	if (chroot_path) {
		r = chdir(chroot_path);
		if (r < 0)
			err(EX_OSERR, "chdir %s", chroot_path);
		r = chroot(".");
		if (r < 0)
			err(EX_OSERR, "chroot %s", chroot_path);
	}

	/*
	 * WARNING: The root directory may be untrusted past this point!
	 */

	if (!(do_exec = no_fork)) {
		if (pty_wrap) {
			pty_wrap = pty_wrap_setup(pty_wrap_partial);
			if (!pty_wrap) { /* NOTE: new_sid might still be set */
				unsetenv("TERM");
			} else if (pty_wrap_filter) {
				esetenv("TERM", "dumb", 1);
			}
		}
		child_pid = 0;
		signal(SIGHUP, forward_signal);
		signal(SIGINT, forward_signal);
		signal(SIGQUIT, forward_signal);
		signal(SIGTERM, forward_signal);
		child_pid = pty_wrap ? fork() : vfork();
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
				pty_wrap_parent();
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

	if (pty_wrap) {
		signal(SIGCHLD, interrupt_signal);
		if (tty_made_raw) {
			signal(SIGTSTP, forward_signal);
			signal(SIGCONT, forward_signal);
		}
	}
	do {
		pid_t pid;
		if (pty_wrap)
			pty_wrap = pty_wrap_relay(pty_wrap_filter);
		pid = waitpid(child_pid, &status,
		    pty_wrap ? (tty_made_raw ? WSTOPPED : 0) | WNOHANG : 0);
		if (pid <= 0) {
			if (pid < 0 && errno != EINTR)
				err(EX_OSERR, "waitpid");
			continue;
		}
		assert(pid == child_pid);
		if (WIFSTOPPED(status)) {
			if (pty_wrap && tty_made_raw) {
				signal(SIGTSTP, SIG_DFL);
				pty_suspend(SIGTSTP);
				signal(SIGTSTP, forward_signal);
			}
		} else if (!WIFCONTINUED(status)) {
			child_pid = 0;
			break;
		}
	} while (true);

	/* shell-like exit status */
	exit(WIFSIGNALED(status) ? 128 + WTERMSIG(status) : WEXITSTATUS(status));
}
