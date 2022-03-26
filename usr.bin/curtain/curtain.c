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
	if (dst == NULL)
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

static int
eunsetenv(char *string)
{
	int r;
	r = unsetenv(string);
	if (r < 0)
		err(EX_OSERR, "unsetenv");
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
		} else if (r < 0 || (errno != 0 && errno != ENOTTY)) {
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

#define	DEFAULT_LEVEL 5
/* level 1 usually lets the application at least print an error message */
#define	STRICT_APP_LEVEL 1
#define	LOOSE_APP_LEVEL DEFAULT_LEVEL

int
main(int argc, char *argv[])
{
	enum {
		LONGOPT_NEWPGRP = CHAR_MAX + 1,
		LONGOPT_NEWSID,
		LONGOPT_CHDIR,
		LONGOPT_CHROOT,
		LONGOPT_UNENFORCED,
		LONGOPT_SETENV,
		LONGOPT_UNSETENV,
		LONGOPT_KEEPENV,
		LONGOPT_SETUSER,
		LONGOPT_NO_TTY,
		LONGOPT_NO_TMPDIR,
		LONGOPT_SAME_TMPDIR,
		LONGOPT_PUBLIC_TMPDIR,
		LONGOPT_WRITE_DBUS_ADDRESS,
	};
	const struct option longopts[] = {
		{ "newpgrp", no_argument, NULL, LONGOPT_NEWPGRP },
		{ "newsid", no_argument, NULL, LONGOPT_NEWSID },
		{ "chdir", required_argument, NULL, LONGOPT_CHDIR },
		{ "chroot", required_argument, NULL, LONGOPT_CHROOT },
		{ "unenforced", no_argument, NULL, LONGOPT_UNENFORCED },
		{ "setenv", required_argument, NULL, LONGOPT_SETENV },
		{ "unsetenv", required_argument, NULL, LONGOPT_UNSETENV },
		{ "keepenv", required_argument, NULL, LONGOPT_KEEPENV },
		{ "setuser", required_argument, NULL, LONGOPT_SETUSER },
		{ "no-tty", no_argument, NULL, LONGOPT_NO_TTY },
		{ "no-tmpdir", no_argument, NULL, LONGOPT_NO_TMPDIR },
		{ "same-tmpdir", no_argument, NULL, LONGOPT_SAME_TMPDIR },
		{ "public-tmpdir", no_argument, NULL, LONGOPT_PUBLIC_TMPDIR },
		{ "write-dbus-address", required_argument, NULL, LONGOPT_WRITE_DBUS_ADDRESS },
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
	     new_sid = false,
	     new_pgrp = false,
	     no_network = false,
	     no_tmpdir = false,
	     same_tmpdir = false,
	     public_tmpdir = false,
	     unenforced = false;
	enum { X11_NONE, X11_UNTRUSTED, X11_TRUSTED } x11_mode = X11_NONE;
	bool wayland = false;
	bool dbus = false;
	char *cmd_arg0 = NULL;
	const char *chdir_path = NULL, *chroot_path = NULL;
	const char *setuser_name = NULL;
	const char *write_dbus_address_path = NULL;
	FILE *write_dbus_address_file = NULL;
	char *setenv_base[argc], **setenv_fill = setenv_base;
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

	while ((ch = getopt_long(argc, argv, "+0123456789@:d:vfknaA!t:p:u:0:TRSslUXYWD",
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
			r = curtain_path_str(args_slot, path,
			    ch == 'u' ? CURTAIN_PATH_NOSTAT | CURTAIN_PATH_NOLIST : 0,
			    perms);
			if (r < 0)
				warn("%s", path);
			break;
		}
		case LONGOPT_NO_TTY:
			new_sid = true;
			/* FALLTHROUGH */
		case 'T':
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
		case 'D':
			dbus = true;
			break;
		case LONGOPT_WRITE_DBUS_ADDRESS:
			write_dbus_address_path = optarg;
			break;
		case LONGOPT_NEWPGRP:
			new_pgrp = true;
			break;
		case LONGOPT_NEWSID:
			new_sid = true;
			break;
		case LONGOPT_CHDIR:
			chdir_path = optarg;
			break;
		case LONGOPT_CHROOT:
			chroot_path = optarg;
			break;
		case LONGOPT_SETENV:
		case LONGOPT_UNSETENV:
			*setenv_fill++ = optarg;
			break;
		case LONGOPT_KEEPENV: {
			char *p;
			if ((p = getenv(optarg)) != NULL) {
				r = asprintf(&p, "%s=%s", optarg, p);
				if (r < 0)
					err(EX_TEMPFAIL, "asprintf");
				*setenv_fill++ = p;
			}
			break;
		}
		case LONGOPT_SETUSER:
			user_ctx = true;
			setuser_name = optarg;
			break;
		case LONGOPT_NO_TMPDIR:
			no_tmpdir = true;
			break;
		case LONGOPT_SAME_TMPDIR:
			same_tmpdir = true;
			break;
		case LONGOPT_PUBLIC_TMPDIR:
			public_tmpdir = true;
			break;
		default:
			usage();
		}
	argv += optind;
	argc -= optind;


	if (app_tag) {
		unsafety = MAX(unsafety, app_tag_unsafe ? 1 : 0);
		if (!has_level)
			level = signaling ? STRICT_APP_LEVEL : LOOSE_APP_LEVEL;
	}

	curtain_config_unsafety(cfg, unsafety);
	curtain_config_tags_from_env(cfg, NULL);
	curtain_config_tag_push(cfg, "_default");
	{
		char name[] = "_levelX";
		name[strlen(name) - 1] = '0' + level;
		curtain_config_tag_push(cfg, name);
	}
	if (!signaling) {
		curtain_default(main_slot, CURTAIN_DENY);
		curtain_config_tag_push(cfg, "_loose");
	} else
		curtain_config_tag_push(cfg, "_strict");
	if (no_network) {
		curtain_config_tag_block(cfg, "_network");
		curtain_config_tag_block(cfg, "_net_client");
		curtain_config_tag_block(cfg, "_net_server");
	}
	if (run_shell)
		curtain_config_tag_push(cfg, "_shell");
	if (login_shell)
		curtain_config_tag_push(cfg, "_login_shell");

	if (app_tag && argc != 0) {
		char *p;
		if ((p = strrchr(argv[0], '/')) != NULL)
			p = p + 1;
		else
			p = argv[0];
		curtain_config_tag_push(cfg, p);
	}

	if (no_tmpdir) {
		unsetenv("TMPDIR");
	} else if (!no_fork && !same_tmpdir) {
		r = curtain_config_setup_tmpdir(cfg);
		if (r >= 0 && public_tmpdir) {
			r = chmod(getenv("TMPDIR"), S_ISTXT | ACCESSPERMS);
			if (r < 0)
				warn("chmod %s", getenv("TMPDIR"));
		}
	} else {
		curtain_config_tag_push(cfg, "_shared_tmpdir"); /* XXX not very safe... */
	}
	if (x11_mode != X11_NONE) {
		if (no_fork)
			errx(EX_USAGE, "option -X/-Y incompatible with -f");
		r = curtain_config_setup_x11(cfg, x11_mode == X11_TRUSTED);
		if (r >= 0) {
			curtain_config_tag_push(cfg, "_x11");
			curtain_config_tag_push(cfg,
			    x11_mode == X11_TRUSTED ? "_x11_trusted" : "_x11_untrusted");
		} else
			x11_mode = X11_NONE;
	};
	if (wayland) {
		r = curtain_config_setup_wayland(cfg);
		if (r >= 0) {
			curtain_config_tag_push(cfg, "_wayland");
		} else
			wayland = false;
	}
	if (dbus) {
		if (no_fork)
			errx(EX_USAGE, "option -D incompatible with -f");
		r = curtain_config_setup_dbus(cfg);
		if (r >= 0) {
			curtain_config_tag_push(cfg, "dbus-daemon");
			curtain_config_tag_push(cfg, "_dbus");
			if (write_dbus_address_path != NULL) {
				write_dbus_address_file = fopen(write_dbus_address_path, "we");
				if (write_dbus_address_file == NULL)
					warn("%s", write_dbus_address_path);
			}
		} else
			dbus = false;
	}


	curtain_config_load(cfg);

	r = unenforced ? curtain_apply_soft() : curtain_apply();
	if (r < 0)
		err(EX_NOPERM, "curtain_apply");

	if (dbus) {
		curtain_config_spawn_dbus(cfg);
		if (write_dbus_address_file != NULL) {
			fprintf(write_dbus_address_file, "%s\n", getenv("DBUS_SESSION_BUS_ADDRESS"));
			fclose(write_dbus_address_file);
		}
	}

	curtain_config_free(cfg);


	pw = NULL;

	if (user_ctx) {
		const char *set_home = NULL, *set_shell = NULL,
		      *set_user = NULL, *set_logname = NULL,
		      *set_term = NULL,
		      *set_tmpdir = NULL,
		      *set_display = NULL, *set_xauthority = NULL,
		      *set_wdisplay = NULL,
		      *set_dbus_addr = NULL;
		static char *null_env[] = { NULL };
		extern char **environ;
		unsigned flags;

		if (pw == NULL) {
			errno = 0;
			if (setuser_name != NULL)
				pw = getpwnam(setuser_name);
			else
				pw = getpwuid(getuid());
			if (pw == NULL) {
				if (errno)
					err(EX_OSERR, "getpwuid");
				if (setuser_name != NULL)
					errx(EX_OSERR, "user not found: %s", setuser_name);
			}
		}

		flags = 0;

		if (clean_env) {
			if (login_shell) {
				set_home = pw != NULL ? pw->pw_dir : "/";
				set_shell = pw != NULL && pw->pw_shell != NULL && *pw->pw_shell ?
				    pw->pw_shell : _PATH_BSHELL;
				if (pw->pw_name != NULL)
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
			if (wayland)
				set_wdisplay = getenv("WAYLAND_DISPLAY");
			if (dbus)
				set_dbus_addr = getenv("DBUS_SESSION_BUS_ADDRESS");
			environ = null_env;
			flags |= LOGIN_SETENV | LOGIN_SETPATH;
		}

		if (setuser_name != NULL) {
			flags |= LOGIN_SETUSER | LOGIN_SETGROUP;
			if (login_shell)
				flags |= LOGIN_SETLOGIN;
		}

		r = setusercontext(NULL, pw, pw != NULL ? pw->pw_uid : getuid(), flags);
		if (r < 0)
			err(EX_OSERR, "setusercontext()");

		if (clean_env) {
			if (set_home != NULL)
				esetenv("HOME", set_home, 1);
			if (set_shell != NULL)
				esetenv("SHELL", set_shell, 1);
			if (set_user != NULL)
				esetenv("USER", set_user, 1);
			if (set_logname != NULL)
				esetenv("LOGNAME", set_logname, 1);
			if (set_term != NULL)
				esetenv("TERM", set_term, 1);
			if (set_tmpdir != NULL)
				esetenv("TMPDIR", set_tmpdir, 1);
			if (set_display != NULL)
				esetenv("DISPLAY", set_display, 1);
			if (set_xauthority != NULL)
				esetenv("XAUTHORITY", set_xauthority, 1);
			if (set_wdisplay != NULL)
				esetenv("WAYLAND_DISPLAY", set_wdisplay, 1);
			if (set_dbus_addr != NULL)
				esetenv("DBUS_SESSION_BUS_ADDRESS", set_dbus_addr, 1);
		}
	}

	for (char **setenv_iter = setenv_base; setenv_iter < setenv_fill; setenv_iter++)
		if (strchr(*setenv_iter, '=') != 0)
			eputenv(*setenv_iter);
		else
			eunsetenv(*setenv_iter);
	while (argc != 0 && strchr(*argv, '=') != NULL) {
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
		if (shell == NULL) {
			if (pw == NULL) {
				errno = 0;
				pw = getpwuid(getuid());
				if (pw == NULL && errno != 0)
					err(EX_OSERR, "getpwuid");
			}
			if (pw != NULL && pw->pw_shell != NULL && *pw->pw_shell)
				shell = pw->pw_shell;
			shell = estrdup(shell != NULL ? shell : _PATH_BSHELL);
		}
		sh_argv[0] = shell;
		sh_argv[1] = NULL;
		argv = sh_argv;
		argc = 1;
	}

	if (login_shell) { /* prefix arg0 with "-" */
		char *p, *q;
		q = (p = strrchr(argv[0], '/')) != NULL ? p + 1 : argv[0];
		p = malloc(1 + strlen(q) + 1);
		if (p == NULL)
			err(EX_TEMPFAIL, "malloc");
		p[0] = '-';
		strcpy(p + 1, q);
		cmd_arg0 = p;
	}

	endpwent();
	pw = NULL;

	if (chroot_path != NULL) {
		r = chdir(chroot_path);
		if (r < 0)
			err(EX_OSERR, "chdir %s", chroot_path);
		r = chroot(".");
		if (r < 0)
			err(EX_OSERR, "chroot %s", chroot_path);
	}
	if (chdir_path != NULL) {
		r = chdir(chdir_path);
		if (r < 0)
			err(EX_OSERR, "chdir %s", chdir_path);
	}

	/*
	 * WARNING: The root directory may be untrusted past this point!
	 */

	if (!(do_exec = no_fork)) {
		if (pty_wrap) {
			pty_wrap = pty_wrap_setup(pty_wrap_partial);
			if (!pty_wrap)
				new_sid = true;
		}
		child_pid = 0;
		signal(SIGHUP, forward_signal);
		signal(SIGINT, forward_signal);
		signal(SIGQUIT, forward_signal);
		signal(SIGTERM, forward_signal);
		child_pid = pty_wrap || new_sid ? fork() : vfork();
		if (child_pid < 0)
			err(EX_TEMPFAIL, "fork");
		if ((do_exec = child_pid == 0)) {
			err_set_exit(_exit);
			if (pty_wrap) {
				pty_wrap_child(pty_wrap_partial);
				if (pty_wrap_filter)
					esetenv("TERM", "dumb", 1);
			} else if (new_sid) {
				r = setsid();
				if (r < 0)
					err(EX_OSERR, "setsid");
				unsetenv("TERM");
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
		if (cmd_arg0 != NULL)
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
		if (pty_wrap) {
			if (!pty_wrap_relay(pty_wrap_filter)) {
				restore_tty();
				pty_wrap = false;
			}
		}
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
		} else if (!WIFCONTINUED(status))
			break;
	} while (true);

	if (WIFSIGNALED(status)) {
		warnx("child process %d terminated with signal %d (%s)",
		    child_pid, WTERMSIG(status), strsignal(WTERMSIG(status)));
		exit(128 + WTERMSIG(status)); /* shell-like exit status */
	}
	exit(WEXITSTATUS(status));
}
