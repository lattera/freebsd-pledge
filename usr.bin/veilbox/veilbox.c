#include <err.h>
#include <limits.h>
#include <paths.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sysexits.h>
#include <unistd.h>

/*
 * Creating a "blind" directory for the new TMPDIR.  Since secure usage of
 * TMPDIR generally requires using unpredictable filenames, this should help
 * prevent different sandboxed applications from interfering with each others.
 *
 * This is (hopefully) better than nothing, but probably still risky.
 */
static const mode_t tmpdir_mode = S_IWUSR|S_IXUSR;

static const char *default_promises =
    "stdio "
    "thread "
    "rlimit "
    "rpath wpath cpath dpath tmppath "
    "exec prot_exec "
    "flock fattr chown id "
    "proc_child ps_child "
    "tty "
    "posixrt "
    "unix recvfd sendfd ";

static const char *pgrp_promises = "proc_pgrp ps_pgrp";

static const char *shell_promises = "proc_session ps_session";

static const char *network_promises = "ssl dns inet";

static const char *error_promises = "error sigtrap";

struct unveil_entry {
	const char *path;
	const char perms[8];
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
	{ "/usr/share", "rx" },
	{ _PATH_LOCALBASE "/share", "rx" },
};

static const size_t default_unveils_count =
    sizeof default_unveils / sizeof *default_unveils;


static void
usage(void)
{
	fprintf(stderr, "usage: %s [-kg] [-p promises] [-u unveil ...] [-sS] cmd [arg ...]\n", getprogname());
	exit(EX_USAGE);
}

static void
new_tmpdir()
{
	const char *tmpdir;
	char newtmpdir[PATH_MAX];
	struct stat st;
	uid_t uid;
	int r;
	uid = geteuid();
	if (!(tmpdir = getenv("TMPDIR")))
		tmpdir = _PATH_TMP;
	r = snprintf(newtmpdir, sizeof newtmpdir,
	    "%s/veilbox-%ju", tmpdir, (uintmax_t)uid);
	if (r < 0)
		err(EX_SOFTWARE, "snprintf");
	if ((size_t)r >= sizeof newtmpdir)
		errx(EX_OSFILE, "new TMPDIR too long");
	r = mkdir(newtmpdir, tmpdir_mode);
	if (r < 0 && errno != EEXIST)
		warn("%s", newtmpdir);
	r = lstat(newtmpdir, &st);
	if (r < 0)
		err(EX_OSERR, "%s", newtmpdir);
	if (!S_ISDIR(st.st_mode))
		errc(EX_OSFILE, ENOTDIR, "%s", newtmpdir);
	if (st.st_uid != uid)
		errx(EX_OSFILE, "new TMPDIR owned by wrong user (%ju): %s",
		    (uintmax_t)st.st_uid, newtmpdir);
	r = chmod(newtmpdir, tmpdir_mode);
	if (r < 0)
		err(EX_OSERR, "%s", newtmpdir);
	r = setenv("TMPDIR", newtmpdir, 1);
	if (r < 0)
		err(EX_OSERR, "setenv");
}

static void
preexec_cleanup(void)
{
	closefrom(3); /* Prevent potentially unintended FD passing. */
}

static void
exec_shell(bool login_shell)
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

	preexec_cleanup();
	execlp(run, name, (char *)NULL);
	err(EX_OSERR, "%s", run);
}

int
main(int argc, char *argv[])
{
	int ch, r;
	char promises[1024] = "";
	bool signaling = false,
	     run_shell = false,
	     login_shell = false,
	     new_pgrp = false;
	char *cmd_arg0 = NULL;
	char abspath[PATH_MAX];
	size_t abspath_len = 0;

	strlcat(promises, " ", sizeof promises);
	strlcat(promises, default_promises, sizeof promises);
	strlcat(promises, " ", sizeof promises);
	strlcat(promises, network_promises, sizeof promises);

	const struct unveil_entry *entry;
	for (entry = default_unveils;
	    entry != &default_unveils[default_unveils_count];
	    entry++) {
		r = unveilexec(entry->path, entry->perms);
		if (r < 0)
			err(EX_OSERR, "%s", entry->path);
	}

	while ((ch = getopt(argc, argv, "kgp:u:0:sS")) != -1)
		switch (ch) {
		case 'k':
			signaling = true;
			break;
		case 'g':
			  new_pgrp = true;
			  break;
		case 'p': {
			char *p;
			for (p = optarg; *p; p++)
				if (*p == ',')
					*p = ' ';
			strlcat(promises, " ", sizeof promises);
			strlcat(promises, optarg, sizeof promises);
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
			r = unveilexec(path, perms);
			if (r < 0)
				err(EX_OSERR, "%s", optarg);
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
		default:
			usage();
		}
	argv += optind;
	argc -= optind;

	if (run_shell == (argc != 0))
		usage();

	new_tmpdir();

	if (!signaling) {
		strlcat(promises, " ", sizeof promises);
		strlcat(promises, error_promises, sizeof promises);
	}
	if (run_shell) {
		strlcat(promises, " ", sizeof promises);
		strlcat(promises, shell_promises, sizeof promises);
	}
	if (new_pgrp) {
		strlcat(promises, " ", sizeof promises);
		strlcat(promises, pgrp_promises, sizeof promises);
		if (getpgid(0) != getpid()) {
			r = setpgid(0, 0);
			if (r < 0)
				err(EX_OSERR, "setpgid");
		}
	}

	r = pledge(NULL, promises);
	if (r < 0)
		err(EX_NOPERM, "pledge");

	if (run_shell) {
		exec_shell(login_shell);

	} else {
		char *cmd_name;
		cmd_name = argv[0];
		if (cmd_arg0)
			argv[0] = cmd_arg0;
		preexec_cleanup();
		execvp(cmd_name, argv);
		err(EX_OSERR, "%s", cmd_name);
	}
}
