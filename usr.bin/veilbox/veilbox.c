#include <err.h>
#include <limits.h>
#include <paths.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/stat.h>
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
    "rlimit "
    "rpath wpath cpath dpath tmppath "
    "exec prot_exec "
    "flock fattr chown id "
    "proc_session thread "
    "tty "
    "unix recvfd sendfd ";

static const char *network_promises = "ssl dns inet";

static const char *error_promises = "error sigtrap";

struct unveil_entry {
	const char *path;
	const char perms[8];
};

static const struct unveil_entry default_unveils[] = {
	{ _PATH_DEV "/fd", "rwc" },
	{ _PATH_DEV "/stdin", "r" },
	{ _PATH_DEV "/stdout", "rwc" },
	{ _PATH_DEV "/stderr", "rwc" },
	{ _PATH_DEV "/full", "rwc" },
	{ _PATH_DEV "/zero", "rwc" },
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
	fprintf(stderr, "usage: %s [-s] [-p promises] [-u unveil ...] cmd [arg ...]\n", getprogname());
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
	mkdir(newtmpdir, tmpdir_mode);
	r = lstat(newtmpdir, &st);
	if (r < 0)
		err(EX_OSERR, "%s", newtmpdir);
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


int
main(int argc, char *argv[])
{
	int ch, r;
	char promises[1024] = "";
	bool signaling = false;
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

	while ((ch = getopt(argc, argv, "sp:u:")) != -1)
		switch (ch) {
		case 's':
			signaling = true;
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
		default:
			usage();
		}
	argv += optind;
	argc -= optind;

	if (!argc)
		usage();

	closefrom(3); /* Prevent potentially unintended FD passing. */

	new_tmpdir();

	if (!signaling) {
		strlcat(promises, " ", sizeof promises);
		strlcat(promises, error_promises, sizeof promises);
	}

	r = pledge(NULL, promises);
	if (r < 0)
		err(EX_NOPERM, "pledge");

	execvp(argv[0], argv);
	err(EX_OSERR, "execvp");
}
