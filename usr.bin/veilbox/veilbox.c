#include <err.h>
#include <limits.h>
#include <paths.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <unistd.h>

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-p promises] [-u unveil ...] cmd [arg ...]\n", getprogname());
	exit(EX_USAGE);
}

/*
 * Creating a "blind" directory for the new TMPDIR.  Since secure usage of
 * TMPDIR generally requires using unpredictable filenames, this should help
 * prevent different sandboxed applications from interfering with each others.
 *
 * This is (hopefully) better than nothing, but probably still risky.
 */
static const mode_t tmpdir_mode = S_IWUSR|S_IXUSR;

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

struct unveil_entry {
	const char *path;
	const char perms[8];
};

static const char *default_promises =
    "error capsicum stdio "
    "rpath wpath cpath dpath tmppath exec "
    "flock fattr chown id "
    "proc thread "
    "tty "
    "dns inet unix";

static const struct unveil_entry default_unveils[] = {
	{ "/dev/fd", "rwc" }, /* not included by "stdio" */
	{ "/lib", "rx" },
	{ "/usr/lib", "rx" },
	{ "/usr/local/lib", "rx" },
	{ "/libexec", "rx" },
	{ "/usr/libexec", "rx" },
	{ "/bin", "rx" },
	{ "/sbin", "rx" },
	{ "/usr/bin", "rx" },
	{ "/usr/sbin", "rx" },
	{ "/usr/local/bin", "rx" },
	{ "/usr/local/sbin", "rx" },
	{ "/usr/share", "rx" },
	{ "/usr/local/share", "rx" },
};

static const size_t default_unveils_count =
    sizeof default_unveils / sizeof *default_unveils;

int
main(int argc, char *argv[])
{
	int ch, r;
	char promises[1024];

	strlcat(promises, default_promises, sizeof promises);

	const struct unveil_entry *entry;
	for (entry = default_unveils;
	    entry != &default_unveils[default_unveils_count];
	    entry++) {
		r = unveilexec(entry->path, entry->perms);
		if (r < 0)
			err(EX_OSERR, "%s", entry->path);
	}

	while ((ch = getopt(argc, argv, "p:u:")) != -1)
		switch (ch) {
		case 'p': {
			char *p;
			for (p = optarg; *p; p++)
				if (*p == ',')
					*p = ' ';
			strlcat(promises, optarg, sizeof promises);
			break;
		}
		case 'u': {
			char *perms;
			if ((perms = strrchr(optarg, ':')))
				*perms++ = '\0';
			else
				perms = __DECONST(char *, "rx");
			r = unveilexec(optarg, perms);
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

	new_tmpdir();

	r = pledge(NULL, promises);
	if (r < 0)
		err(EX_NOPERM, "pledge");

	execvp(argv[0], argv);
	err(EX_OSERR, "execvp");
}
