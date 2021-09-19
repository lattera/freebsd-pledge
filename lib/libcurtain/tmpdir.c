#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <paths.h>
#include <curtain.h>
#include <sysexits.h>
#include <unistd.h>

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
prepare_tmpdir(struct curtain_config *cfg)
{
	const char *tmpdir;
	char *p;
	int r;
	if (issetugid() || !(tmpdir = getenv("TMPDIR")))
		tmpdir = _PATH_TMP;
	r = asprintf(&p, "%s/%s.tmpdir.XXXXXXXXXXXX", tmpdir, getprogname());
	if (r < 0)
		err(EX_TEMPFAIL, "snprintf");
	new_tmpdir = mkdtemp(p);
	if (!new_tmpdir)
		err(EX_OSERR, "%s", p);
	atexit(cleanup_tmpdir);
	r = setenv("TMPDIR", new_tmpdir, 1);
	if (r < 0)
		err(EX_OSERR, "setenv");
	curtain_config_tag_push(cfg, "_separate_tmpdir");
}

int
curtain_config_tmpdir(struct curtain_config *cfg, bool separate)
{
	if (separate) {
		prepare_tmpdir(cfg);
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
		curtain_config_tag_push(cfg, "_shared_tmpdir");
	}
	return (0);
}
