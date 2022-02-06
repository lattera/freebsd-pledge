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

int
curtain_config_setup_tmpdir(struct curtain_config *cfg)
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
	return (0);
}
