#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <paths.h>
#include <curtain.h>
#include <sysexits.h>
#include <unistd.h>

static struct tmpdir_cleanup {
	struct tmpdir_cleanup *next;
	char path[];
} *tmpdir_cleanups = NULL;

static void
cleanup_tmpdir(void)
{
	struct tmpdir_cleanup *cleanup;
	int r;
	while ((cleanup = tmpdir_cleanups)) {
		r = rmdir(cleanup->path);
		if (r < 0)
			warn("%s", cleanup->path);
		tmpdir_cleanups = cleanup->next;
		free(cleanup);
	}
}

int
curtain_config_setup_tmpdir(struct curtain_config *cfg)
{
	struct tmpdir_cleanup *cleanup;
	const char *tmpdir;
	char *new_tmpdir;
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

	if (!tmpdir_cleanups)
		atexit(cleanup_tmpdir);
	cleanup = malloc(sizeof *cleanup + strlen(new_tmpdir) + 1);
	strcpy(cleanup->path, new_tmpdir);
	free(new_tmpdir);
	cleanup->next = tmpdir_cleanups;
	tmpdir_cleanups = cleanup;

	r = setenv("TMPDIR", cleanup->path, 1);
	if (r < 0)
		err(EX_OSERR, "setenv");
	curtain_config_tag_push(cfg, "_separate_tmpdir");
	return (0);
}
