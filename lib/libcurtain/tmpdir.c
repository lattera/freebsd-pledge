#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <paths.h>
#include <curtain.h>
#include <sysexits.h>
#include <unistd.h>

static void
pathfmt(char *path, const char *fmt, ...)
{
	int r;
	va_list ap;
	va_start(ap, fmt);
	r = vsnprintf(path, PATH_MAX, fmt, ap);
	va_end(ap);
	if (r < 0)
		err(EX_TEMPFAIL, "snprintf");
}

static struct curtain_slot *
get_slot(struct curtain_config *cfg)
{
	struct curtain_slot *slot;
	if (cfg->on_exec)
		curtain_enable((slot = curtain_slot_neutral()), CURTAIN_ON_EXEC);
	else
		slot = curtain_slot();
	return (slot);
}

static void
reprotect_1(struct curtain_slot *slot)
{
	const char *tmpdir, *tmux_tmpdir;
	char path[PATH_MAX];

	/* TODO: This should be moved to a config file. */

	if (!(tmpdir = getenv("TMPDIR")))
		tmpdir = _PATH_TMP;
	pathfmt(path, "%s/krb5cc_%u", tmpdir, geteuid());
	curtain_unveil(slot, path, 0, UPERM_NONE);

	if (!(tmux_tmpdir = getenv("TMUX_TMPDIR")))
		tmux_tmpdir = tmpdir;
	pathfmt(path, "%s/tmux-%u", tmux_tmpdir, geteuid());
	curtain_unveil(slot, path, 0, UPERM_NONE);
}

int
curtain_config_reprotect(struct curtain_config *cfg)
{
	/*
	 * Re-apply another layer of unveils to hide potentially dangerous
	 * files that might allow to escape the sandbox.
	 */
	struct curtain_slot *slot;
	if (!cfg->need_reprotect)
		return (0);
	curtain_unveils_reset_all();
	slot = get_slot(cfg);
	curtain_unveil(slot, "/", 0, UPERM_ALL);
	reprotect_1(slot);
	return (curtain_enforce());
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
prepare_tmpdir(struct curtain_config *cfg)
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
		cfg->need_reprotect = true;
	}
	return (0);
}
