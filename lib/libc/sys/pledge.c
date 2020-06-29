#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/_sysfil.h>
#include <sys/procctl.h>
#include <sys/unveil.h>
#include <sysexits.h>
#include <unistd.h>

enum promise_type {
	PROMISE_NONE = 0,
	PROMISE_ERROR,
	PROMISE_CAPSICUM,
	PROMISE_BASIC, /* same as PROMISE_STDIO but without the unveils */
	PROMISE_STDIO,
	PROMISE_UNVEIL,
	PROMISE_RPATH,
	PROMISE_WPATH,
	PROMISE_CPATH,
	PROMISE_DPATH,
	PROMISE_TMPPATH,
	PROMISE_FLOCK,
	PROMISE_FATTR,
	PROMISE_CHOWN,
	PROMISE_ID,
	PROMISE_PROC,
	PROMISE_THREAD,
	PROMISE_EXEC,
	PROMISE_TTY,
	PROMISE_SETTIME,
	PROMISE_INET,
	PROMISE_UNIX,
	PROMISE_DNS,
	PROMISE_GETPW,
	PROMISE_COUNT /* must be last */
};


struct promise_name {
	const char name[12];
	enum promise_type type;
};

static const struct promise_name promise_names[] = {
	{ "error",	PROMISE_ERROR },
	{ "capsicum",	PROMISE_CAPSICUM },
	{ "basic",	PROMISE_BASIC },
	{ "stdio",	PROMISE_STDIO },
	{ "unveil",	PROMISE_UNVEIL },
	{ "rpath",	PROMISE_RPATH },
	{ "wpath",	PROMISE_WPATH },
	{ "cpath",	PROMISE_CPATH },
	{ "dpath",	PROMISE_DPATH },
	{ "tmppath",	PROMISE_TMPPATH },
	{ "flock",	PROMISE_FLOCK },
	{ "fattr",	PROMISE_FATTR },
	{ "chown",	PROMISE_CHOWN },
	{ "id",		PROMISE_ID },
	{ "proc",	PROMISE_PROC },
	{ "thread",	PROMISE_THREAD },
	{ "exec",	PROMISE_EXEC },
	{ "tty",	PROMISE_TTY },
	{ "settime",	PROMISE_SETTIME },
	{ "inet",	PROMISE_INET },
	{ "unix",	PROMISE_UNIX },
	{ "dns",	PROMISE_DNS },
	{ "getpw",	PROMISE_GETPW },
	{ "",		PROMISE_NONE },
};

static const sysfil_t promise_sysfils[PROMISE_COUNT] = {
	/*
	 * Note that SYF_PLEDGE_UNVEIL and SYF_PLEDGE_?PATH/SYF_PLEDGE_EXEC are
	 * automatially added if required by the promise's unveils (and removed
	 * once they no longer are).
	 */
	[PROMISE_ERROR] = SYF_PLEDGE_ERROR,
	[PROMISE_CAPSICUM] = SYF_CAPENABLED,
	[PROMISE_BASIC] = SYF_PLEDGE_STDIO,
	[PROMISE_STDIO] = SYF_PLEDGE_STDIO,
	[PROMISE_UNVEIL] = SYF_PLEDGE_UNVEIL,
	[PROMISE_RPATH] = SYF_PLEDGE_RPATH,
	[PROMISE_WPATH] = SYF_PLEDGE_WPATH,
	[PROMISE_CPATH] = SYF_PLEDGE_CPATH,
	[PROMISE_DPATH] = SYF_PLEDGE_DPATH,
	[PROMISE_FLOCK] = SYF_PLEDGE_FLOCK,
	[PROMISE_FATTR] = SYF_PLEDGE_FATTR,
	[PROMISE_CHOWN] = SYF_PLEDGE_CHOWN,
	[PROMISE_ID] = SYF_PLEDGE_ID,
	[PROMISE_PROC] = SYF_PLEDGE_PROC,
	[PROMISE_THREAD] = SYF_PLEDGE_THREAD,
	[PROMISE_EXEC] = SYF_PLEDGE_EXEC,
	[PROMISE_TTY] = SYF_PLEDGE_TTY,
	[PROMISE_SETTIME] = SYF_PLEDGE_SETTIME,
	[PROMISE_INET] = SYF_PLEDGE_INET,
	[PROMISE_UNIX] = SYF_PLEDGE_UNIX,
	[PROMISE_DNS] = SYF_PLEDGE_DNS,
};

static const char *const root_path = "/";
static const char *const tmp_path = _PATH_TMP;

static bool promise_unveils_sorted = false;

struct promise_unveil {
	const char *path;
	unveil_perms_t perms;
	enum promise_type type;
};

#define	R UNVEIL_PERM_RPATH
#define	W UNVEIL_PERM_WPATH
#define	C UNVEIL_PERM_CPATH
#define	X UNVEIL_PERM_XPATH

static struct promise_unveil promise_unveils[] = {
	{ root_path, R,				PROMISE_RPATH },
	{ root_path, W,				PROMISE_WPATH },
	{ root_path, C,				PROMISE_CPATH },
	{ root_path, X,				PROMISE_EXEC },
	{ "/etc/malloc.conf", R,		PROMISE_STDIO },
	{ "/etc/libmap.conf", R,		PROMISE_STDIO },
	{ "/var/run/ld-elf.so.hints", R,	PROMISE_STDIO },
	{ "/etc/localtime", R,			PROMISE_STDIO },
	{ "/usr/share/zoneinfo/", R,		PROMISE_STDIO },
	{ "/usr/share/nls/", R,			PROMISE_STDIO },
	{ "/usr/local/share/nls/", R,		PROMISE_STDIO },
	/* Programs will often open /dev/null with O_CREAT.  TODO: Could have a
	 * different unveil() permission just for that. */
	{ "/dev/null", R|W|C,			PROMISE_STDIO },
	{ "/dev/random", R,			PROMISE_STDIO },
	{ "/dev/urandom", R,			PROMISE_STDIO },
	/* XXX: Review /dev/crypto for safety. */
	{ "/dev/crypto", W,			PROMISE_STDIO },
	{ "/etc/nsswitch.conf", R,		PROMISE_DNS },
	{ "/etc/resolv.conf", R,		PROMISE_DNS },
	{ "/etc/hosts", R,			PROMISE_DNS },
	{ "/etc/services", R,			PROMISE_DNS },
	{ "/var/db/services.db", R,		PROMISE_DNS },
	{ "/etc/protocols", R,			PROMISE_DNS },
	{ "/dev/tty", R|W,			PROMISE_TTY },
	{ "/etc/nsswitch.conf", R,		PROMISE_GETPW },
	{ "/etc/pwd.db", R,			PROMISE_GETPW },
	{ "/etc/spwd.db", R,			PROMISE_GETPW },
	{ "/etc/group", R,			PROMISE_GETPW },
	/* TODO: Ideally we wouldn't allow to read the directory itself (so
	 * that a pledged process can't find the names of the temporary files
	 * of other processes). */
	{ tmp_path, R|W|C,			PROMISE_TMPPATH },
	{ "", 0,				PROMISE_NONE }
};

#undef	X
#undef	C
#undef	W
#undef	R


enum {
	UNVEIL_FLAG_FOR_PLEDGE = UNVEIL_FLAG_FOR_SLOT0,
	UNVEIL_FLAG_FOR_CUSTOM = UNVEIL_FLAG_FOR_SLOT1,
};

/* Global state for not-on-exec and on-exec cases. */

static bool has_pledge_unveils[2], has_custom_unveils[2];
static bool cur_promises[2][PROMISE_COUNT];


static sysfil_t
uperms2sysfil(unveil_perms_t up)
{
	return (((up & UNVEIL_PERM_RPATH) ? SYF_PLEDGE_RPATH : 0) |
		((up & UNVEIL_PERM_WPATH) ? SYF_PLEDGE_WPATH : 0) |
		((up & UNVEIL_PERM_CPATH) ? SYF_PLEDGE_CPATH : 0) |
		((up & UNVEIL_PERM_XPATH) ? SYF_PLEDGE_EXEC  : 0));
}

static unveil_perms_t
sysfil2uperms(sysfil_t sf)
{
	return (((sf & SYF_PLEDGE_RPATH) ? UNVEIL_PERM_RPATH : 0) |
		((sf & SYF_PLEDGE_WPATH) ? UNVEIL_PERM_WPATH : 0) |
		((sf & SYF_PLEDGE_CPATH) ? UNVEIL_PERM_CPATH : 0) |
		((sf & SYF_PLEDGE_EXEC)  ? UNVEIL_PERM_XPATH : 0));
}


static int
parse_promises(bool *promises, const char *promises_str)
{
	size_t len = strlen(promises_str);
	char buf[len + 1], *str = buf;
	const char *cur;
	memcpy(buf, promises_str, len + 1);

	while ((cur = strsep(&str, " ")))
		if (*cur) {
			const struct promise_name *pn;
			for (pn = promise_names; *pn->name; pn++)
				if (0 == strcmp(pn->name, cur))
					break;
			if (pn->type == PROMISE_NONE) {
				errno = EINVAL;
				return (-1);
			}
			promises[pn->type] = true;
		}
	return (0);
}


static sysfil_t
do_pledge_unveils(const bool *req_promises, bool for_exec)
{
	const struct promise_unveil *pu;
	const char *path;
	sysfil_t sysfil, req_sysfil;
	unveil_perms_t need_uperms, req_uperms;
	int flags, flags1, r, i;

	flags = for_exec ? UNVEIL_FLAG_FOR_EXEC : UNVEIL_FLAG_FOR_CURR;
	flags1 = flags | UNVEIL_FLAG_FOR_PLEDGE;

	/*
	 * If no unveiling has been done yet, do a "sweep" to get rid of any
	 * inherited unveils.  After a sweep, all unveils become "inactive" and
	 * generally behave as if they were not there, but they still keep
	 * track of their "hard" permissions.  This allows to re-add them with
	 * those permissions if needed.
	 */
	if (!has_pledge_unveils[for_exec]) {
		r = unveilctl(-1, NULL, flags1 | UNVEIL_FLAG_SWEEP, -1);
		if (r < 0)
			err(EX_OSERR, "unveilctl sweep");
	}

	/* Map promises to sysfils. */
	req_sysfil = SYF_PLEDGE_ALWAYS | SYF_PLEDGE_UNVEIL;
	for (i = 0; i < PROMISE_COUNT; i++)
		if (req_promises[i])
			req_sysfil |= promise_sysfils[i];

	/* Do unveils for the unveils added or removed. */
	flags1 |= UNVEIL_FLAG_INTERMEDIATE | UNVEIL_FLAG_INSPECTABLE;
	need_uperms = 0;
	pu = promise_unveils;
	while (*(path = pu->path)) {
		unveil_perms_t uperms = 0;
		bool modified = false;
		do {
			if (cur_promises[for_exec][pu->type] != req_promises[pu->type])
				modified = true;
			if (req_promises[pu->type])
				uperms |= pu->perms;
			pu++;
		} while (strcmp(pu->path, path) == 0);
		need_uperms |= uperms; /* maximum permissions we'll need */
		if (modified) {
			if (path == root_path) {
				/*
				 * The unveil on "/" is only there to
				 * compensate for the other unveils that might
				 * be needed for certain promises.  Once the
				 * user does an explicit unveil(), filesystem
				 * access must be restricted to what has been
				 * explicitly unveiled.
				 */
				if (has_custom_unveils[for_exec])
					continue;
			} else if (path == tmp_path) {
				char *tmpdir;
				if ((tmpdir = getenv("TMPDIR")))
					path = tmpdir;
			}
			r = unveilctl(AT_FDCWD, path, flags1, uperms);
			if (r < 0 && errno != ENOENT) /* XXX */
				warn("unveil: %s", path);
		}
	}

	/*
	 * Figure out what additional sysfils might be needed to make the
	 * promises work.
	 */
	req_uperms = sysfil2uperms(req_sysfil);
	sysfil = req_sysfil | uperms2sysfil(need_uperms);

	/*
	 * Alter user's explicit unveils to compensate for sysfils implicitly
	 * enabled for promises.  Disabling a sysfil requests that certain file
	 * operations be forbidden altogether, but promises are exceptions to
	 * that.  Since we use unveils to implement these exceptions, add the
	 * restrictions to the user's unveils to get a similar effect.
	 */
	flags1 = flags | UNVEIL_FLAG_FOR_CUSTOM;
	if (sysfil != req_sysfil) {
		r = unveilctl(-1, NULL, flags1 | UNVEIL_FLAG_LIMIT, req_uperms);
		if (r < 0)
			err(EX_OSERR, "unveilctl limit");
	}

	/*
	 * Permanently drop permissions that aren't explicitly requested.
	 */
	flags1 = flags | UNVEIL_FLAG_FOR_PLEDGE | UNVEIL_FLAG_FOR_CUSTOM;
	flags1 |= UNVEIL_FLAG_ACTIVATE; /* also a good time to activate */
	r = unveilctl(-1, NULL, flags1 | UNVEIL_FLAG_HARDEN, req_uperms);
	if (r < 0)
		err(EX_OSERR, "unveilctl harden");

	has_pledge_unveils[for_exec] = true;
	return (sysfil);
}

static int do_pledge(const bool *promises, bool for_exec) {
	sysfil_t sysfil;
	int r;
	sysfil = do_pledge_unveils(promises, for_exec);
	r = procctl(P_PID, getpid(), for_exec ? PROC_SYSFIL_EXEC : PROC_SYSFIL, &sysfil);
	memcpy(cur_promises[for_exec], promises, PROMISE_COUNT * sizeof *promises);
	return (r);
}


static int
promise_unveil_cmp(const void *p0, const void *p1)
{
	const struct promise_unveil *pu0 = p0, *pu1 = p1;
	return (strcmp(pu0->path, pu1->path));
}

int
pledge(const char *promises_str, const char *execpromises_str)
{
	bool promises[PROMISE_COUNT] = { 0 };
	bool execpromises[PROMISE_COUNT] = { 0 };
	bool errors;
	int r;
	/* TODO: global lock */
	if (!promise_unveils_sorted) {
		qsort(promise_unveils,
		    (sizeof (promise_unveils) / sizeof (*promise_unveils)) - 1,
		    sizeof (*promise_unveils),
		    promise_unveil_cmp);
		promise_unveils_sorted = true;
	}

	if (promises_str) {
		r = parse_promises(promises, promises_str);
		if (r < 0)
			return (-1);
	}
	if (execpromises_str) {
		r = parse_promises(execpromises, execpromises_str);
		if (r < 0)
			return (-1);
	}

	errors = false;
	if (execpromises_str) {
		r = do_pledge(execpromises, true);
		if (r < 0)
			errors = true;
	}
	if (promises_str) {
		r = do_pledge(promises, false);
		if (r < 0)
			errors = true;
	}
	return (errors ? -1 : 0);
}


static int
unveil_parse_perms(unveil_perms_t *perms, const char *s)
{
	*perms = 0;
	while (*s)
		switch (*s++) {
		case 'r': *perms |= UNVEIL_PERM_RPATH; break;
		case 'w': *perms |= UNVEIL_PERM_WPATH; break;
		case 'c': *perms |= UNVEIL_PERM_CPATH; break;
		case 'x': *perms |= UNVEIL_PERM_XPATH; break;
		case 'i': *perms |= UNVEIL_PERM_INSPECT; break;
		default:
			return (-1);
		}
	return (0);
}

static int
do_unveil(const char *path, int flags, unveil_perms_t perms)
{
	int r, flags1, req_custom_flags, has_pledge_flags, has_custom_flags;

	has_pledge_flags =
	    (has_pledge_unveils[false] ? UNVEIL_FLAG_FOR_CURR : 0) |
	    (has_pledge_unveils[true]  ? UNVEIL_FLAG_FOR_EXEC : 0);
	has_custom_flags =
	    (has_custom_unveils[false] ? UNVEIL_FLAG_FOR_CURR : 0) |
	    (has_custom_unveils[true]  ? UNVEIL_FLAG_FOR_EXEC : 0);
	req_custom_flags = flags & (UNVEIL_FLAG_FOR_CURR | UNVEIL_FLAG_FOR_EXEC);

	if ((flags1 = has_pledge_flags & ~has_custom_flags & req_custom_flags)) {
		/*
		 * After the first call to unveil(), filesystem access must be
		 * restricted to what has been explicitly unveiled (modifying
		 * or adding unveils with higher permissions is still permitted
		 * within the constraints of the unveils' hard permissions).
		 * The pledge() wrapper may have unveiled "/" for certain
		 * promises.  This must be undone.
		 */
		flags1 |= UNVEIL_FLAG_FOR_PLEDGE;
		r = unveilctl(AT_FDCWD, root_path, flags1, 0);
		if (r < 0) /* XXX */
			warn("unveil: %s", root_path);
	}

	if ((flags1 = ~has_custom_flags & req_custom_flags)) {
		flags1 |= UNVEIL_FLAG_FOR_CUSTOM;
		r = unveilctl(-1, NULL, flags1 | UNVEIL_FLAG_SWEEP, -1);
		if (r < 0)
			err(EX_OSERR, "unveilctl sweep");
	}

	if (flags & UNVEIL_FLAG_FOR_CURR)
		has_custom_unveils[false] = true;
	if (flags & UNVEIL_FLAG_FOR_EXEC)
		has_custom_unveils[true] = true;

	flags1 = flags | UNVEIL_FLAG_FOR_CUSTOM;
	flags1 |= UNVEIL_FLAG_ACTIVATE;

	if (!path) {
		/*
		 * XXX If unveil(NULL, NULL) is done before pledge(), pledge()
		 * won't be able to add its unveils.
		 */
		r = unveilctl(-1, NULL, flags1 | UNVEIL_FLAG_HARDEN, 0);
		if (r < 0)
			err(EX_OSERR, "unveilctl harden");
		return (0);
	}

	flags1 |= UNVEIL_FLAG_INTERMEDIATE | UNVEIL_FLAG_INSPECTABLE;
	return (unveilctl(AT_FDCWD, path, flags1 | UNVEIL_FLAG_NOINHERIT, perms));
}

int
unveil_1(const char *path, int flags, const char *perms_str)
{
	unveil_perms_t perms;
	int r;
	if ((perms_str == NULL) != (path == NULL)) {
		errno = EINVAL;
		return (-1);
	}
	if (perms_str) {
		r = unveil_parse_perms(&perms, perms_str);
		if (r < 0) {
			errno = EINVAL;
			return (-1);
		}
	}
	return (do_unveil(path, flags, perms));
}

int
unveil(const char *path, const char *permissions)
{
	/*
	 * XXX: unveil() is inherited on-exec on OpenBSD if the process has
	 * execpledges, but re-unveiling isn't allowed (yet).  If the process
	 * does not have execpledges, unveils are not inherited and the
	 * executed process can do its own unveiling.
	 */
	return (unveil_1(path, UNVEIL_FLAG_FOR_CURR | UNVEIL_FLAG_FOR_EXEC, permissions));
}

int
unveilexec(const char *path, const char *permissions)
{
	return (unveil_1(path, UNVEIL_FLAG_FOR_EXEC, permissions));
}
