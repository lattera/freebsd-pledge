#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysfil.h>
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
	PROMISE_PROC_SESSION,
	PROMISE_THREAD,
	PROMISE_EXEC,
	PROMISE_PROT_EXEC,
	PROMISE_TTY,
	PROMISE_SIGTRAP,
	PROMISE_RLIMIT,
	PROMISE_SETTIME,
	PROMISE_AIO,
	PROMISE_EXTATTR,
	PROMISE_ACL,
	PROMISE_MAC,
	PROMISE_CPUSET,
	PROMISE_SYSVIPC,
	PROMISE_POSIXIPC,
	PROMISE_POSIXRT,
	PROMISE_CHROOT,
	PROMISE_JAIL,
	PROMISE_PS,
	PROMISE_PS_SESSION,
	PROMISE_CHMOD_SPECIAL,
	PROMISE_SYSFLAGS,
	PROMISE_SENDFILE,
	PROMISE_INET,
	PROMISE_UNIX,
	PROMISE_RECVFD,
	PROMISE_SENDFD,
	PROMISE_DNS,
	PROMISE_GETPW,
	PROMISE_SSL,
	PROMISE_COUNT /* must be last */
};

static const struct promise_name {
	const char name[15];
	enum promise_type type : 8;
} names_table[] = {
	{ "error",		PROMISE_ERROR },
	{ "capsicum",		PROMISE_CAPSICUM },
	{ "basic",		PROMISE_BASIC },
	{ "stdio",		PROMISE_STDIO },
	{ "unveil",		PROMISE_UNVEIL },
	{ "rpath",		PROMISE_RPATH },
	{ "wpath",		PROMISE_WPATH },
	{ "cpath",		PROMISE_CPATH },
	{ "dpath",		PROMISE_DPATH },
	{ "tmppath",		PROMISE_TMPPATH },
	{ "flock",		PROMISE_FLOCK },
	{ "fattr",		PROMISE_FATTR },
	{ "chown",		PROMISE_CHOWN },
	{ "id",			PROMISE_ID },
	{ "proc",		PROMISE_PROC },
	{ "proc_session",	PROMISE_PROC_SESSION },
	{ "thread",		PROMISE_THREAD },
	{ "exec",		PROMISE_EXEC },
	{ "prot_exec",		PROMISE_PROT_EXEC },
	{ "tty",		PROMISE_TTY },
	{ "sigtrap",		PROMISE_SIGTRAP },
	{ "rlimit",		PROMISE_RLIMIT },
	{ "settime",		PROMISE_SETTIME },
	{ "aio",		PROMISE_AIO },
	{ "extattr",		PROMISE_EXTATTR },
	{ "acl",		PROMISE_ACL },
	{ "mac",		PROMISE_MAC },
	{ "cpuset",		PROMISE_CPUSET },
	{ "sysvipc",		PROMISE_SYSVIPC },
	{ "posixipc",		PROMISE_POSIXIPC },
	{ "posixrt",		PROMISE_POSIXRT },
	{ "chroot",		PROMISE_CHROOT },
	{ "jail",		PROMISE_JAIL },
	{ "ps",			PROMISE_PS },
	{ "ps_session",		PROMISE_PS_SESSION },
	{ "chmod_special",	PROMISE_CHMOD_SPECIAL },
	{ "sysflags",		PROMISE_SYSFLAGS },
	{ "sendfile",		PROMISE_SENDFILE },
	{ "inet",		PROMISE_INET },
	{ "unix",		PROMISE_UNIX },
	{ "recvfd",		PROMISE_RECVFD },
	{ "sendfd",		PROMISE_SENDFD },
	{ "dns",		PROMISE_DNS },
	{ "getpw",		PROMISE_GETPW },
	{ "ssl",		PROMISE_SSL },
	{ "",			PROMISE_NONE },
};

static const struct promise_sysfil {
	enum promise_type type;
	int sysfil;
} sysfils_table[] = {
	{ PROMISE_ERROR,		SYSFIL_ERROR },
	{ PROMISE_BASIC,		SYSFIL_STDIO },
	{ PROMISE_STDIO,		SYSFIL_STDIO },
	{ PROMISE_UNVEIL,		SYSFIL_UNVEIL },
	{ PROMISE_RPATH,		SYSFIL_RPATH },
	{ PROMISE_WPATH,		SYSFIL_WPATH },
	{ PROMISE_CPATH,		SYSFIL_CPATH },
	{ PROMISE_DPATH,		SYSFIL_DPATH },
	{ PROMISE_FLOCK,		SYSFIL_FLOCK },
	{ PROMISE_FATTR,		SYSFIL_FATTR },
	{ PROMISE_CHOWN,		SYSFIL_CHOWN },
	{ PROMISE_ID,			SYSFIL_ID },
	{ PROMISE_PROC,			SYSFIL_PROC },
	{ PROMISE_PROC,			SYSFIL_ANY_SESSION },
	{ PROMISE_PROC_SESSION,		SYSFIL_PROC },
	{ PROMISE_THREAD,		SYSFIL_THREAD },
	{ PROMISE_EXEC,			SYSFIL_EXEC },
	{ PROMISE_PROT_EXEC,		SYSFIL_PROT_EXEC },
	{ PROMISE_TTY,			SYSFIL_TTY },
	{ PROMISE_SIGTRAP,		SYSFIL_SIGTRAP },
	{ PROMISE_RLIMIT,		SYSFIL_RLIMIT },
	{ PROMISE_SETTIME,		SYSFIL_SETTIME },
	{ PROMISE_AIO,			SYSFIL_AIO },
	{ PROMISE_EXTATTR,		SYSFIL_EXTATTR },
	{ PROMISE_ACL,			SYSFIL_ACL },
	{ PROMISE_MAC,			SYSFIL_MAC },
	{ PROMISE_CPUSET,		SYSFIL_CPUSET },
	{ PROMISE_SYSVIPC,		SYSFIL_SYSVIPC },
	{ PROMISE_POSIXIPC,		SYSFIL_POSIXIPC },
	{ PROMISE_POSIXRT,		SYSFIL_POSIXRT },
	{ PROMISE_CHROOT,		SYSFIL_CHROOT },
	{ PROMISE_JAIL,			SYSFIL_JAIL },
	{ PROMISE_PS,			SYSFIL_PS },
	{ PROMISE_PS,			SYSFIL_ANY_SESSION },
	{ PROMISE_PS_SESSION,		SYSFIL_PS },
	{ PROMISE_CHMOD_SPECIAL,	SYSFIL_CHMOD_SPECIAL },
	{ PROMISE_SYSFLAGS,		SYSFIL_SYSFLAGS },
	{ PROMISE_SENDFILE,		SYSFIL_SENDFILE },
	{ PROMISE_INET,			SYSFIL_INET },
	{ PROMISE_UNIX,			SYSFIL_UNIX },
	{ PROMISE_RECVFD,		SYSFIL_RECVFD },
	{ PROMISE_SENDFD,		SYSFIL_SENDFD },
	{ PROMISE_DNS,			SYSFIL_INET }, /* XXX */
};

static const struct promise_uperms {
	enum promise_type type;
	unveil_perms_t uperms;
} uperms_table[] = {
	{ PROMISE_RPATH,	UPERM_RPATH },
	{ PROMISE_WPATH,	UPERM_WPATH },
	{ PROMISE_CPATH,	UPERM_CPATH },
	{ PROMISE_EXEC,		UPERM_XPATH },
	{ PROMISE_FATTR,	UPERM_APATH },
};

/* The "fattr" promise is a bit special and shouldn't be enabled implicitly. */
static const unveil_perms_t promise_no_implicit_uperms = UPERM_APATH;

static const unveil_perms_t custom_keep_implicit_uperms = UPERM_INSPECT;

static const char *const root_path = "/";
static const char *const tmp_path = _PATH_TMP;

static bool unveils_table_sorted = false;

static struct promise_unveil {
	const char *path;
	unveil_perms_t perms;
	enum promise_type type;
} unveils_table[] = {
#define	R UPERM_RPATH
#define	W UPERM_WPATH
#define	C UPERM_CPATH
#define	X UPERM_XPATH
#define	A UPERM_APATH
	{ root_path, R,				PROMISE_RPATH },
	{ root_path, W,				PROMISE_WPATH },
	{ root_path, C,				PROMISE_CPATH },
	{ root_path, X,				PROMISE_EXEC },
	{ root_path, A,				PROMISE_FATTR },
	{ _PATH_ETC "/malloc.conf", R,		PROMISE_STDIO },
	{ _PATH_ETC "/libmap.conf", R,		PROMISE_STDIO },
	{ _PATH_VARRUN "/ld-elf.so.hints", R,	PROMISE_STDIO },
	{ _PATH_ETC "/localtime", R,		PROMISE_STDIO },
	{ "/usr/share/zoneinfo/", R,		PROMISE_STDIO },
	{ "/usr/share/nls/", R,			PROMISE_STDIO },
	{ _PATH_LOCALBASE "/share/nls/", R,	PROMISE_STDIO },
	/* Programs will often open /dev/null with O_CREAT.  TODO: Could have a
	 * different unveil() permission just for that. */
	{ _PATH_DEVNULL, R|W|C,			PROMISE_STDIO },
	{ _PATH_DEV "/random", R,		PROMISE_STDIO },
	{ _PATH_DEV "/urandom", R,		PROMISE_STDIO },
	/* XXX: Review /dev/crypto for safety. */
	{ _PATH_DEV "/crypto", W,		PROMISE_STDIO },
	{ _PATH_ETC "/nsswitch.conf", R,	PROMISE_DNS },
	{ _PATH_ETC "/resolv.conf", R,		PROMISE_DNS },
	{ _PATH_ETC "/hosts", R,		PROMISE_DNS },
	{ _PATH_ETC "/services", R,		PROMISE_DNS },
	{ _PATH_VARDB "/services.db", R,	PROMISE_DNS },
	{ _PATH_ETC "/protocols", R,		PROMISE_DNS },
	{ _PATH_DEV "/tty", R|W|A,		PROMISE_TTY },
	{ _PATH_ETC "/nsswitch.conf", R,	PROMISE_GETPW },
	{ _PATH_ETC "/pwd.db", R,		PROMISE_GETPW },
	{ _PATH_ETC "/spwd.db", R,		PROMISE_GETPW },
	{ _PATH_ETC "/group", R,		PROMISE_GETPW },
	{ _PATH_ETC "/ssl/cert.pem", R,		PROMISE_SSL },
	/* TODO: Ideally we wouldn't allow to read the directory itself (so
	 * that a pledged process can't find the names of the temporary files
	 * of other processes). */
	{ tmp_path, R|W|C|A,			PROMISE_TMPPATH },
	{ "", 0,				PROMISE_NONE }
#undef	A
#undef	X
#undef	C
#undef	W
#undef	R
};


static const int unveil_global_flags =
    UNVEILCTL_INTERMEDIATE | UNVEILCTL_INSPECTABLE | UNVEILCTL_NONDIRBYNAME;

enum {
	UNVEILCTL_FOR_PLEDGE = UNVEILCTL_FOR_SLOT0,
	UNVEILCTL_FOR_CUSTOM = UNVEILCTL_FOR_SLOT1,
};

/* Global state for not-on-exec and on-exec cases. */

static bool has_pledge_unveils[2], has_custom_unveils[2];
static bool cur_promises[2][PROMISE_COUNT];


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
			for (pn = names_table; *pn->name; pn++)
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


static const char *
pledge_unveil_fixup_path(bool for_exec, const char *path)
{
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
			path = NULL;
	} else if (path == tmp_path) {
		char *tmpdir;
		if ((tmpdir = getenv("TMPDIR")))
			path = tmpdir;
	}
	return (path);
}

static size_t
do_pledge_unveils(const bool *req_promises, bool for_exec, int *sysfils)
{
	int *orig_sysfils = sysfils;
	const struct promise_sysfil *pa;
	const struct promise_unveil *pu;
	const struct promise_uperms *pp;
	const char *path;
	unveil_perms_t need_uperms, req_uperms;
	int flags, flags1, r;
	bool need_promises[PROMISE_COUNT];

	flags = for_exec ? UNVEILCTL_FOR_EXEC : UNVEILCTL_FOR_CURR;
	flags1 = flags | UNVEILCTL_FOR_PLEDGE;

	/*
	 * If no unveiling has been done yet, do a "sweep" to get rid of any
	 * inherited unveils.  After a sweep, all unveils become "inactive" and
	 * generally behave as if they were not there, but they still keep
	 * track of their "frozen" permissions.  This allows to re-add them
	 * with those permissions if needed.
	 */
	if (!has_pledge_unveils[for_exec]) {
		r = unveilctl(-1, NULL, flags1 | UNVEILCTL_SWEEP, -1);
		if (r < 0)
			err(EX_OSERR, "unveilctl sweep");
	}

	/*
	 * Do unveils for the promises added or removed.
	 */
	flags1 |= unveil_global_flags;
	need_uperms = UPERM_NONE;
	for (pu = unveils_table; (*(path = pu->path)); ) {
		unveil_perms_t uperms = UPERM_NONE;
		bool modified = false;
		do {
			if (cur_promises[for_exec][pu->type] != req_promises[pu->type])
				modified = true;
			if (req_promises[pu->type])
				uperms |= pu->perms;
			pu++;
		} while (strcmp(pu->path, path) == 0);
		/* maximum unveil permissions we'll need for those promises */
		need_uperms |= uperms & ~promise_no_implicit_uperms;
		if (modified && (path = pledge_unveil_fixup_path(for_exec, path))) {
			r = unveilctl(AT_FDCWD, path, flags1, uperms);
			if (r < 0 && errno != ENOENT) /* XXX */
				warn("unveil: %s", path);
		}
	}

	/*
	 * Figure out which uperms equivalents were explicitly requested with
	 * promises and which additional promises must be implicitly enabled
	 * for the implicit uperms needed for their unveils to work.
	 */
	memcpy(need_promises, req_promises, PROMISE_COUNT * sizeof *need_promises);
	req_uperms = UPERM_NONE;
	for (pp = uperms_table; pp != &uperms_table[nitems(uperms_table)]; pp++) {
		if (req_promises[pp->type])
			req_uperms |= pp->uperms | custom_keep_implicit_uperms;
		if (pp->uperms & need_uperms)
			need_promises[pp->type] = true;
	}

	/*
	 * Map promises to sysfils.
	 *
	 * NOTE: do_pledge() must allocate a large enough array.
	 */
	*sysfils++ = SYSFIL_UNVEIL;
	for (pa = sysfils_table; pa != &sysfils_table[nitems(sysfils_table)]; pa++)
		if (need_promises[pa->type])
			*sysfils++ = pa->sysfil;

	/*
	 * Alter user's explicit unveils to compensate for sysfils implicitly
	 * enabled for promises.  Disabling a sysfil requests that certain file
	 * operations be forbidden altogether, but promises are exceptions to
	 * that.  Since we use unveils to implement these exceptions, add the
	 * restrictions to the user's unveils to get a similar effect.
	 */
	flags1 = flags | UNVEILCTL_FOR_CUSTOM;
	if (need_uperms & ~req_uperms) {
		r = unveilctl(-1, NULL, flags1 | UNVEILCTL_LIMIT, req_uperms);
		if (r < 0)
			err(EX_OSERR, "unveilctl limit");
	}

	/*
	 * Permanently drop permissions that aren't explicitly requested.
	 */
	flags1 = flags | UNVEILCTL_ACTIVATE;
	r = unveilctl(-1, NULL, flags1 | UNVEILCTL_FREEZE, UPERM_NONE);
	if (r < 0)
		err(EX_OSERR, "unveilctl freeze");

	has_pledge_unveils[for_exec] = true;
	return (sysfils - orig_sysfils);
}

static void
reserve_pledge_unveils(bool for_exec)
{
	const struct promise_unveil *pu;
	const char *path;
	int r, i, flags, flags1;
	flags = (for_exec ? UNVEILCTL_FOR_EXEC : UNVEILCTL_FOR_CURR) |
	    UNVEILCTL_FOR_PLEDGE;
	r = unveilctl(-1, NULL, flags | UNVEILCTL_SWEEP, -1);
	if (r < 0)
		err(EX_OSERR, "unveilctl sweep");
	flags1 = flags | unveil_global_flags;
	for (pu = unveils_table; (*(path = pu->path)); ) {
		unveil_perms_t uperms = UPERM_NONE;
		do {
			uperms |= pu->perms;
			pu++;
		} while (strcmp(pu->path, path) == 0);
		if ((path = pledge_unveil_fixup_path(for_exec, path))) {
			r = unveilctl(AT_FDCWD, path, flags1, uperms);
			if (r < 0 && errno != ENOENT) /* XXX */
				warn("unveil: %s", path);
		}
	}
	for (i = 0; i < PROMISE_COUNT; i++)
		cur_promises[for_exec][i] = true;
	has_pledge_unveils[for_exec] = true;
	/* NOTE: caller expected to do the UNVEILCTL_FREEZE */
}

static int
do_pledge(const bool *promises, bool for_exec)
{
	int sysfils[nitems(sysfils_table) + 1];
	size_t count;
	int r;
	count = do_pledge_unveils(promises, for_exec, sysfils);
	r = sysfilctl(
	    SYSFILCTL_MASK | (for_exec ? SYSFILCTL_FOR_EXEC : SYSFILCTL_FOR_CURR),
	    sysfils, count);
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
	if (!unveils_table_sorted) {
		qsort(unveils_table,
		    (sizeof (unveils_table) / sizeof (*unveils_table)) - 1,
		    sizeof (*unveils_table),
		    promise_unveil_cmp);
		unveils_table_sorted = true;
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
	*perms = UPERM_NONE;
	while (*s)
		switch (*s++) {
		case 'r': *perms |= UPERM_RPATH; break;
		case 'w': *perms |= UPERM_WPATH; /* FALLTHROUGH */
		case 'a': *perms |= UPERM_APATH; break;
		case 'c': *perms |= UPERM_CPATH; break;
		case 'x': *perms |= UPERM_XPATH; break;
		case 'i': *perms |= UPERM_INSPECT; break;
		default:
			return (-1);
		}
	return (0);
}

static int
do_unveil(const char *path, int flags, unveil_perms_t perms)
{
	int r, flags1, flags2, req_custom_flags, has_pledge_flags, has_custom_flags;

	has_pledge_flags =
	    (has_pledge_unveils[false] ? UNVEILCTL_FOR_CURR : 0) |
	    (has_pledge_unveils[true]  ? UNVEILCTL_FOR_EXEC : 0);
	has_custom_flags =
	    (has_custom_unveils[false] ? UNVEILCTL_FOR_CURR : 0) |
	    (has_custom_unveils[true]  ? UNVEILCTL_FOR_EXEC : 0);
	req_custom_flags = flags & (UNVEILCTL_FOR_CURR | UNVEILCTL_FOR_EXEC);

	if ((flags1 = has_pledge_flags & ~has_custom_flags & req_custom_flags)) {
		/*
		 * After the first call to unveil(), filesystem access must be
		 * restricted to what has been explicitly unveiled (modifying
		 * or adding unveils with higher permissions is still permitted
		 * within the constraints of the unveils' frozen permissions).
		 * The pledge() wrapper may have unveiled "/" for certain
		 * promises.  This must be undone.
		 */
		flags1 |= UNVEILCTL_FOR_PLEDGE;
		r = unveilctl(AT_FDCWD, root_path, flags1, UPERM_NONE);
		if (r < 0) /* XXX */
			warn("unveil: %s", root_path);
	}

	if ((flags1 = ~has_custom_flags & req_custom_flags)) {
		flags1 |= UNVEILCTL_FOR_CUSTOM;
		r = unveilctl(-1, NULL, flags1 | UNVEILCTL_SWEEP, -1);
		if (r < 0)
			err(EX_OSERR, "unveilctl sweep");
	}

	if (flags & UNVEILCTL_FOR_CURR)
		has_custom_unveils[false] = true;
	if (flags & UNVEILCTL_FOR_EXEC)
		has_custom_unveils[true] = true;

	flags1 = flags | UNVEILCTL_ACTIVATE;

	if (!path) {
		/* Make calling pledge() after unveil(NULL, NULL) work. */
		if ((flags2 = req_custom_flags & ~has_pledge_flags)) {
			if (flags2 & UNVEILCTL_FOR_CURR)
				reserve_pledge_unveils(false);
			if (flags2 & UNVEILCTL_FOR_EXEC)
				reserve_pledge_unveils(true);
		}
		/* Forbid ever raising unveil permissions. */
		r = unveilctl(-1, NULL, flags1 | UNVEILCTL_FREEZE, UPERM_NONE);
		if (r < 0)
			err(EX_OSERR, "unveilctl freeze");
		return (0);
	}

	flags1 |= UNVEILCTL_FOR_CUSTOM | unveil_global_flags;
	return (unveilctl(AT_FDCWD, path, flags1 | UNVEILCTL_NOINHERIT, perms));
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
	return (unveil_1(path, UNVEILCTL_FOR_CURR | UNVEILCTL_FOR_EXEC, permissions));
}

int
unveilexec(const char *path, const char *permissions)
{
	return (unveil_1(path, UNVEILCTL_FOR_EXEC, permissions));
}
