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
#include <signal.h>

enum promise_type {
	PROMISE_ERROR,
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
	PROMISE_PROC_CHILD,
	PROMISE_PROC_PGRP,
	PROMISE_PROC_SESSION,
	PROMISE_THREAD,
	PROMISE_EXEC,
	PROMISE_PROT_EXEC,
	PROMISE_TTY,
	PROMISE_SIGTRAP,
	PROMISE_RLIMIT,
	PROMISE_SCHED,
	PROMISE_SETTIME,
	PROMISE_FFCLOCK,
	PROMISE_MLOCK,
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
	PROMISE_PS_CHILD,
	PROMISE_PS_PGRP,
	PROMISE_PS_SESSION,
	PROMISE_CHMOD_SPECIAL,
	PROMISE_SYSFLAGS,
	PROMISE_SENDFILE,
	PROMISE_INET,
	PROMISE_UNIX,
	PROMISE_SETFIB,
	PROMISE_ROUTE,
	PROMISE_RECVFD,
	PROMISE_SENDFD,
	PROMISE_DNS,
	PROMISE_GETPW,
	PROMISE_SSL,
	PROMISE_CRYPTODEV,
	PROMISE_MOUNT,
	PROMISE_QUOTA,
	PROMISE_FH,
	PROMISE_ANY_AF,
	PROMISE_ANY_PRIV,
	PROMISE_ANY_IOCTL,
	PROMISE_ANY_SOCKOPT,
	PROMISE_COUNT /* must be last */
};

#define	PROMISE_NAME_SIZE 16
static const struct promise_name {
	const char name[PROMISE_NAME_SIZE];
} names_table[PROMISE_COUNT] = {
	[PROMISE_ERROR] =		{ "error" },
	[PROMISE_BASIC] =		{ "basic" },
	[PROMISE_STDIO] =		{ "stdio" },
	[PROMISE_UNVEIL] =		{ "unveil" },
	[PROMISE_RPATH] =		{ "rpath" },
	[PROMISE_WPATH] =		{ "wpath" },
	[PROMISE_CPATH] =		{ "cpath" },
	[PROMISE_DPATH] =		{ "dpath" },
	[PROMISE_TMPPATH] =		{ "tmppath" },
	[PROMISE_FLOCK] =		{ "flock" },
	[PROMISE_FATTR] =		{ "fattr" },
	[PROMISE_CHOWN] =		{ "chown" },
	[PROMISE_ID] =			{ "id" },
	[PROMISE_PROC] =		{ "proc" },
	[PROMISE_PROC_CHILD] =		{ "proc_child" },
	[PROMISE_PROC_PGRP] =		{ "proc_pgrp" },
	[PROMISE_PROC_SESSION] =	{ "proc_session" },
	[PROMISE_THREAD] =		{ "thread" },
	[PROMISE_EXEC] =		{ "exec" },
	[PROMISE_PROT_EXEC] =		{ "prot_exec" },
	[PROMISE_TTY] =			{ "tty" },
	[PROMISE_SIGTRAP] =		{ "sigtrap" },
	[PROMISE_RLIMIT] =		{ "rlimit" },
	[PROMISE_SCHED] =		{ "sched" },
	[PROMISE_SETTIME] =		{ "settime" },
	[PROMISE_FFCLOCK] =		{ "ffclock" },
	[PROMISE_MLOCK] =		{ "mlock" },
	[PROMISE_AIO] =			{ "aio" },
	[PROMISE_EXTATTR] =		{ "extattr" },
	[PROMISE_ACL] =			{ "acl" },
	[PROMISE_MAC] =			{ "mac" },
	[PROMISE_CPUSET] =		{ "cpuset" },
	[PROMISE_SYSVIPC] =		{ "sysvipc" },
	[PROMISE_POSIXIPC] =		{ "posixipc" },
	[PROMISE_POSIXRT] =		{ "posixrt" },
	[PROMISE_CHROOT] =		{ "chroot" },
	[PROMISE_JAIL] =		{ "jail" },
	[PROMISE_PS] =			{ "ps" },
	[PROMISE_PS_CHILD] =		{ "ps_child" },
	[PROMISE_PS_PGRP] =		{ "ps_pgrp" },
	[PROMISE_PS_SESSION] =		{ "ps_session" },
	[PROMISE_CHMOD_SPECIAL] =	{ "chmod_special" },
	[PROMISE_SYSFLAGS] =		{ "sysflags" },
	[PROMISE_SENDFILE] =		{ "sendfile" },
	[PROMISE_INET] =		{ "inet" },
	[PROMISE_UNIX] =		{ "unix" },
	[PROMISE_SETFIB] =		{ "setfib" },
	[PROMISE_ROUTE] =		{ "route" },
	[PROMISE_RECVFD] =		{ "recvfd" },
	[PROMISE_SENDFD] =		{ "sendfd" },
	[PROMISE_DNS] =			{ "dns" },
	[PROMISE_GETPW] =		{ "getpw" },
	[PROMISE_SSL] =			{ "ssl" },
	[PROMISE_CRYPTODEV] =		{ "cryptodev" },
	[PROMISE_MOUNT] =		{ "mount" },
	[PROMISE_QUOTA] =		{ "quota" },
	[PROMISE_FH] =			{ "fh" },
	[PROMISE_ANY_AF] =		{ "any_af" },
	[PROMISE_ANY_PRIV] =		{ "any_priv" },
	[PROMISE_ANY_IOCTL] =		{ "any_ioctl" },
	[PROMISE_ANY_SOCKOPT] =		{ "any_sockopt" },
};

static const struct promise_sysfil {
	enum promise_type type : 8;
	int sysfil : 8;
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
	{ PROMISE_PROC,			SYSFIL_SCHED },
	{ PROMISE_PROC,			SYSFIL_ANY_PROCESS },
	{ PROMISE_PROC_SESSION,		SYSFIL_PROC },
	{ PROMISE_PROC_SESSION,		SYSFIL_SCHED },
	{ PROMISE_PROC_SESSION,		SYSFIL_SAME_SESSION },
	{ PROMISE_PROC_PGRP,		SYSFIL_PROC },
	{ PROMISE_PROC_PGRP,		SYSFIL_SCHED },
	{ PROMISE_PROC_PGRP,		SYSFIL_SAME_PGRP },
	{ PROMISE_PROC_CHILD,		SYSFIL_PROC },
	{ PROMISE_PROC_CHILD,		SYSFIL_SCHED },
	{ PROMISE_PROC_CHILD,		SYSFIL_CHILD_PROCESS },
	{ PROMISE_THREAD,		SYSFIL_THREAD },
	{ PROMISE_THREAD,		SYSFIL_SCHED },
	{ PROMISE_EXEC,			SYSFIL_EXEC },
	{ PROMISE_PROT_EXEC,		SYSFIL_PROT_EXEC },
	{ PROMISE_TTY,			SYSFIL_TTY },
	{ PROMISE_SIGTRAP,		SYSFIL_SIGTRAP },
	{ PROMISE_RLIMIT,		SYSFIL_RLIMIT },
	{ PROMISE_SCHED,		SYSFIL_SCHED },
	{ PROMISE_SETTIME,		SYSFIL_SETTIME },
	{ PROMISE_FFCLOCK,		SYSFIL_FFCLOCK },
	{ PROMISE_MLOCK,		SYSFIL_MLOCK },
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
	{ PROMISE_PS,			SYSFIL_ANY_PROCESS },
	{ PROMISE_PS_SESSION,		SYSFIL_PS },
	{ PROMISE_PS_SESSION,		SYSFIL_SAME_SESSION },
	{ PROMISE_PS_PGRP,		SYSFIL_PS },
	{ PROMISE_PS_PGRP,		SYSFIL_SAME_PGRP },
	{ PROMISE_PS_CHILD,		SYSFIL_PS },
	{ PROMISE_PS_CHILD,		SYSFIL_CHILD_PROCESS },
	{ PROMISE_CHMOD_SPECIAL,	SYSFIL_CHMOD_SPECIAL },
	{ PROMISE_SYSFLAGS,		SYSFIL_SYSFLAGS },
	{ PROMISE_SENDFILE,		SYSFIL_SENDFILE },
	{ PROMISE_INET,			SYSFIL_INET },
	{ PROMISE_UNIX,			SYSFIL_UNIX },
	{ PROMISE_SETFIB,		SYSFIL_SETFIB },
	{ PROMISE_ROUTE,		SYSFIL_ROUTE },
	{ PROMISE_RECVFD,		SYSFIL_RECVFD },
	{ PROMISE_SENDFD,		SYSFIL_SENDFD },
	{ PROMISE_DNS,			SYSFIL_INET },
	{ PROMISE_DNS,			SYSFIL_ROUTE }, /* XXX */
	{ PROMISE_CRYPTODEV,		SYSFIL_CRYPTODEV },
	{ PROMISE_SSL,			SYSFIL_CRYPTODEV },
	{ PROMISE_MOUNT,		SYSFIL_MOUNT },
	{ PROMISE_QUOTA,		SYSFIL_QUOTA },
	{ PROMISE_FH,			SYSFIL_FH },
	{ PROMISE_ANY_AF,		SYSFIL_ANY_AF },
	{ PROMISE_ANY_PRIV,		SYSFIL_ANY_PRIV },
	{ PROMISE_ANY_IOCTL,		SYSFIL_ANY_IOCTL },
	{ PROMISE_ANY_SOCKOPT,		SYSFIL_ANY_SOCKOPT },
};

static const char *const root_path = "/";
static const char *const tmp_path = _PATH_TMP;

static bool unveils_table_sorted = false;

static struct promise_unveil {
	const char *path;
	unveil_perms uperms : 8;
	enum promise_type type : 8;
} unveils_table[] = {
#define	I UPERM_INSPECT
#define	R UPERM_RPATH
#define	W UPERM_WPATH /* NOTE: UPERM_APATH not implied here */
#define	C UPERM_CPATH
#define	X UPERM_XPATH
#define	A UPERM_APATH
#define	T UPERM_TMPPATH
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
	{ _PATH_DEVNULL, R|W,			PROMISE_STDIO },
	{ _PATH_DEV "/random", R,		PROMISE_STDIO },
	{ _PATH_DEV "/urandom", R,		PROMISE_STDIO },
	{ "/libexec/ld-elf.so.1", X,		PROMISE_EXEC },
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
	{ _PATH_DEV "/crypto", R|W,		PROMISE_CRYPTODEV },
	{ _PATH_DEV "/crypto", R|W,		PROMISE_SSL }, /* sysfil also enabled */
	{ _PATH_ETC "/ssl/", R,			PROMISE_SSL },
	{ _PATH_LOCALBASE "/etc/ssl/", R,	PROMISE_SSL },
	{ tmp_path, T,				PROMISE_TMPPATH },
	{ "", 0, -1 }
#undef	T
#undef	A
#undef	X
#undef	C
#undef	W
#undef	R
#undef	I
};


enum apply_on { ON_SELF, ON_EXEC, };
enum apply_for { FOR_PLEDGE, FOR_CUSTOM, };
enum { ON_COUNT = 2 };

/* Using slots 1 to 4; reserving slot 0 for user. */

static const unveil_slots unveil_slots_for[ON_COUNT][2] = {
	[ON_SELF] = { [FOR_PLEDGE] = 1U << 1, [FOR_CUSTOM] = 1U << 2 },
	[ON_EXEC] = { [FOR_PLEDGE] = 1U << 3, [FOR_CUSTOM] = 1U << 4 },
};

static const int unveil_flags_on[ON_COUNT] = {
	[ON_SELF] = UNVEILCTL_ON_SELF,
	[ON_EXEC] = UNVEILCTL_ON_EXEC,
};

static const int unveil_flags_path =
    UNVEILCTL_INTERMEDIATE | UNVEILCTL_INSPECTABLE | UNVEILCTL_NONDIRBYNAME;

static const int sysfil_flags_on[ON_COUNT] = {
	[ON_SELF] = SYSFILCTL_ON_SELF,
	[ON_EXEC] = SYSFILCTL_ON_EXEC,
};

static const int sysfil_sel_flags_on[ON_COUNT] = {
	[ON_SELF] = SYSFILSEL_ON_SELF,
	[ON_EXEC] = SYSFILSEL_ON_EXEC,
};

/* Global state for not-on-exec and on-exec cases. */

static bool has_reserved_pledge_unveils[ON_COUNT];
static bool has_pledge_unveils[ON_COUNT], has_custom_unveils[ON_COUNT];


static int __noinline
parse_promises(bool *promises, const char *promises_str)
{
	const char *p = promises_str;
	do {
		/* skip spaces */
		while (*p == ' ')
			p++;
		if (!*p) /* whole string processed */
			break;
		/* get next promise name */
		char name[PROMISE_NAME_SIZE] = { '\0' }, *q = name;
		do {
			if (q == &name[sizeof name])
				goto inval; /* name too long */
			*q++ = *p++;
		} while (*p && *p != ' ');
		/* search for name in table */
		enum promise_type type = 0;
		do {
			if (type >= PROMISE_COUNT)
				goto inval; /* not found */
			if (memcmp(name, names_table[type].name, sizeof name) == 0)
				break;
			type++;
		} while (true);
		promises[type] = true; /* found */
	} while (true);
	return (0);
inval:	errno = EINVAL;
	return (-1);
}


static const char *
pledge_unveil_fixup_path(bool tainted, enum apply_on on, const char *path)
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
		if (has_custom_unveils[on])
			path = NULL;
	} else if (!tainted && path == tmp_path) {
		char *tmpdir;
		if ((tmpdir = getenv("TMPDIR")))
			path = tmpdir;
	}
	return (path);
}

static void
promises_needed_for_uperms(bool *promises, unveil_perms uperms)
{
	if (uperms & UPERM_RPATH) promises[PROMISE_RPATH] = true;
	if (uperms & UPERM_WPATH) promises[PROMISE_WPATH] = true;
	if (uperms & UPERM_CPATH) promises[PROMISE_CPATH] = true;
	if (uperms & UPERM_XPATH) promises[PROMISE_EXEC]  = true;
	/* Note that UPERM_APATH does not imply PROMISE_FATTR. */
	if (uperms & UPERM_TMPPATH) {
		promises[PROMISE_RPATH] = true;
		promises[PROMISE_WPATH] = true;
		promises[PROMISE_CPATH] = true;
	}
}

static unveil_perms
retained_uperms_for_promises(const bool *promises)
{
	unveil_perms uperms = UPERM_INSPECT;
	if (promises[PROMISE_RPATH]) uperms |= UPERM_RPATH;
	if (promises[PROMISE_WPATH]) uperms |= UPERM_WPATH;
	if (promises[PROMISE_CPATH]) uperms |= UPERM_CPATH;
	if (promises[PROMISE_EXEC])  uperms |= UPERM_XPATH;
	if (promises[PROMISE_FATTR]) uperms |= UPERM_APATH;
	if (promises[PROMISE_RPATH] &&
	    promises[PROMISE_WPATH] &&
	    promises[PROMISE_CPATH])
		uperms |= UPERM_TMPPATH;
	return (uperms);
}

static int
unveil_path(int flags, unveil_slots slots, const char *path, unveil_perms uperms)
{
	struct unveilctl ctl = {
		.atfd = AT_FDCWD, .path = path,
		.slots = slots,
		.uperms = uperms,
	};
	int r;
	r = unveilctl(flags | unveil_flags_path | UNVEILCTL_UNVEIL, &ctl);
	if (r < 0 && errno != ENOENT && errno != EACCES)
		warn("unveil: %s", path);
	return (r);
}

static int
unveil_op(int flags, enum apply_on on, unveil_slots slots, unveil_perms uperms)
{
	struct unveilctl ctl = {
		.atfd = -1, .path = NULL,
		.slots = slots,
		.uperms = uperms,
	};
	int r;
	r = unveilctl(unveil_flags_on[on] | flags, &ctl);
	if (r < 0)
		err(EX_OSERR, "unveilctl");
	return (r);
}

static unveil_perms
do_promise_unveils(const bool *want_promises, enum apply_on on)
{
	unveil_perms need_uperms;
	const struct promise_unveil *pu;
	const char *path;
	bool tainted;
	tainted = issetugid() != 0;
	need_uperms = UPERM_NONE;
	for (pu = unveils_table; (*(path = pu->path)); ) {
		unveil_perms uperms = UPERM_NONE;
		do {
			if (want_promises[pu->type])
				uperms |= pu->uperms;
			pu++;
		} while (strcmp(pu->path, path) == 0);
		if (uperms == UPERM_NONE)
			continue;
		/* maximum unveil permissions we'll need for those promises */
		need_uperms |= uperms;
		if ((path = pledge_unveil_fixup_path(tainted, on, path)))
			unveil_path(0, unveil_slots_for[on][FOR_PLEDGE], path, uperms);
	}
	return (need_uperms);
}

static size_t
do_pledge_unveils(const bool *want_promises, enum apply_on on, int *sels)
{
	int *orig_sels = sels;
	const struct promise_sysfil *pa;
	unveil_perms need_uperms, want_uperms;
	bool need_promises[PROMISE_COUNT];

	/*
	 * Do unveils for all requested promists.
	 */
	unveil_op(UNVEILCTL_SWEEP, on, unveil_slots_for[on][FOR_PLEDGE], UPERM_NONE);
	need_uperms = do_promise_unveils(want_promises, on);

	/*
	 * Figure out which promises must be implicitly enabled to make the
	 * unveils of the requested promises work.  Only the sysfils associated
	 * with those implicitly enabled promises are needed, not their unveils.
	 */
	memcpy(need_promises, want_promises, PROMISE_COUNT * sizeof *want_promises);
	promises_needed_for_uperms(need_promises, need_uperms);

	/*
	 * Map promises to sysfils.
	 *
	 * NOTE: do_pledge() must allocate a large enough array.
	 */
	if (want_promises != UPERM_NONE)
		/* allow dropping unveil permissions afterward */
		*sels++ = SYSFIL_UNVEIL | sysfil_sel_flags_on[on];
	for (pa = sysfils_table; pa != &sysfils_table[nitems(sysfils_table)]; pa++)
		if (need_promises[pa->type])
			*sels++ = pa->sysfil | sysfil_sel_flags_on[on];

	/*
	 * Figure out the uperms equivalent for the promises that were
	 * explicitly required (NOT those that were implicitly enabled).
	 */
	want_uperms = retained_uperms_for_promises(want_promises);

	/*
	 * Alter user's explicit unveils to compensate for sysfils implicitly
	 * enabled for promises.  Disabling a sysfil requests that certain file
	 * operations be forbidden altogether, but promises are exceptions to
	 * that.  Since we use unveils to implement these exceptions, add the
	 * restrictions to the user's unveils to get a similar effect.
	 */
	unveil_op(UNVEILCTL_LIMIT, on, unveil_slots_for[on][FOR_CUSTOM], want_uperms);

	/*
	 * Permanently drop permissions that aren't explicitly requested.
	 *
	 * If the "unveil" promise was explicitly requested, retain the uperms
	 * equivalent for the explicitly requested promises in the frozen
	 * permissions to allow future unveils to use them (until they are
	 * frozen with no retained permissions, either by dropping the "unveil"
	 * promise or doing an unveil(NULL, NULL).
	 */
	unveil_op(UNVEILCTL_ENABLE | UNVEILCTL_FREEZE,
	    on, unveil_slots_for[on][FOR_PLEDGE] |
	    (has_custom_unveils[on] ? unveil_slots_for[on][FOR_CUSTOM] : 0),
	    want_promises[PROMISE_UNVEIL] ? want_uperms : UPERM_NONE);

	has_pledge_unveils[on] = true;
	return (sels - orig_sels);
}

static void
reserve_pledge_unveils(enum apply_on on)
{
	bool want_promises[PROMISE_COUNT];
	for (int i = 0; i < PROMISE_COUNT; i++)
		want_promises[i] = true;
	do_promise_unveils(want_promises, on);
	has_reserved_pledge_unveils[on] = true;
}

static int
do_pledge(bool *promises_on[ON_COUNT])
{
	int selv[(nitems(sysfils_table) + 1) * ON_COUNT];
	bool reset_sigtrap = false;
	int flags = 0;
	size_t selc = 0;
	for (enum apply_on on = 0; on < ON_COUNT; on++) {
		if (!promises_on[on])
			continue;
		flags |= sysfil_flags_on[on];
		if (!promises_on[on][PROMISE_SIGTRAP])
			reset_sigtrap = true;
		selc += do_pledge_unveils(promises_on[on], on, &selv[selc]);
	}
	if (reset_sigtrap) {
		sig_t osig;
		/* XXX might not be sufficient */
		osig = signal(SIGTRAP, SIG_DFL);
		if (osig == SIG_ERR)
			warn("signal SIGTRAP");
	}
	return (sysfilctl(SYSFILCTL_RESTRICT | flags, selc, selv));
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
	bool *promises_on[ON_COUNT] = { NULL };
	int r;
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
		promises_on[ON_SELF] = promises;
	}
	if (execpromises_str) {
		r = parse_promises(execpromises, execpromises_str);
		if (r < 0)
			return (-1);
		promises_on[ON_EXEC] = execpromises;
	}
	return (do_pledge(promises_on));
}


static int
unveil_parse_perms(unveil_perms *uperms, const char *s)
{
	*uperms = UPERM_NONE;
	while (*s)
		switch (*s++) {
		case 'r': *uperms |= UPERM_RPATH; break;
		case 'm': *uperms |= UPERM_WPATH; break;
		case 'w': *uperms |= UPERM_WPATH; /* FALLTHROUGH */
		case 'a': *uperms |= UPERM_APATH; break;
		case 'c': *uperms |= UPERM_CPATH; break;
		case 'x': *uperms |= UPERM_XPATH; break;
		case 'i': *uperms |= UPERM_INSPECT; break;
		case 't': *uperms |= UPERM_TMPPATH; break;
		default:
			return (-1);
		}
	return (0);
}

static int
do_unveil(const char *path, const bool on[ON_COUNT], unveil_perms uperms)
{
	for (int i = 0; i < ON_COUNT; i++) {
		if (!on[i] || has_custom_unveils[i])
			continue;
		if (has_pledge_unveils[i]) {
			/*
			 * After the first call to unveil(), filesystem access
			 * must be restricted to what has been explicitly
			 * unveiled (modifying or adding unveils with higher
			 * permissions is still permitted within the
			 * constraints of the unveils' frozen permissions).
			 * The pledge() wrapper may have unveiled "/" for
			 * certain promises.  This must be undone.
			 */
			unveil_path(0, unveil_slots_for[i][FOR_PLEDGE],
			    root_path, UPERM_NONE);
		}
		has_custom_unveils[i] = true;
		if (i == ON_EXEC && on[ON_SELF] && !has_pledge_unveils[i])
			continue;
		unveil_op(UNVEILCTL_ENABLE, i,
		    unveil_slots_for[i][FOR_CUSTOM],
		    UPERM_NONE);
	}

	if (path) {
		unveil_slots slots = 0;
		for (int i = 0; i < ON_COUNT; i++)
			if (on[i])
				slots |= unveil_slots_for[i][FOR_CUSTOM];
		return (unveil_path(UNVEILCTL_NOINHERIT, slots, path, uperms));
	}

	/* Forbid ever raising current unveil permissions. */
	for (int i = 0; i < ON_COUNT; i++) {
		bool reserve;
		if (!on[i])
			continue;
		if (i == ON_EXEC && on[ON_SELF] && !has_pledge_unveils[i])
			continue;
		if ((reserve = !has_pledge_unveils[i] && !has_reserved_pledge_unveils[i]))
			/* Make calling pledge() after unveil(NULL, NULL) work. */
			reserve_pledge_unveils(i);
		unveil_op(UNVEILCTL_FREEZE, i,
		    reserve ? unveil_slots_for[i][FOR_PLEDGE] : 0, UPERM_NONE);
	}
	return (0);
}

int
unveil_1(const char *path, const bool on[ON_COUNT], const char *perms_str)
{
	unveil_perms uperms;
	int r;
	if ((perms_str == NULL) != (path == NULL)) {
		errno = EINVAL;
		return (-1);
	}
	if (perms_str) {
		r = unveil_parse_perms(&uperms, perms_str);
		if (r < 0) {
			errno = EINVAL;
			return (-1);
		}
	}
	return (do_unveil(path, on, uperms));
}

int
unveil(const char *path, const char *permissions)
{
	bool on[ON_COUNT] = { [ON_SELF] = true, [ON_EXEC] = true };
	/*
	 * XXX: unveil() is inherited on-exec on OpenBSD if the process has
	 * execpledges, but re-unveiling isn't allowed (yet).  If the process
	 * does not have execpledges, unveils are not inherited and the
	 * executed process can do its own unveiling.
	 */
	return (unveil_1(path, on, permissions));
}

int
unveilself(const char *path, const char *permissions)
{
	bool on[ON_COUNT] = { [ON_SELF] = true };
	return (unveil_1(path, on, permissions));
}

int
unveilexec(const char *path, const char *permissions)
{
	bool on[ON_COUNT] = { [ON_EXEC] = true };
	return (unveil_1(path, on, permissions));
}
