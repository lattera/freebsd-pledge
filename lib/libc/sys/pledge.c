#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <sys/_sysfil.h>
#include <sys/procctl.h>
#include <sys/unveil.h>

enum promise_type {
	PROMISE_NONE = 0,
	PROMISE_ERROR,
	PROMISE_CAPSICUM,
	PROMISE_STDIO,
	PROMISE__STDIO, /* stdio without unveils */
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

struct promise_unveil {
	const char *path;
	unveil_perms_t perms;
	enum promise_type type;
};

struct pledge_state {
	bool promises[PROMISE_COUNT];
};


static const struct promise_name promise_names[] = {
	{ "error",	PROMISE_ERROR },
	{ "capsicum",	PROMISE_CAPSICUM },
	{ "stdio",	PROMISE_STDIO },
	{ "_stdio",	PROMISE__STDIO },
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
	[PROMISE_ERROR] = SYF_PLEDGE_ERROR,
	[PROMISE_CAPSICUM] = SYF_CAPENABLED,
	[PROMISE_STDIO] = SYF_PLEDGE_STDIO | SYF_PLEDGE_UNVEIL, /* XXX */
	[PROMISE__STDIO] = SYF_PLEDGE_STDIO,
	[PROMISE_UNVEIL] = SYF_PLEDGE_UNVEIL,
	[PROMISE_RPATH] = SYF_PLEDGE_RPATH,
	[PROMISE_WPATH] = SYF_PLEDGE_WPATH,
	[PROMISE_CPATH] = SYF_PLEDGE_CPATH,
	[PROMISE_DPATH] = SYF_PLEDGE_DPATH,
	[PROMISE_TMPPATH] = SYF_PLEDGE_TMPPATH,
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

static const unveil_perms_t promise_uperms[PROMISE_COUNT] = {
	[PROMISE_RPATH] = UNVEIL_PERM_RPATH,
	[PROMISE_WPATH] = UNVEIL_PERM_WPATH,
	[PROMISE_CPATH] = UNVEIL_PERM_CPATH,
	[PROMISE_EXEC]  = UNVEIL_PERM_EXEC,
};

#define	R UNVEIL_PERM_RPATH
#define	W UNVEIL_PERM_WPATH
#define	C UNVEIL_PERM_CPATH
#define	X UNVEIL_PERM_EXEC

static struct promise_unveil promise_unveils[] = {
	{ "/", R,				PROMISE_RPATH },
	{ "/", W,				PROMISE_WPATH },
	{ "/", C,				PROMISE_CPATH },
	{ "/", X,				PROMISE_EXEC },
	{ "/etc/malloc.conf", R,		PROMISE_STDIO },
	{ "/etc/localtime", R,			PROMISE_STDIO },
	{ "/usr/share/zoneinfo/", R,		PROMISE_STDIO },
	{ "/usr/share/nls/", R,			PROMISE_STDIO },
	{ "/usr/local/share/nls/", R,		PROMISE_STDIO },
	/* Programs will often open /dev/null with O_CREAT.  TODO: Could have a
	 * different unveil() permission just for that. */
	{ "/dev/null", R|W|C,			PROMISE_STDIO },
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
	{ "/tmp/", R|W|C,			PROMISE_TMPPATH },
	{ "", 0,				PROMISE_NONE }
};

#undef	X
#undef	C
#undef	W
#undef	R


static int
parse_promises_1(struct pledge_state *pledge, char *promises)
{
	const char *promise;
	while ((promise = strsep(&promises, " ")))
		if (*promise) {
			const struct promise_name *pn;
			for (pn = promise_names; *pn->name; pn++)
				if (0 == strcmp(pn->name, promise))
					break;
			if (pn->type == PROMISE_NONE)
				return (-1);
			pledge->promises[pn->type] = true;
		}
	return (0);
}

static int
parse_promises(struct pledge_state *pledge, const char *promises)
{
	int r;
	char *s;
	s = strdup(promises);
	if (!s)
		return (-1);
	r = parse_promises_1(pledge, s);
	free(s);
	if (r < 0) {
		errno = EINVAL;
		return (r);
	}
	return (0);
}


static sysfil_t
uperms2sysfil(unveil_perms_t up)
{
	return (((up & UNVEIL_PERM_RPATH) ? SYF_PLEDGE_RPATH : 0) |
	        ((up & UNVEIL_PERM_WPATH) ? SYF_PLEDGE_WPATH : 0) |
	        ((up & UNVEIL_PERM_CPATH) ? SYF_PLEDGE_CPATH : 0) |
	        ((up & UNVEIL_PERM_EXEC)  ? SYF_PLEDGE_EXEC  : 0));
}

static bool unveils_sorted = false;

static int
unveil_cmp(const void *p0, const void *p1)
{
	const struct promise_unveil *u0 = p0, *u1 = p1;
	return (strcmp(u0->path, u1->path));
}

static void
sort_unveils(void)
{
	if (unveils_sorted)
		return;
	qsort(promise_unveils,
	    sizeof (promise_unveils) / sizeof (*promise_unveils) - 1,
	    sizeof *promise_unveils,
	    unveil_cmp);
	unveils_sorted = true;
}

static int
apply_pledge(struct pledge_state *req_pledge, struct pledge_state *cur_pledge,
    int procctl_cmd)
{
	struct promise_unveil *pu;
	sysfil_t sysfil;
	int r, i;
	sort_unveils();
	sysfil = SYF_PLEDGE_ALWAYS;
	for (i = 0; i < PROMISE_COUNT; i++)
		if (req_pledge->promises[i])
			sysfil |= promise_sysfils[i];
	for (pu = promise_unveils; *pu->path; pu++) {
		unveil_perms_t cur_uperms = 0, new_uperms = 0;
		do {
			if (req_pledge->promises[pu->type])
				new_uperms |= pu->perms;
			if (cur_pledge->promises[pu->type])
				cur_uperms |= pu->perms;
			if (strcmp(pu->path, (pu + 1)->path) != 0)
				break;
			pu++;
		} while (true);
		sysfil |= uperms2sysfil(new_uperms);
		if (new_uperms) {
			r = unveilctl(AT_FDCWD, pu->path, 0, new_uperms);
			if (r < 0 && errno != ENOENT)
				warn("unveil(\"%s\", \"%u\")", pu->path, new_uperms);
		} else if (cur_uperms) {
			/* undo unveils for previous pledge, if any */
			/* XXX: This should drop the unveil instead of removing
			 * permissions so that it doesn't mask a parent unveil
			 * (possibly added by the application). */
			r = unveilctl(AT_FDCWD, pu->path, 0, 0);
			if (r < 0 && errno != ENOENT)
				warn("unveil(\"%s\", %u)", pu->path, 0);
		}
	}
	/* TODO: freeze unveils */
	r = procctl(P_PID, getpid(), procctl_cmd, &sysfil);
	if (r < 0)
		return (-1);
	return (0);
}

static struct pledge_state current_pledge, current_execpledge;

static int
do_pledge(const char *promises, bool for_exec)
{
	struct pledge_state req_pledge = { 0 }, *cur_pledge;
	int r;
	r = parse_promises(&req_pledge, promises);
	if (r < 0)
		return (-1);
	cur_pledge = for_exec ? &current_execpledge : &current_pledge;
	r = apply_pledge(&req_pledge, cur_pledge,
	    for_exec ? PROC_SYSFIL_EXEC : PROC_SYSFIL);
	if (r < 0)
		return (-1);
	*cur_pledge = req_pledge;
	return (0);
}

int
pledge(const char *promises, const char *execpromises)
{
#ifdef PLEDGE
	/* TODO: global lock */
	int r;
	if (promises) {
		r = do_pledge(promises, false);
		if (r < 0)
			return (-1);
	}
	if (execpromises) {
		r = do_pledge(execpromises, true);
		if (r < 0)
			return (-1);
	}
	return (0);
#else
	errno = ENOSYS;
	return (-1);
#endif
}
