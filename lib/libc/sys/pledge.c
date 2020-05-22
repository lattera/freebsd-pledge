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

struct promise_unveil {
	const char *path;
	unveil_perms_t perms;
	enum promise_type type;
};


enum unveil_type {
	SLOT_PROMISE,
	SLOT_EXECPROMISE,
	SLOT_CUSTOM,
	SLOT_EXECCUSTOM,
	SLOT_COUNT
};

struct unveil_node {
	struct unveil_node *parent, *sibling, *children;
	unveil_perms_t rem_perms[SLOT_COUNT];
	unveil_perms_t add_perms[SLOT_COUNT];
	int last_errno;
	bool dirty, has_dirty;
	char name[];
};

static struct {
	struct unveil_node *unveils;
	unveil_perms_t retained_perms, retained_execperms;
	bool initial;
	bool inhibit_root[SLOT_COUNT];
	bool promises[PROMISE_COUNT], execpromises[PROMISE_COUNT];
} state = { .initial = true, .retained_perms = -1, .retained_execperms = -1 };


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

#define	R UNVEIL_PERM_RPATH
#define	W UNVEIL_PERM_WPATH
#define	C UNVEIL_PERM_CPATH
#define	X UNVEIL_PERM_XPATH

static const struct promise_unveil promise_unveils[] = {
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


static const char *
skip_extra_path_prefix(const char *p)
{
	/*
	 * This does some trivial canonicalization.  If complex paths are used,
	 * custom and promise unveil permissions may interfere with each others.
	 */
	while (true) {
		if (*p == '/') {
			p++;
			if (p[0] == '.' && p[1] == '/')
				p += 2;
		} else
			break;
	}
	return (p);
}

static struct unveil_node *
get_unveil(const char *path, const char **rest, bool insert)
{
	struct unveil_node **link, *parent;
	const char *next;
	parent = NULL;
	link = &state.unveils;
	/* start with empty path component for root node */
	next = path;
	do {
		if (!*link) {
			struct unveil_node *node;
			if (!insert)
				return (NULL);
			node = malloc(sizeof *node + (next - path) + 1);
			if (!node)
				return (NULL);
			*node = (struct unveil_node){ .parent = parent };
			memcpy(node->name, path, next - path);
			node->name[next - path] = '\0';
			*link = node;
		}
		path = skip_extra_path_prefix(next);
		next = strchrnul(path, '/');
		if (next == path)
			return (*link);
		parent = *link;
		for (link = &(**link).children;
		    *link;
		    link = &(**link).sibling) {
			const char *p, *q;
			for (p = path, q = (**link).name;
			    *p == *q && p != next;
			    p++, q++);
			if (p == next)
				break;
		}
	} while (true);
}

static inline void
dirty_unveil(struct unveil_node *node)
{
	if (!node->dirty) {
		node->dirty = true;
		while ((node = node->parent) && !node->has_dirty)
			node->has_dirty = true;
	}
}

static void
set_unveil_perms(struct unveil_node *node,
    enum unveil_type type, unveil_perms_t rem_perms, unveil_perms_t add_perms)
{
	node->rem_perms[type] = rem_perms;
	node->add_perms[type] = add_perms;
	dirty_unveil(node);
}

static void
apply_unveils_1(struct unveil_node *node, unveil_perms_t *inherited_perms,
    char *path_prefix, bool dirty)
{
	char *path_end;
	unveil_perms_t all_perms[SLOT_COUNT];
	unsigned i;
	int r;

	path_end = path_prefix + strlen(path_prefix);
	*path_end = '/';
	strcpy(path_end + 1, node->name);

	for (i = 0; i < SLOT_COUNT; i++) {
		all_perms[i] = inherited_perms[i];
		all_perms[i] &= ~node->rem_perms[i];
		all_perms[i] |= node->add_perms[i];
	}

	node->last_errno = 0;
	if (dirty || (dirty = node->dirty)) {
		r = unveilctl(AT_FDCWD, path_prefix, 0,
		    all_perms[SLOT_PROMISE] | all_perms[SLOT_CUSTOM],
		    all_perms[SLOT_EXECPROMISE] | all_perms[SLOT_EXECCUSTOM]);
		if (r < 0) {
			if (errno != ENOENT) {
				/* XXX: This is fragile. */
				node->last_errno = errno;
				warn("unveil %s", path_prefix);
			}
		}
	}

	if (dirty || node->has_dirty) {
		struct unveil_node *child;
		for (child = node->children; child; child = child->sibling)
			apply_unveils_1(child, all_perms, path_prefix, dirty);
	}

	*path_end = '\0';
	node->dirty = node->has_dirty = false;
}

static void
apply_unveils(bool all)
{
	char path_buf[PATH_MAX] = ""; /* XXX: length */
	unveil_perms_t all_perms[SLOT_COUNT] = { 0 };
	if (!state.unveils)
		return;
	apply_unveils_1(state.unveils, all_perms, path_buf, all);
}


static void
limit_unveils_1(struct unveil_node *node,
    enum unveil_type type, unveil_perms_t limit)
{
	struct unveil_node *parent;
	unveil_perms_t *p, b;
	p = &node->add_perms[type];
	b = *p;
	*p &= limit;
	if (*p != b)
		dirty_unveil(node);
	for (node = (parent = node)->children; node; node = node->sibling)
		limit_unveils_1(node, type, limit);
}

static void
limit_unveils(enum unveil_type type, unveil_perms_t limit)
{
	if (!state.unveils)
		return;
	limit_unveils_1(state.unveils, type, limit);
}


static int
flush_restrict_unveils(unveil_perms_t retained_perms, unveil_perms_t retained_execperms)
{
	bool errors = false;
	int r;
	/*
	 * If no unveiling has been done yet, do a "sweep" to get rid of any
	 * inherited unveils.  After a sweep, all unveils become "inactive" and
	 * generally behave as if they were not there, but they still keep
	 * track of their "hard" permissions.  This allows to re-add them with
	 * those permissions if needed.
	 */
	if (state.initial) {
		r = unveilctl(-1, NULL, UNVEIL_FLAG_SWEEP, -1, -1);
		if (r < 0) {
			errors = true;
			warn("unveilctl sweep");
		}
	}
	/*
	 * If doing a sweep, re-apply all of our unveils to keep them active.
	 * If not, only apply the modified ones.
	 */
	apply_unveils(state.initial);
	/*
	 * "Harden" unveil permissions, if needed.  The general idea is that
	 * after hardening it should not be possible to regain any permissions
	 * not within the passed "retained" sets.
	 */
	if (state.retained_perms & ~retained_perms ||
	    state.retained_execperms & ~retained_execperms) {
		r = unveilctl(-1, NULL, UNVEIL_FLAG_RESTRICT,
		    retained_perms, retained_execperms);
		if (r < 0) {
			errors = true;
			warn("unveilctl restrict");
		}
	}
	/* Done. */
	state.initial = false;
	state.retained_perms = retained_perms;
	state.retained_execperms = retained_execperms;
	return (errors ? -1 : 0);
}

static int
flush_unveils(void)
{
	return (flush_restrict_unveils(state.retained_perms, state.retained_execperms));
}

static int
merge_promises_unveils(enum unveil_type type, sysfil_t *sysfil,
    const bool *cur_promises, const bool *req_promises)
{
	const struct promise_unveil *pu;
	for (pu = promise_unveils; *pu->path; pu++) {
		struct unveil_node *node;
		if (cur_promises[pu->type] != req_promises[pu->type]) {
			const char *path;
			unveil_perms_t perms;
			path = pu->path;
			if (path == root_path) {
				/*
				 * The unveil on "/" is only there to
				 * compensate for the other unveils that might
				 * be needed for certain promises.  Once the
				 * user does an explicit unveil(), filesystem
				 * access must be restricted to what has been
				 * explicitly unveiled.
				 */
				if (state.inhibit_root[type])
					continue;
			} else if (path == tmp_path) {
				char *tmpdir;
				if ((tmpdir = getenv("TMPDIR")))
					path = tmpdir;
			}
			node = get_unveil(path, NULL, true);
			if (!node)
				return (-1);
			perms = node->add_perms[type];
			if (req_promises[pu->type])
				perms |= pu->perms;
			else
				perms &= ~pu->perms;
			set_unveil_perms(node, type, 0, perms);
		}
		if (req_promises[pu->type] && pu->perms) {
			/* unveil won't work if sysfil blocks all accesses */
			*sysfil |= uperms2sysfil(pu->perms);
			/* maintain ability to drop the unveil later on */
			*sysfil |= SYF_PLEDGE_UNVEIL;
		}
	}
	return (0);
}

static int
update_promises_unveils(
    unveil_perms_t *retained_perms,
    sysfil_t *ret_sysfil,
    bool *cur_promises, const bool *req_promises,
    enum unveil_type promise_type, enum unveil_type custom_type)
{
	bool errors = false;
	sysfil_t sysfil, req_sysfil;
	int r, i;

	/* Map promises to sysfils. */

	req_sysfil = SYF_PLEDGE_ALWAYS;
	for (i = 0; i < PROMISE_COUNT; i++)
		if (req_promises[i])
			req_sysfil |= promise_sysfils[i];

	/*
	 * Figure out what unveils will be needed for these promises.  Also
	 * figure out what additional sysfils might be needed to make these
	 * unveils work.
	 */

	sysfil = req_sysfil;
	r = merge_promises_unveils(promise_type, &sysfil,
	    cur_promises, req_promises);
	if (r < 0)
		errors = true;

	/*
	 * Alter user's explicit unveils to compensate for sysfils implicitly
	 * enabled for promises.  Disabling a sysfil requests that certain file
	 * operations be forbidden altogether, but promises are exceptions to
	 * that.  Since we use unveils to implement these exceptions, add the
	 * restrictions to the user's unveils to get a similar effect.
	 */

	if (sysfil2uperms(req_sysfil) != sysfil2uperms(sysfil))
		limit_unveils(custom_type, sysfil2uperms(req_sysfil));

	if (req_sysfil & SYF_PLEDGE_UNVEIL)
		*retained_perms = sysfil2uperms(req_sysfil);
	else
		*retained_perms = 0;
	*ret_sysfil = sysfil;
	return (errors ? -1 : 0);
}

/*
 * TODO: Handle partial failure better.
 */

static int
do_pledge(const bool *promises, const bool *execpromises)
{
	bool errors = false;
	sysfil_t sysfil, execsysfil;
	unveil_perms_t retained_perms, retained_execperms;
	pid_t pid;
	int r;

	if (promises) {
		r = update_promises_unveils(
		    &retained_perms, &sysfil,
		    state.promises, promises,
		    SLOT_PROMISE, SLOT_CUSTOM);
		if (r < 0)
			return (-1);
	} else
		retained_perms = state.retained_perms;
	if (execpromises) {
		r = update_promises_unveils(
		    &retained_execperms, &execsysfil,
		    state.execpromises, execpromises,
		    SLOT_EXECPROMISE, SLOT_EXECCUSTOM);
		if (r < 0)
			return (-1);
	} else
		retained_execperms = state.retained_execperms;

	r = flush_restrict_unveils(retained_perms, retained_execperms);
	if (r < 0)
		errors = true;

	pid = getpid();
	if (promises) {
		r = procctl(P_PID, pid, PROC_SYSFIL, &sysfil);
		if (r < 0)
			errors = true;
		memcpy(state.promises, promises,
		    PROMISE_COUNT * sizeof *promises);
	}
	if (execpromises) {
		r = procctl(P_PID, pid, PROC_SYSFIL_EXEC, &execsysfil);
		if (r < 0)
			errors = true;
		memcpy(state.execpromises, execpromises,
		    PROMISE_COUNT * sizeof *execpromises);
	}

	return (errors ? -1 : 0);
}

int
pledge(const char *promises_str, const char *execpromises_str)
{
	bool promises[PROMISE_COUNT] = { 0 };
	bool execpromises[PROMISE_COUNT] = { 0 };
	int r;
	/* TODO: global lock */
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
	r = do_pledge(promises_str ? promises : NULL,
	    execpromises_str ? execpromises : NULL);
	return (r);
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
			errno = EINVAL;
			return (-1);
		}
	return (0);
}

static void
do_unveil_node(enum unveil_type promise_type, enum unveil_type custom_type,
    struct unveil_node *node, unveil_perms_t perms)
{
	if (!state.inhibit_root[promise_type]) {
		/*
		 * After the first call to unveil(), filesystem access must be
		 * restricted to what has been explicitly unveiled (modifying
		 * or adding unveils with higher permissions is still permitted
		 * within the constraints of the unveils' hard permissions).
		 * The pledge() wrapper may have unveiled "/" for certain
		 * promises.  This must be undone.
		 */
		struct unveil_node *root;
		root = get_unveil(root_path, NULL, false);
		if (root)
			set_unveil_perms(root, promise_type, -1, 0);
		state.inhibit_root[promise_type] = true;
	}
	if (node)
		set_unveil_perms(node, custom_type, -1, perms);
}

static int
do_unveil(const char *path,
    const unveil_perms_t *perms, const unveil_perms_t *execperms)
{
	struct unveil_node *node;
	int r;
	if (path) {
		node = get_unveil(path, NULL, true);
		if (!node)
			return (-1);
	} else
		node = NULL;

	if (perms)
		do_unveil_node(SLOT_PROMISE, SLOT_CUSTOM, node, *perms);
	if (execperms)
		do_unveil_node(SLOT_EXECPROMISE, SLOT_EXECCUSTOM, node, *execperms);

	/*
	 * XXX: This also disallows unveils that future pledge promise may need
	 * to add.
	 */
	r = flush_restrict_unveils(
	    path || !perms ? state.retained_perms : 0,
	    path || !execperms ? state.retained_execperms : 0);
	if (r < 0)
		return (-1);

	if (node && node->last_errno) {
		errno = node->last_errno;
		return (-1);
	}
	return (0);
}

/*
 * Allows to set the current and on-execute permissions separately.  A NULL
 * permission string means to not change the corresponding unveil state at all
 * (like for pledge()).  To request disabling future unveil calls, a NULL path
 * and an empty permissions string should be passed.
 */

static int
unveil2(const char *path, const char *perms_str, const char *execperms_str)
{
	unveil_perms_t perms, execperms;
	int r;
	/* TODO: global lock */
	if (perms_str) {
		r = unveil_parse_perms(&perms, perms_str);
		if (r < 0)
			return (-1);
	}
	if (execperms_str) {
		r = unveil_parse_perms(&execperms, execperms_str);
		if (r < 0)
			return (-1);
	}
	r = do_unveil(path,
	    perms_str ? &perms : NULL,
	    execperms_str ? &execperms : NULL);
	return (r);
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
	if ((permissions == NULL) != (path == NULL)) {
		errno = EINVAL;
		return (-1);
	}
	if (!permissions)
		permissions = "";
	return (unveil2(path, permissions, permissions));
}

int
unveilexec(const char *path, const char *permissions)
{
	if ((permissions == NULL) != (path == NULL)) {
		errno = EINVAL;
		return (-1);
	}
	if (!permissions)
		permissions = "";
	return (unveil2(path, NULL, permissions));
}
