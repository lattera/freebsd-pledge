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
	UNVEIL_TYPE_PROMISE,
	UNVEIL_TYPE_EXECPROMISE,
	UNVEIL_TYPE_CUSTOM,
	UNVEIL_TYPE_EXECCUSTOM,
	UNVEIL_TYPE_COUNT
};

struct unveil_node {
	struct unveil_node *parent, *sibling, *children;
	unveil_perms_t rem_perms[UNVEIL_TYPE_COUNT];
	unveil_perms_t add_perms[UNVEIL_TYPE_COUNT];
	bool dirty;
	char name[];
};

static struct {
	bool promises[PROMISE_COUNT], execpromises[PROMISE_COUNT];
	struct unveil_node *unveils;
	bool has_custom_unveils;
	bool unveil_active;
	bool unveil_lockdown;
} state = { 0 };


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

static const char *const root_path = "/";
static const char *const tmp_path = _PATH_TMP;

#define	R UNVEIL_PERM_RPATH
#define	W UNVEIL_PERM_WPATH
#define	C UNVEIL_PERM_CPATH
#define	X UNVEIL_PERM_EXEC

static const struct promise_unveil promise_unveils[] = {
	{ root_path, R,				PROMISE_RPATH },
	{ root_path, W,				PROMISE_WPATH },
	{ root_path, C,				PROMISE_CPATH },
	{ root_path, X,				PROMISE_EXEC },
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
		((up & UNVEIL_PERM_EXEC)  ? SYF_PLEDGE_EXEC  : 0));
}

static unveil_perms_t
sysfil2uperms(sysfil_t sf)
{
	return (((sf & SYF_PLEDGE_RPATH) ? UNVEIL_PERM_RPATH : 0) |
		((sf & SYF_PLEDGE_WPATH) ? UNVEIL_PERM_WPATH : 0) |
		((sf & SYF_PLEDGE_CPATH) ? UNVEIL_PERM_CPATH : 0) |
		((sf & SYF_PLEDGE_EXEC)  ? UNVEIL_PERM_EXEC  : 0));
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
		if (node->parent)
			dirty_unveil(node->parent);
		node->dirty = true;
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

static int
apply_unveils_1(struct unveil_node *node, unveil_perms_t *inherited_perms,
    char *path_prefix, int flags, bool dirty)
{
	char *path_end;
	unveil_perms_t all_perms[UNVEIL_TYPE_COUNT];
	unsigned i;
	int r;
	bool errors = false;

	if (!(dirty || (dirty = node->dirty)))
		return (0);

	for (i = 0; i < UNVEIL_TYPE_COUNT; i++) {
		all_perms[i] = inherited_perms[i];
		all_perms[i] &= ~node->rem_perms[i];
		all_perms[i] |= node->add_perms[i];
	}

	path_end = path_prefix + strlen(path_prefix);
	*path_end = '/';
	strcpy(path_end + 1, node->name);
	r = unveilctl(AT_FDCWD, path_prefix, flags,
	    all_perms[UNVEIL_TYPE_PROMISE] |
	    all_perms[UNVEIL_TYPE_CUSTOM],
	    all_perms[UNVEIL_TYPE_EXECPROMISE] |
	    all_perms[UNVEIL_TYPE_EXECCUSTOM]);
	if (r < 0 && errno != ENOENT) {
		errors = true;
		warn("unveil %s", path_prefix);
	} else
		node->dirty = false;

	for (node = node->children; node; node = node->sibling) {
		r = apply_unveils_1(node, all_perms, path_prefix, flags, dirty);
		if (r < 0)
			errors = true;
	};

	*path_end = '\0';
	return (errors ? -1 : 0);
}

static int
apply_unveils(bool activate)
{
	char path_buf[PATH_MAX] = ""; /* XXX: length */
	unveil_perms_t all_perms[UNVEIL_TYPE_COUNT] = { 0 };
	int flags = activate ? UNVEIL_FLAG_ACTIVATE : 0;
	if (!state.unveils)
		return (0);
	return (apply_unveils_1(state.unveils, all_perms, path_buf, flags, false));
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
		node->dirty = true;
	for (node = (parent = node)->children; node; node = node->sibling) {
		limit_unveils_1(node, type, limit);
		if (node->dirty)
			parent->dirty = true;
	}
}

static void
limit_unveils(enum unveil_type type, unveil_perms_t limit)
{
	if (!state.unveils)
		return;
	limit_unveils_1(state.unveils, type, limit);
}


static int
unveil_activate(void) {
	int r;
	if (state.unveil_active)
		return (0);
	r = unveilctl(-1, NULL, UNVEIL_FLAG_ACTIVATE, 0, 0);
	if (r < 0)
		return (r);
	state.unveil_active = true;
	return (0);
}

static int
unveil_lockdown(void) {
	int r;
	if (state.unveil_lockdown)
		return (0);
	/* Disable any inherited unveils. */
	r = unveilctl(-1, NULL,
	    UNVEIL_FLAG_FOR_ALL | UNVEIL_FLAG_FROM_EXEC | UNVEIL_FLAG_MASK,
	    0, 0);
	if (r < 0)
		return (r);
	/* Activate/finish unveiling and make all permissions hard. */
	r = unveilctl(-1, NULL,
	    UNVEIL_FLAG_ACTIVATE | UNVEIL_FLAG_FINISH |
	    UNVEIL_FLAG_FOR_ALL | UNVEIL_FLAG_HARDEN | UNVEIL_FLAG_MASK,
	    -1, -1);
	if (r < 0)
		return (r);
	state.unveil_lockdown = true;
	return (0);
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
				if (state.has_custom_unveils)
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

/*
 * TODO: Handle partial failure better.
 */

static int
apply_pledge(bool finish, int procctl_cmd,
    bool *cur_promises, const bool *req_promises,
    enum unveil_type promise_type, enum unveil_type custom_type)
{
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
		return (-1);

	/*
	 * Alter user's explicit unveils to compensate for sysfils implicitly
	 * enabled for promises.  Disabling a sysfil requests that certain file
	 * operations be forbidden altogether, but promises are exceptions to
	 * that.  Since we use unveils to implement these exceptions, add the
	 * restrictions to the user's unveils to get a similar effect.
	 */

	if (sysfil2uperms(req_sysfil) != sysfil2uperms(sysfil))
		limit_unveils(custom_type,
		    sysfil2uperms(req_sysfil) | UNVEIL_PERM_ERROR);

	/* Apply modified unveils. */

	apply_unveils(false);

	/* Activate and lockdown unveiling if needed. */

	if (finish) {
		if (req_sysfil & SYF_PLEDGE_UNVEIL)
			r = unveil_activate();
		else
			r = unveil_lockdown();
		if (r < 0)
			return (-1);
	}

	/* Finally apply sysfils. */

	r = procctl(P_PID, getpid(), procctl_cmd, &sysfil);
	if (r < 0)
		return (-1);

	/* Remember which promises were applied. */
	memcpy(cur_promises, req_promises, PROMISE_COUNT * sizeof *cur_promises);

	return (0);
}

static int
do_pledge(const char *promises_str, const char *execpromises_str)
{
	bool promises[PROMISE_COUNT] = { 0 };
	bool execpromises[PROMISE_COUNT] = { 0 };
	int r;
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

	if (execpromises_str) {
		/* Doing this one first to avoid sysfil interferences. */
		r = apply_pledge(!promises_str,
		    PROC_SYSFIL_EXEC,
		    state.execpromises, execpromises,
		    UNVEIL_TYPE_EXECPROMISE,
		    UNVEIL_TYPE_EXECCUSTOM);
		if (r < 0)
			return (-1);
	}
	if (promises_str) {
		r = apply_pledge(true,
		    PROC_SYSFIL,
		    state.promises, promises,
		    UNVEIL_TYPE_PROMISE,
		    UNVEIL_TYPE_CUSTOM);
		if (r < 0)
			return (-1);
	}
	return (0);
}

int
pledge(const char *promises, const char *execpromises)
{
	/* TODO: global lock */
	int r;
	r = do_pledge(promises, execpromises);
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
		case 'x': *perms |= UNVEIL_PERM_EXEC;  break;
		default:
			errno = EINVAL;
			return (-1);
		}
	return (0);
}

static int
do_unveil(const char *path, const char *perms_str)
{
	int r;
	struct unveil_node *node;
	unveil_perms_t perms;
	int flags;

	flags |= UNVEIL_FLAG_ACTIVATE;

	if (!path && !perms_str)
		/*
		 * XXX: This also disallows any unveils that future pledge
		 * promise may need to add.
		 */
		return (unveil_lockdown());

	r = unveil_parse_perms(&perms, perms_str);
	if (r < 0)
		return (-1);

	if (!state.has_custom_unveils) {
		/*
		 * After the first call to unveil(), filesystem access must be
		 * restricted to what has been explicitly unveiled (modifying
		 * or adding unveils with higher permissions is still
		 * permitted).  After UNVEIL_FLAG_ACTIVATE is used, filesystem
		 * access is restricted to paths that have been unveiled, but
		 * the pledge() wrapper may have unveiled "/" for certain
		 * promises.  This must be undone.
		 */
		state.has_custom_unveils = true;
		node = get_unveil(root_path, NULL, false);
		if (node) {
			set_unveil_perms(node, UNVEIL_TYPE_PROMISE, -1, 0);
			set_unveil_perms(node, UNVEIL_TYPE_EXECPROMISE, -1, 0);
		}
	}

	node = get_unveil(path, NULL, true);
	if (!node)
		return (-1);
	perms |= UNVEIL_PERM_ERROR;
	set_unveil_perms(node, UNVEIL_TYPE_CUSTOM, -1, perms);
	set_unveil_perms(node, UNVEIL_TYPE_EXECCUSTOM, -1, perms);
	return (apply_unveils(true));
}

int
unveil(const char *path, const char *permissions)
{
	/* TODO: global lock */
	int r;
	r = do_unveil(path, permissions);
	return (r);
}
