#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_capsicum.h"

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/ucred.h>
#include <sys/syslog.h>
#include <sys/jail.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/unveil.h>

#ifdef UNVEIL

MALLOC_DEFINE(M_UNVEIL, "unveil", "unveil");

static bool __read_mostly unveil_enabled = true;
SYSCTL_BOOL(_kern, OID_AUTO, unveil_enabled, CTLFLAG_RW,
	&unveil_enabled, 0, "Allow unveil usage");

static unsigned int __read_mostly unveil_max_nodes_per_process = 128;
SYSCTL_UINT(_kern, OID_AUTO, maxunveilsperproc, CTLFLAG_RW,
	&unveil_max_nodes_per_process, 0, "Maximum unveils allowed per process");


enum unveil_role {
	UNVEIL_ROLE_CURR,
	UNVEIL_ROLE_EXEC,
};

enum { UNVEIL_SLOT_COUNT = 2 };

struct unveil_node {
	struct unveil_node *cover;
	RB_ENTRY(unveil_node) entry;
	/*
	 * If name is NULL, the node is not name-based and vp is a directly
	 * unveiled vnode.  Otherwise, vp is the vnode of a parent directory
	 * under which the name is unveiled.
	 */
	struct vnode *vp;
	char *name;
	u_char name_len;
	bool fully_covered;
	unveil_perms_t frozen_perms[UNVEIL_ROLE_COUNT];
	unveil_perms_t wanted_perms[UNVEIL_ROLE_COUNT][UNVEIL_SLOT_COUNT];
	bool wanted_final[UNVEIL_ROLE_COUNT][UNVEIL_SLOT_COUNT];
};

CTASSERT(NAME_MAX <= UCHAR_MAX);


static const unveil_perms_t uperms_noninheritable = UPERM_INSPECT | UPERM_TMPPATH;

static inline unveil_perms_t
unveil_uperms_expand(unveil_perms_t perms)
{
	if (perms & UPERM_RPATH) {
		perms |= UPERM_INSPECT;
		if (perms & UPERM_WPATH && perms & UPERM_CPATH)
			perms |= UPERM_TMPPATH;
	}
	return (perms);
}


static unveil_perms_t
unveil_node_soft_perms(struct unveil_node *node, enum unveil_role role)
{
	struct unveil_node *node1;
	bool inherited_final[UNVEIL_SLOT_COUNT];
	unveil_perms_t inherited_perms[UNVEIL_SLOT_COUNT], soft_perms;
	bool all_final;
	int i;
	/*
	 * Go up the node chain until all wanted permissions have been found
	 * without any more inheritance required.
	 */
	for (all_final = true, i = 0; i < UNVEIL_SLOT_COUNT; i++) {
		inherited_perms[i] = node->wanted_perms[role][i];
		if (!(inherited_final[i] = node->wanted_final[role][i]))
			all_final = false;
	}
	for (node1 = node->cover; !all_final && node1; node1 = node1->cover)
		for (all_final = true, i = 0; i < UNVEIL_SLOT_COUNT; i++)
			if (!inherited_final[i]) {
				inherited_perms[i] |= node1->wanted_perms[role][i] &
				    ~uperms_noninheritable;
				if (!(inherited_final[i] = node1->wanted_final[role][i]))
					all_final = false;
			}
	/* Merge wanted permissions from all slots */
	soft_perms = UPERM_NONE;
	for (i = 0; i < UNVEIL_SLOT_COUNT; i++)
		soft_perms |= inherited_perms[i];
	return (soft_perms);
}

static void
unveil_node_freeze(struct unveil_node *node, enum unveil_role role, unveil_perms_t keep)
{
	node->frozen_perms[role] =
	    unveil_uperms_expand(node->frozen_perms[role]) &
	    unveil_uperms_expand(keep | unveil_node_soft_perms(node, role));
}

static void
unveil_node_exec_to_curr(struct unveil_node *node)
{
	const int s = UNVEIL_ROLE_EXEC, d = UNVEIL_ROLE_CURR;
	unveil_node_freeze(node, s, UPERM_NONE);
	node->frozen_perms[d] = node->frozen_perms[s];
	for (int i = 0; i < UNVEIL_SLOT_COUNT; i++) {
		node->wanted_perms[d][i] = node->wanted_perms[s][i];
		node->wanted_final[d][i] = node->wanted_final[s][i];
	}
}


static inline int
memcmplen(const char *p0, size_t l0, const char *p1, size_t l1)
{
	int r;
	if (!(p0 && p1))
		return (p0 ? 1 : p1 ? -1 : 0);
	r = memcmp(p0, p1, MIN(l0, l1));
	if (r != 0)
		return (r);
	return (l0 > l1 ? 1 : l0 < l1 ? -1 : 0);
}

static int
unveil_node_cmp(struct unveil_node *n0, struct unveil_node *n1)
{
	uintptr_t p0 = (uintptr_t)n0->vp, p1 = (uintptr_t)n1->vp;
	return (p0 > p1 ? 1 : p0 < p1 ? -1 :
	    memcmplen(n0->name, n0->name_len, n1->name, n1->name_len));
}

RB_GENERATE_STATIC(unveil_node_tree, unveil_node, entry, unveil_node_cmp);


static void
unveil_check(struct unveil_base *base)
{
#ifdef INVARIANTS
	for (int i = 0; i < UNVEIL_ROLE_COUNT; i++)
		KASSERT(base->active[i] || !base->frozen[i],
		    ("unveils frozen but not active"));
#endif
}

static void
unveil_init(struct unveil_base *base)
{
	*base = (struct unveil_base){
		.root = RB_INITIALIZER(&base->root),
	};
	unveil_check(base);
}

static struct unveil_node *unveil_insert(struct unveil_base *, struct vnode *,
    const char *name, size_t name_len, bool *inserted);
static struct unveil_node *unveil_lookup(struct unveil_base *, struct vnode *,
    const char *name, size_t name_len);

static void
unveil_merge(struct unveil_base *dst, struct unveil_base *src)
{
	struct unveil_node *dst_node, *src_node;
	int i, j;
	for (i = 0; i < UNVEIL_ROLE_COUNT; i++) {
		dst->active[i] = src->active[i];
		dst->frozen[i] = src->frozen[i];
	}
	/* first pass, copy the nodes without cover links */
	RB_FOREACH(src_node, unveil_node_tree, &src->root) {
		dst_node = unveil_insert(dst, src_node->vp,
		    src_node->name, src_node->name_len, NULL);
		dst_node->fully_covered = src_node->fully_covered;
		for (i = 0; i < UNVEIL_ROLE_COUNT; i++) {
			dst_node->frozen_perms[i] = src_node->frozen_perms[i];
			for (j = 0; j < UNVEIL_SLOT_COUNT; j++) {
				dst_node->wanted_perms[i][j] = src_node->wanted_perms[i][j];
				dst_node->wanted_final[i][j] = src_node->wanted_final[i][j];
			}
		}
	}
	/* second pass, fixup the cover links */
	RB_FOREACH(src_node, unveil_node_tree, &src->root) {
		if (!src_node->cover)
			continue;
		dst_node = unveil_lookup(dst, src_node->vp,
		    src_node->name, src_node->name_len);
		KASSERT(dst_node, ("unveil node missing"));
		dst_node->cover = unveil_lookup(dst, src_node->cover->vp,
		    src_node->cover->name, src_node->cover->name_len);
		KASSERT(dst_node->cover, ("cover unveil node missing"));
	}
	unveil_check(dst);
}

static void
unveil_node_remove(struct unveil_base *base, struct unveil_node *node)
{
	RB_REMOVE(unveil_node_tree, &base->root, node);
	base->node_count--;
	vrele(node->vp);
	free(node, M_UNVEIL);
}

static void
unveil_clear(struct unveil_base *base)
{
	struct unveil_node *node, *node_tmp;
	RB_FOREACH_SAFE(node, unveil_node_tree, &base->root, node_tmp)
	    unveil_node_remove(base, node);
	MPASS(base->node_count == 0);
}

static void
unveil_free(struct unveil_base *base)
{
	unveil_clear(base);
}

static struct unveil_node *
unveil_insert(struct unveil_base *base, struct vnode *vp,
    const char *name, size_t name_len, bool *inserted)
{
	struct unveil_node *new, *old;
	new = malloc(sizeof *new + (name ? name_len + 1 : 0), M_UNVEIL, M_WAITOK);
	*new = (struct unveil_node){
		.vp = vp,
		.name = __DECONST(char *, name),
		.name_len = name_len,
	};
	old = RB_INSERT(unveil_node_tree, &base->root, new);
	if (old) {
		free(new, M_UNVEIL);
		if (inserted)
			*inserted = false;
		return (old);
	}
	if (name) {
		new->name = (char *)(new + 1);
		memcpy(new->name, name, name_len);
		new->name[name_len] = '\0'; /* not required by this code */
	}
	vref(vp);
	base->node_count++;
	if (inserted)
		*inserted = true;
	return (new);
}

static struct unveil_node *
unveil_lookup(struct unveil_base *base, struct vnode *vp, const char *name, size_t name_len)
{
	struct unveil_node key;
	key.vp = vp;
	key.name = __DECONST(char *, name);
	key.name_len = name_len;
	return (RB_FIND(unveil_node_tree, &base->root, &key));
}


void
unveil_fd_init(struct filedesc *fd)
{
	unveil_init(&fd->fd_unveil);
}

void
unveil_fd_merge(struct filedesc *dst_fdp, struct filedesc *src_fdp)
{
	unveil_merge(&dst_fdp->fd_unveil, &src_fdp->fd_unveil);
}

void
unveil_fd_free(struct filedesc *fdp)
{
	unveil_free(&fdp->fd_unveil);
}


bool
unveil_is_active(struct thread *td)
{
	return (td->td_proc->p_fd->fd_unveil.active[UNVEIL_ROLE_CURR]);
}

bool
unveil_exec_is_active(struct thread *td)
{
	return (td->td_proc->p_fd->fd_unveil.active[UNVEIL_ROLE_EXEC]);
}

void
unveil_proc_exec_switch(struct thread *td)
{
	struct filedesc *fdp = td->td_proc->p_fd;
	struct unveil_base *base = &fdp->fd_unveil;
	if ((base->active[UNVEIL_ROLE_CURR] = base->active[UNVEIL_ROLE_EXEC])) {
		base->frozen[UNVEIL_ROLE_CURR] = base->frozen[UNVEIL_ROLE_EXEC] = true;
		struct unveil_node *node, *node_tmp;
		RB_FOREACH_SAFE(node, unveil_node_tree, &base->root, node_tmp)
			unveil_node_exec_to_curr(node);
#if 0
		/*
		 * Since unveil_node_exec_to_curr() freezes the nodes (in a
		 * separate pass and with no extra retained permissions); it is
		 * possible to drop the inheritance from the wanted permissions.
		 */
		RB_FOREACH_SAFE(node, unveil_node_tree, &base->root, node_tmp)
			for (int i = 0; i < UNVEIL_ROLE_COUNT; i++) {
				unveil_perms_t perms = unveil_node_soft_perms(node, i);
				for (int j = 0; j < UNVEIL_SLOT_COUNT; j++) {
					node->wanted_perms[i][j] = perms;
					node->wanted_final[i][j] = true;
				}
			}
#endif
	} else {
		/*
		 * This is very important for SUID/SGID execution checks.  When
		 * unveil_exec_is_active() is false, unveil_proc_exec_switch()
		 * must provide a clean execution environment for programs with
		 * elevated privileges.
		 */
		base->frozen[UNVEIL_ROLE_CURR] = base->frozen[UNVEIL_ROLE_EXEC] = false;
		unveil_clear(base);
	}
	unveil_check(base);
}

#define	FOREACH_ROLE_FLAGS(flags, i) \
	for (i = 0; i < UNVEIL_ROLE_COUNT; i++) \
		if ((flags) & (1 << (UNVEILCTL_ROLE_SHIFT + i)))

#define	FOREACH_SLOT_FLAGS(flags, i, j) \
	FOREACH_ROLE_FLAGS(flags, i) \
		for (j = 0; j < UNVEIL_SLOT_COUNT; j++) \
			if ((flags) & (1 << (UNVEILCTL_SLOT_SHIFT + j)))

static int
unveil_remember(struct unveil_base *base,
    struct unveil_node **cover,
    int flags, unveil_perms_t perms,
    struct vnode *dvp, const char *name, size_t name_len, struct vnode *vp, bool final)
{
	struct unveil_node *node, *iter;
	bool inserted;
	int i, j;

	if (!name)
		node = unveil_insert(base, dvp, NULL, 0, &inserted);
	else if ((flags & UNVEILCTL_NONDIRBYNAME) && (!vp || vp->v_type != VDIR))
		node = unveil_insert(base, dvp, name, name_len, &inserted);
	else if (vp)
		node = unveil_insert(base, vp, NULL, 0, &inserted);
	else
		return (ENOENT);

	/*
	 * Update the cover link of the node.  If directories move around, the
	 * cover hierarchy might become out of date.  This is only updated when
	 * adding unveils for now.
	 *
	 * Note how allowing each process to potentially have its own "view" of
	 * the covering hierarchy has security implications on how the cover
	 * links are to be trusted.
	 */
	if (*cover) {
		for (iter = *cover; iter; iter = iter->cover)
			if (iter == node)
				break;
		if (!iter) /* prevent loops */
			node->cover = *cover;
	}

	/*
	 * Newly added unveil nodes can inherit frozen permissions from their
	 * most immediate covering node (if any).  Note that this is the
	 * covering node that was discovered while traversing the path, it does
	 * not come from a node's cover link.
	 */
	if (inserted)
		for (int i = 0; i < UNVEIL_ROLE_COUNT; i++)
			node->frozen_perms[i] =
			    *cover ? (*cover)->frozen_perms[i] & ~uperms_noninheritable :
			    base->frozen[i] ? UPERM_NONE : UPERM_ALL;
	*cover = node;

	if (flags & UNVEILCTL_INTERMEDIATE)
		node->fully_covered = true; /* cannot be turned off */

	if (name && final) {
		FOREACH_SLOT_FLAGS(flags, i, j) {
			node->wanted_perms[i][j] = perms;
			node->wanted_final[i][j] = (flags & UNVEILCTL_NOINHERIT) != 0;
		}
	} else if (flags & UNVEILCTL_INSPECTABLE) {
		FOREACH_SLOT_FLAGS(flags, i, j)
			node->wanted_perms[i][j] |= UPERM_INSPECT;
	}
	return (0);
}

static int
unveil_find_cover(struct thread *td, struct vnode *dp,
    struct unveil_node **cover, uint8_t *depth)
{
	struct filedesc *fdp = td->td_proc->p_fd;
	struct unveil_base *base = &fdp->fd_unveil;
	int error = 0;
	struct vnode *vp;
	struct componentname cn;

	error = vget(dp, LK_RETRY | LK_SHARED);
	if (error)
		return (error);

	while (true) {
		/* At the start of the loop, dp is locked (and referenced). */

		FILEDESC_SLOCK(fdp);
		*cover = unveil_lookup(base, dp, NULL, 0);
		FILEDESC_SUNLOCK(fdp);
		if (*cover)
			break; /* found unveil node */

		if (dp->v_vflag & VV_ROOT) {
			/*
			 * This is a mountpoint.  Before doing a ".." lookup,
			 * find the underlying directory it is mounted onto.
			 */
			if (!dp->v_mount || !(vp = dp->v_mount->mnt_vnodecovered))
				break;
			/* Must not lock parent while child lock is held. */
			vref(vp);
			vput(dp);
			error = vn_lock(vp, LK_RETRY | LK_SHARED);
			if (error) {
				vrele(vp);
				return (error); /* must not try to unlock */
			}
			dp = vp;
			/*
			 * The underlying directory could also be a mountpoint,
			 * and should be checked for unveils as well.
			 */
			continue;
		}

		cn = (struct componentname){
			.cn_nameiop = LOOKUP,
			.cn_flags = ISLASTCN | ISDOTDOT,
			.cn_lkflags = LK_SHARED,
			.cn_thread = td,
			.cn_cred = td->td_ucred,
			.cn_nameptr = "..",
			.cn_namelen = 2,
		};
		error = VOP_LOOKUP(dp, &vp, &cn);
		if (error)
			break;
		/* Now vp is the parent directory and dp the child directory. */
		if (dp == vp) {
			vrele(dp);
			break;
		}
		vput(dp);
		dp = vp;

		if (!++*depth)
			*depth = -1;
	}

	vput(dp);
	return (error);
}


struct unveil_save {
	int flags;
	unveil_perms_t perms;
};

int
unveil_traverse_begin(struct thread *td, struct unveil_traversal *trav,
    struct vnode *dvp)
{
	/* TODO: caching */
	trav->cover = NULL;
	trav->type = VDIR;
	trav->depth = 0;
	return (unveil_find_cover(td, dvp, &trav->cover, &trav->depth));
}

/*
 * dvp is a directory pointer (which may not be NULL).  If name is NULL, it
 * means that dvp is being descended into while looking up a path.  If name is
 * non-NULL, it means that the last path component has been located under dvp
 * with the given name.  vp may point to its vnode if it exists.  It's possible
 * for dvp and vp to be equal (in which case name should be "." or "").
 *
 * When following symlinks, there may be multiple "last" path components.  When
 * encountering a symlink that is to be followed, name will be non-NULL and
 * final will be false.  final will be true when the target file has been found
 * (which may not be a symlink if symlinks are to be followed).
 */

int
unveil_traverse(struct thread *td, struct unveil_traversal *trav,
    struct vnode *dvp, const char *name, size_t name_len, struct vnode *vp, bool final)
{
	struct filedesc *fdp = td->td_proc->p_fd;
	struct unveil_base *base = &fdp->fd_unveil;

	if (trav->save && (final || (trav->save->flags & UNVEILCTL_INTERMEDIATE))) {
		int error;
		if (name_len > NAME_MAX)
			return (ENAMETOOLONG);
		if (base->node_count >= unveil_max_nodes_per_process)
			return (E2BIG);

		FILEDESC_XLOCK(fdp);
		error = unveil_remember(base, &trav->cover,
		    trav->save->flags, trav->save->perms,
		    dvp, name, name_len, vp, final);
		FILEDESC_XUNLOCK(fdp);
		if (error)
			return (error);
		trav->depth = 0;

	} else {
		struct unveil_node *node;
		FILEDESC_SLOCK(fdp);
		if (vp)
			node = unveil_lookup(base, vp, NULL, 0);
		else
			node = NULL;
		if (!node)
			node = unveil_lookup(base, dvp, name, name_len);
		FILEDESC_SUNLOCK(fdp);
		if (node) {
			trav->cover = node;
			trav->depth = 0;
		} else {
			if (!++trav->depth)
				trav->depth = -1;
		}
	}

	trav->type = vp ? vp->v_type : VNON;
	return (0);
}

void
unveil_traverse_dotdot(struct thread *td, struct unveil_traversal *trav,
    struct vnode *dvp)
{
	struct filedesc *fdp = td->td_proc->p_fd;
	if (trav->cover && trav->depth == 0) {
		FILEDESC_SLOCK(fdp);
		trav->cover = trav->cover->fully_covered ? NULL : trav->cover->cover;
		FILEDESC_SUNLOCK(fdp);
	}
	trav->depth = -1;
	trav->type = VDIR;
}

unveil_perms_t
unveil_traverse_effective_uperms(struct thread *td, struct unveil_traversal *trav)
{
	struct filedesc *fdp = td->td_proc->p_fd;
	struct unveil_base *base = &fdp->fd_unveil;
	unveil_perms_t perms;
	FILEDESC_SLOCK(fdp);
	if (trav->cover) {
		perms = unveil_uperms_expand(
		    trav->cover->frozen_perms[UNVEIL_ROLE_CURR]);
		if (!trav->save)
			perms &= unveil_uperms_expand(
			    unveil_node_soft_perms(trav->cover, UNVEIL_ROLE_CURR));
	} else {
		if (trav->save)
			perms = base->frozen[UNVEIL_ROLE_CURR] ? UPERM_NONE : UPERM_ALL;
		else
			perms = base->active[UNVEIL_ROLE_CURR] ? UPERM_NONE : UPERM_ALL;
	}
	FILEDESC_SUNLOCK(fdp);
	/* NOTE: This function does not take the depth into consideration. */
	return (perms);
}

static void unveil_uperms_rights_1(unveil_perms_t, enum vtype type, uint8_t depth,
    cap_rights_t *);

void
unveil_traverse_effective_rights(struct thread *td, struct unveil_traversal *trav,
    cap_rights_t *rights, int *suggested_error)
{
	unveil_perms_t perms;
	perms = unveil_traverse_effective_uperms(td, trav);
	unveil_uperms_rights_1(perms, trav->type, trav->depth, rights);

	/* Kludge for directory O_EXEC/O_SEARCH opens. */
	if (trav->type == VDIR && (perms & UPERM_RPATH))
		cap_rights_set(rights, CAP_FEXECVE, CAP_EXECAT);
	/* Kludge for O_CREAT opens. */
	if (trav->type != VNON && (perms & UPERM_WPATH))
		cap_rights_set(rights, CAP_CREATE);

	if (suggested_error)
		*suggested_error = perms & ~UPERM_INSPECT ? EACCES : ENOENT;
}


static void
do_unveil_limit(struct unveil_base *base, int flags, unveil_perms_t perms)
{
	struct unveil_node *node;
	int i, j;
	RB_FOREACH(node, unveil_node_tree, &base->root)
		FOREACH_SLOT_FLAGS(flags, i, j)
			node->wanted_perms[i][j] &= unveil_uperms_expand(perms);
}

static void
do_unveil_freeze(struct unveil_base *base, int flags, unveil_perms_t perms)
{
	struct unveil_node *node;
	int i;
	FOREACH_ROLE_FLAGS(flags, i)
	    base->frozen[i] = base->active[i] = true;
	RB_FOREACH(node, unveil_node_tree, &base->root)
		FOREACH_ROLE_FLAGS(flags, i)
			unveil_node_freeze(node, i, perms);
}

static void
do_unveil_sweep(struct unveil_base *base, int flags)
{
	struct unveil_node *node;
	int i, j;
	RB_FOREACH(node, unveil_node_tree, &base->root)
		FOREACH_SLOT_FLAGS(flags, i, j) {
			node->wanted_perms[i][j] = UPERM_NONE;
			node->wanted_final[i][j] = false;
		}
}

#endif /* UNVEIL */

int
sys_unveilctl(struct thread *td, struct unveilctl_args *uap)
{
#ifdef UNVEIL
	struct filedesc *fdp = td->td_proc->p_fd;
	struct unveil_base *base = &fdp->fd_unveil;
	int flags = uap->flags;
	unveil_perms_t perms = uap->perms;

	if (!unveil_enabled)
		return (EPERM);

	if (uap->path != NULL) {
		struct unveil_save save = { flags, perms };
		struct nameidata nd;
		int error;
		int nd_flags;
		nd_flags = flags & UNVEILCTL_NOFOLLOW ? 0 : FOLLOW;
		NDINIT_ATRIGHTS(&nd, LOOKUP, nd_flags,
		    UIO_USERSPACE, uap->path, uap->atfd, &cap_fstat_rights, td);
		nd.ni_unveil.save = &save; /* checked in unveil_traverse() */
		error = namei(&nd);
		if (error)
			return (error);
		NDFREE(&nd, 0);
	}

	FILEDESC_XLOCK(fdp);

	if (flags & UNVEILCTL_ACTIVATE) {
		int i;
		FOREACH_ROLE_FLAGS(flags, i)
		    base->active[i] = true;
	}
	if (flags & UNVEILCTL_LIMIT)
		do_unveil_limit(base, flags, perms);
	if (flags & UNVEILCTL_FREEZE)
		do_unveil_freeze(base, flags, perms);
	if (flags & UNVEILCTL_SWEEP)
		do_unveil_sweep(base, flags);

	unveil_check(base);
	FILEDESC_XUNLOCK(fdp);
	return (0);
#else
	return (ENOSYS);
#endif /* UNVEIL */
}

#if defined(UNVEIL)

static cap_rights_t __read_mostly inspect_rights;
static cap_rights_t __read_mostly rpath_rights;
static cap_rights_t __read_mostly wpath_rights;
static cap_rights_t __read_mostly cpath_rights;
static cap_rights_t __read_mostly xpath_rights;
static cap_rights_t __read_mostly apath_rights;
static cap_rights_t __read_mostly tmppath_rights;
static cap_rights_t __read_mostly rcpath_rights;
static cap_rights_t __read_mostly rwcapath_rights;

static void
unveil_uperms_rights_1(unveil_perms_t perms, enum vtype type, uint8_t depth,
    cap_rights_t *rights)
{
	CAP_NONE(rights);
	if (perms & UPERM_INSPECT && depth == 0)
		cap_rights_merge(rights, &inspect_rights);
	if (perms & UPERM_RPATH)
		cap_rights_merge(rights, &rpath_rights);
	if (perms & UPERM_WPATH)
		cap_rights_merge(rights, &wpath_rights);
	if (perms & UPERM_CPATH) {
		cap_rights_merge(rights, &cpath_rights);
		if (perms & UPERM_RPATH)
			cap_rights_merge(rights, &rcpath_rights);
	}
	if (perms & UPERM_XPATH)
		cap_rights_merge(rights, &xpath_rights);
	if (perms & UPERM_APATH) {
		cap_rights_merge(rights, &apath_rights);
		if (perms & UPERM_CPATH && perms & UPERM_WPATH && perms & UPERM_RPATH)
			cap_rights_merge(rights, &rwcapath_rights);
	}
	if (perms & UPERM_TMPPATH) {
		if (depth == 0)
			cap_rights_merge(rights, &inspect_rights);
		else if (depth == 1 && (type == VNON || type == VREG))
			cap_rights_merge(rights, &tmppath_rights);
	}
}

void
unveil_uperms_rights(unveil_perms_t perms, cap_rights_t *rights)
{
	return (unveil_uperms_rights_1(perms, VBAD, 0, rights));
}

static void
unveil_sysinit(void *arg)
{
	cap_rights_init(&inspect_rights,
	    CAP_LOOKUP,
	    CAP_FPATHCONF,
	    CAP_FSTAT,
	    CAP_FSTATAT,
	    CAP_FCHDIR);
	cap_rights_init(&rpath_rights,
	    CAP_LOOKUP,
	    CAP_FLOCK,
	    CAP_READ,
	    CAP_SEEK,
	    CAP_FPATHCONF,
	    CAP_MMAP,
	    CAP_FCHDIR,
	    CAP_FSTAT,
	    CAP_FSTATAT,
	    CAP_FSTATFS,
	    CAP_MAC_GET,
	    CAP_EXTATTR_GET,
	    CAP_EXTATTR_LIST);
	cap_rights_init(&wpath_rights,
	    CAP_LOOKUP,
	    CAP_FLOCK,
	    CAP_WRITE,
	    CAP_SEEK,
	    CAP_FPATHCONF,
	    CAP_MMAP,
	    CAP_FSYNC,
	    CAP_FTRUNCATE);
	cap_rights_init(&cpath_rights,
	    CAP_LOOKUP,
	    CAP_CREATE,
	    CAP_FPATHCONF,
	    CAP_LINKAT_TARGET,
	    CAP_MKDIRAT,
	    CAP_MKFIFOAT,
	    CAP_MKNODAT,
	    CAP_SYMLINKAT,
	    CAP_UNLINKAT,
	    CAP_BINDAT,
	    CAP_CONNECTAT,
	    CAP_RENAMEAT_TARGET,
	    CAP_UNDELETEAT);
	cap_rights_init(&xpath_rights,
	    CAP_LOOKUP,
	    CAP_FEXECVE,
	    CAP_EXECAT);
	cap_rights_init(&apath_rights,
	    CAP_LOOKUP,
	    CAP_FCHFLAGS,
	    CAP_CHFLAGSAT,
	    CAP_FCHMOD,
	    CAP_FCHMODAT,
	    CAP_FCHOWN,
	    CAP_FCHOWNAT,
	    CAP_FUTIMES,
	    CAP_FUTIMESAT,
	    CAP_MAC_SET,
	    CAP_REVOKEAT,
	    CAP_EXTATTR_SET,
	    CAP_EXTATTR_DELETE);
	cap_rights_init(&tmppath_rights,
	    CAP_LOOKUP,
	    CAP_FSTAT,
	    CAP_FSTATAT,
	    CAP_FPATHCONF,
	    CAP_READ,
	    CAP_SEEK,
	    CAP_MMAP,
	    CAP_CREATE,
	    CAP_WRITE,
	    CAP_UNLINKAT,
	    CAP_FTRUNCATE);
	cap_rights_init(&rcpath_rights,
	    CAP_RENAMEAT_SOURCE);
	/*
	 * To prevent a file being linked in a target directory that was
	 * unveiled with more permissions than its source directory, require
	 * the source to have all permissions except UPERM_XPATH for now.
	 *
	 * UPERM_CPATH might arguably not be required (since directories cannot
	 * be hard linked), but it is probably safer to require it (even if
	 * only because it might be less surprising).
	 */
	cap_rights_init(&rwcapath_rights,
	    CAP_LINKAT_SOURCE);
}

SYSINIT(unveil_sysinit, SI_SUB_COPYRIGHT, SI_ORDER_ANY, unveil_sysinit, NULL);

#endif
