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

static bool unveil_enabled = true;
SYSCTL_BOOL(_kern, OID_AUTO, unveil_enabled, CTLFLAG_RW,
	&unveil_enabled, 0, "Allow unveil usage");

static unsigned int unveil_max_nodes_per_process = 128;
SYSCTL_UINT(_kern, OID_AUTO, maxunveilsperproc, CTLFLAG_RW,
	&unveil_max_nodes_per_process, 0, "Maximum unveils allowed per process");


enum unveil_role {
	UNVEIL_ROLE_CURR,
	UNVEIL_ROLE_EXEC,
};

enum {
	UNVEIL_ROLE_COUNT = 2,
	UNVEIL_SLOT_COUNT = 2,
};

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


static unveil_perms_t
unveil_node_soft_perms(struct unveil_node *node, enum unveil_role role)
{
	struct unveil_node *node1;
	bool inherited_final[UNVEIL_SLOT_COUNT];
	unveil_perms_t inherited_perms[UNVEIL_SLOT_COUNT], soft_perms, mask;
	bool all_final;
	int i;
	for (i = 0; i < UNVEIL_SLOT_COUNT; i++) {
		inherited_final[i] = false;
		inherited_perms[i] = UNVEIL_PERM_NONE;
	}
	/*
	 * Go up the node chain until all wanted permissions have been found
	 * without any more inheritance required.
	 */
	node1 = node;
	mask = UNVEIL_PERM_ALL;
	do {
		all_final = true;
		for (i = 0; i < UNVEIL_SLOT_COUNT; i++)
			if (!inherited_final[i]) {
				inherited_perms[i] |= node1->wanted_perms[role][i] & mask;
				if (!(inherited_final[i] = node1->wanted_final[role][i]))
					all_final = false;
			}
		mask &= ~UNVEIL_PERM_NONINHERITED_MASK;
	} while (!all_final && (node1 = node1->cover));
	/*
	 * Merge wanted permissions and mask them with the frozen permissions.
	 */
	soft_perms = UNVEIL_PERM_NONE;
	for (i = 0; i < UNVEIL_SLOT_COUNT; i++)
		soft_perms |= inherited_perms[i];
	soft_perms &= node->frozen_perms[role];
	return (soft_perms);
}


static void
unveil_node_freeze(struct unveil_node *node, enum unveil_role role, unveil_perms_t keep)
{
	node->frozen_perms[role] &= keep | unveil_node_soft_perms(node, role);
}

static void
unveil_node_exec_to_curr(struct unveil_node *node, bool simplify)
{
	const int s = UNVEIL_ROLE_EXEC, d = UNVEIL_ROLE_CURR;
	int i;
	if (simplify) {
		unveil_perms_t perms;
		perms = unveil_node_soft_perms(node, s);
		for (i = 0; i < UNVEIL_SLOT_COUNT; i++) {
			node->wanted_perms[s][i] = perms;
			node->wanted_final[s][i] = true;
		}
	}
	node->frozen_perms[d] = node->frozen_perms[s];
	for (i = 0; i < UNVEIL_SLOT_COUNT; i++)
		node->wanted_perms[d][i] = node->wanted_perms[s][i];
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
unveil_init(struct unveil_base *base)
{
	*base = (struct unveil_base){
		.root = RB_INITIALIZER(&base->root),
	};
}

static struct unveil_node *unveil_insert(struct unveil_base *, struct vnode *,
    const char *name, size_t name_len, bool *inserted);
static struct unveil_node *unveil_lookup(struct unveil_base *, struct vnode *,
    const char *name, size_t name_len);

static void
unveil_merge(struct unveil_base *dst, struct unveil_base *src)
{
	struct unveil_node *dst_node, *src_node;
	dst->active = src->active;
	dst->exec_active = src->exec_active;
	/* first pass, copy the nodes without cover links */
	RB_FOREACH(src_node, unveil_node_tree, &src->root) {
		dst_node = unveil_insert(dst, src_node->vp,
		    src_node->name, src_node->name_len, NULL);
		dst_node->fully_covered = src_node->fully_covered;
		for (int i = 0; i < UNVEIL_ROLE_COUNT; i++) {
			dst_node->frozen_perms[i] = src_node->frozen_perms[i];
			for (int j = 0; j < UNVEIL_SLOT_COUNT; j++) {
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

void
unveil_proc_exec_switch(struct thread *td)
{
	struct filedesc *fdp = td->td_proc->p_fd;
	struct unveil_base *base = &fdp->fd_unveil;
	struct unveil_node *node, *node_tmp;
	base->active = base->exec_active;
	RB_FOREACH_SAFE(node, unveil_node_tree, &base->root, node_tmp)
		unveil_node_exec_to_curr(node, false);
}


#define	FOREACH_SLOT_FLAGS(flags, i, j) \
	for (i = 0; i < UNVEIL_ROLE_COUNT; i++) \
		if ((flags) & (1 << (UNVEIL_FLAG_ROLE_SHIFT + i))) \
			for (j = 0; j < UNVEIL_SLOT_COUNT; j++) \
				if ((flags) & (1 << (UNVEIL_FLAG_SLOT_SHIFT + j)))

static int
unveil_remember(struct unveil_base *base,
    struct unveil_node **cover,
    int flags, unveil_perms_t perms,
    struct vnode *dvp, const char *name, size_t name_len, struct vnode *vp)
{
	struct unveil_node *node, *iter;
	bool inserted;
	int i, j;

	if (!name)
		node = unveil_insert(base, dvp, NULL, 0, &inserted);
	else if ((flags & UNVEIL_FLAG_NONDIRBYNAME) && (!vp || vp->v_type != VDIR))
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
	for (iter = *cover; iter; iter = iter->cover)
		if (iter == node)
			break;
	if (!iter) /* prevent loops */
		node->cover = *cover;

	/*
	 * Newly added unveil nodes can inherit frozen permissions from their
	 * most immediate covering node (if any).  Note that this is the
	 * covering node that was discovered while traversing the path, it does
	 * not come from a node's cover link.
	 */
	if (inserted)
		for (int i = 0; i < UNVEIL_ROLE_COUNT; i++)
			node->frozen_perms[i] = node->cover ? node->cover->frozen_perms[i] :
			                       base->active ? UNVEIL_PERM_NONE :
			                                      UNVEIL_PERM_ALL;

	if (flags & UNVEIL_FLAG_INTERMEDIATE)
		node->fully_covered = true; /* cannot be turned off */

	if (name) {
		FOREACH_SLOT_FLAGS(flags, i, j) {
			node->wanted_perms[i][j] = perms;
			node->wanted_final[i][j] = flags & UNVEIL_FLAG_NOINHERIT;
		}
	} else if (flags & UNVEIL_FLAG_INSPECTABLE) {
		FOREACH_SLOT_FLAGS(flags, i, j)
			node->wanted_perms[i][j] |= UNVEIL_PERM_INSPECT;
	}
	*cover = node;
	return (0);
}

static int
unveil_find_cover(struct thread *td, struct vnode *dp, struct unveil_node **cover)
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
			.cn_flags = ISLASTCN | ISDOTDOT | RDONLY,
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
	int error;
	/* TODO: caching */
	trav->cover = NULL;
	trav->descended = false;
	error = unveil_find_cover(td, dvp, &trav->cover);
	if (error)
		return (error);
	trav->descended = trav->cover && trav->cover->vp != dvp;
	return (error);
}

/*
 * dvp is a directory pointer (which may not be NULL).  If name is NULL, it
 * means that dvp is being descended into while looking up a path.  If name is
 * non-NULL, it means that the final path component has been located under dvp
 * with the given name.  vp may point to its vnode if it exists.  It's possible
 * for dvp and vp to be equal (in which case name should be "." or "").
 */

int
unveil_traverse(struct thread *td, struct unveil_traversal *trav,
    struct vnode *dvp, const char *name, size_t name_len, struct vnode *vp)
{
	struct filedesc *fdp = td->td_proc->p_fd;
	struct unveil_base *base = &fdp->fd_unveil;
	int error = 0;

	if (trav->save && (name || (trav->save->flags & UNVEIL_FLAG_INTERMEDIATE))) {
		if (name_len > NAME_MAX)
			return (ENAMETOOLONG);
		if (base->node_count >= unveil_max_nodes_per_process)
			return (E2BIG);

		FILEDESC_XLOCK(fdp);
		error = unveil_remember(base, &trav->cover,
		    trav->save->flags, trav->save->perms,
		    dvp, name, name_len, vp);
		FILEDESC_XUNLOCK(fdp);
		trav->descended = false;

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
			trav->descended = false;
		} else
			trav->descended = true;
	}

	return (error);
}

void
unveil_traverse_dotdot(struct thread *td, struct unveil_traversal *trav,
    struct vnode *dvp)
{
	struct filedesc *fdp = td->td_proc->p_fd;
	if (trav->cover && !trav->descended) {
		FILEDESC_SLOCK(fdp);
		trav->cover = trav->cover->fully_covered ? NULL : trav->cover->cover;
		trav->descended = trav->cover && trav->cover->vp != dvp;
		FILEDESC_SUNLOCK(fdp);
	}
}

unveil_perms_t
unveil_traverse_effective_perms(struct thread *td, struct unveil_traversal *trav)
{
	unveil_perms_t perms;
	if (!trav->cover)
		return (UNVEIL_PERM_NONE);
	perms = unveil_node_soft_perms(trav->cover, UNVEIL_ROLE_CURR);
	if (trav->descended) /* the unveil covered a parent directory */
		perms &= ~UNVEIL_PERM_NONINHERITED_MASK;
	return (perms);
}


static void
do_unveil_limit(struct unveil_base *base, int flags, unveil_perms_t perms)
{
	struct unveil_node *node;
	int i, j;
	RB_FOREACH(node, unveil_node_tree, &base->root)
		FOREACH_SLOT_FLAGS(flags, i, j)
			node->wanted_perms[i][j] &= perms;
}

static void
do_unveil_freeze(struct unveil_base *base, int flags, unveil_perms_t perms)
{
	struct unveil_node *node;
	int i;
	RB_FOREACH(node, unveil_node_tree, &base->root)
		for (i = 0; i < UNVEIL_ROLE_COUNT; i++)
			if (flags & (1 << (UNVEIL_FLAG_ROLE_SHIFT + i)))
				unveil_node_freeze(node, i, perms);
}

static void
do_unveil_sweep(struct unveil_base *base, int flags)
{
	struct unveil_node *node;
	int i, j;
	RB_FOREACH(node, unveil_node_tree, &base->root)
		FOREACH_SLOT_FLAGS(flags, i, j) {
			node->wanted_perms[i][j] = UNVEIL_PERM_NONE;
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
		nd_flags = flags & UNVEIL_FLAG_NOFOLLOW ? 0 : FOLLOW;
		NDINIT_ATRIGHTS(&nd, LOOKUP, nd_flags,
		    UIO_USERSPACE, uap->path, uap->atfd, &cap_no_rights, td);
		/* this will cause namei() to call unveil_traverse_save() */
		nd.ni_unveil.save = &save;
		error = namei(&nd);
		if (error)
			return (error);
		NDFREE(&nd, 0);
	}

	FILEDESC_XLOCK(fdp);

	if (flags & UNVEIL_FLAG_ACTIVATE) {
		if (flags & UNVEIL_FLAG_FOR_CURR)
			base->active = true;
		if (flags & UNVEIL_FLAG_FOR_EXEC)
			base->exec_active = true;
	}
	if (flags & UNVEIL_FLAG_LIMIT)
		do_unveil_limit(base, flags, perms);
	if (flags & UNVEIL_FLAG_FREEZE)
		do_unveil_freeze(base, flags, perms);
	if (flags & UNVEIL_FLAG_SWEEP)
		do_unveil_sweep(base, flags);

	FILEDESC_XUNLOCK(fdp);
	return (0);
#else
	return (ENOSYS);
#endif /* UNVEIL */
}
