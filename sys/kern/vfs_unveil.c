#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_capsicum.h"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/tree.h>
#include <sys/capsicum.h>
#include <sys/counter.h>
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
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/sx.h>
#include <sys/refcount.h>
#include <sys/eventhandler.h>
#include <sys/unveil.h>

#ifdef UNVEIL

MALLOC_DEFINE(M_UNVEIL, "unveil", "unveil");

static bool __read_mostly unveil_enabled = true;
static unsigned int __read_mostly unveil_max_nodes_per_process = 128;

static SYSCTL_NODE(_vfs, OID_AUTO, unveil, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "");

SYSCTL_BOOL(_vfs_unveil, OID_AUTO, enabled, CTLFLAG_RW,
	&unveil_enabled, 0, "Allow unveil usage");

SYSCTL_UINT(_vfs_unveil, OID_AUTO, maxperproc, CTLFLAG_RW,
	&unveil_max_nodes_per_process, 0, "Maximum unveils allowed per process");

static SYSCTL_NODE(_vfs_unveil, OID_AUTO, stats, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "");

#define STATNODE_COUNTER(name, varname, descr)					\
	static COUNTER_U64_DEFINE_EARLY(varname);				\
	SYSCTL_COUNTER_U64(_vfs_unveil_stats, OID_AUTO, name, CTLFLAG_RD, &varname, \
	    descr);

STATNODE_COUNTER(lookups, unveil_stats_lookups, "");
STATNODE_COUNTER(treedups, unveil_stats_treedups, "");
STATNODE_COUNTER(traversals, unveil_stats_traversals, "");
STATNODE_COUNTER(ascents, unveil_stats_ascents, "");
STATNODE_COUNTER(ascent_total_depth, unveil_stats_ascent_total_depth, "");


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
	unveil_perms frozen_uperms[UNVEIL_ON_COUNT];
	unveil_perms wanted_uperms[UNVEIL_ON_COUNT];
	bool inherit[UNVEIL_ON_COUNT];
	unsigned index;
};

struct unveil_tree {
	RB_HEAD(unveil_node_tree, unveil_node) root;
	unsigned refcount;
	unsigned node_count;
};

CTASSERT(NAME_MAX <= UCHAR_MAX);

struct unveil_save {
	int flags;
	/* trail entries */
	bool te_overflow /* array overflowed? */;
	size_t ter; /* remaining array slots */
	unveil_index (*tev)[2] /* array base */, (*tep)[2] /* fill pointer */;
};


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


static struct unveil_tree *
unveil_tree_new(void)
{
	struct unveil_tree *tree;
	tree = malloc(sizeof *tree, M_UNVEIL, M_WAITOK);
	*tree = (struct unveil_tree){
		.root = RB_INITIALIZER(&tree->root),
	};
	refcount_init(&tree->refcount, 1);
	return (tree);
}

static void
unveil_tree_free_1(struct unveil_tree *tree)
{
	struct unveil_node *node, *node_tmp;
	MPASS(tree->refcount == 0);
	RB_FOREACH_SAFE(node, unveil_node_tree, &tree->root, node_tmp) {
		RB_REMOVE(unveil_node_tree, &tree->root, node);
		vrele(node->vp);
		free(node, M_UNVEIL);
	}
	free(tree, M_UNVEIL);
}

static void
unveil_tree_free(struct unveil_tree *tree)
{
	if (refcount_release(&tree->refcount))
		unveil_tree_free_1(tree);
}

static struct unveil_node *
unveil_tree_insert(struct unveil_tree *tree, struct vnode *vp,
    const char *name, size_t name_len, bool *inserted)
{
	struct unveil_node *new, *old;
	KASSERT(tree->refcount == 1, ("modifying CoW unveil tree"));
	new = malloc(sizeof *new + (name ? name_len + 1 : 0), M_UNVEIL, M_WAITOK);
	*new = (struct unveil_node){
		.vp = vp,
		.name = __DECONST(char *, name),
		.name_len = name_len,
	};
	old = RB_INSERT(unveil_node_tree, &tree->root, new);
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
	new->index = tree->node_count++;
	if (inserted)
		*inserted = true;
	return (new);
}

static struct unveil_node *
unveil_tree_lookup(struct unveil_tree *tree, struct vnode *vp,
    const char *name, size_t name_len)
{
	struct unveil_node key;
	key.vp = vp;
	key.name = __DECONST(char *, name);
	key.name_len = name_len;
	counter_u64_add(unveil_stats_lookups, 1);
	return (RB_FIND(unveil_node_tree, &tree->root, &key));
}

static struct unveil_tree *
unveil_tree_dup(struct unveil_tree *old_tree)
{
	struct unveil_tree *new_tree;
	struct unveil_node *new_node, *old_node;
	new_tree = unveil_tree_new();
	/* first pass, copy the nodes without cover links */
	RB_FOREACH(old_node, unveil_node_tree, &old_tree->root) {
		bool inserted;
		new_node = unveil_tree_insert(new_tree, old_node->vp,
		    old_node->name, old_node->name_len, &inserted);
		MPASS(inserted);
		new_node->fully_covered = old_node->fully_covered;
		for (int i = 0; i < UNVEIL_ON_COUNT; i++) {
			new_node->frozen_uperms[i] = old_node->frozen_uperms[i];
			new_node->wanted_uperms[i] = old_node->wanted_uperms[i];
			new_node->inherit[i] = old_node->inherit[i];
		}
		new_node->index = old_node->index;
	}
	/* second pass, fixup the cover links */
	RB_FOREACH(old_node, unveil_node_tree, &old_tree->root) {
		if (!old_node->cover)
			continue;
		new_node = unveil_tree_lookup(new_tree, old_node->vp,
		    old_node->name, old_node->name_len);
		KASSERT(new_node, ("unveil node missing"));
		new_node->cover = unveil_tree_lookup(new_tree, old_node->cover->vp,
		    old_node->cover->name, old_node->cover->name_len);
		KASSERT(new_node->cover, ("cover unveil node missing"));
	}
	counter_u64_add(unveil_stats_treedups, 1);
	return (new_tree);
}



static void
unveil_base_check(struct unveil_base *base)
{
#ifdef INVARIANTS
	for (int i = 0; i < UNVEIL_ON_COUNT; i++)
		KASSERT(base->on[i].active || !base->on[i].frozen,
		    ("unveils frozen but not active"));
	if (base->tree) {
		MPASS(base->tree->refcount != 0);
		MPASS((base->tree->node_count == 0) == RB_EMPTY(&base->tree->root));
	}
#else
	(void)base;
#endif
}

void
unveil_base_init(struct unveil_base *base)
{
	*base = (struct unveil_base){ .tree = NULL };
	sx_init_flags(&base->sx, "unveil base", SX_NEW);
}

static struct unveil_tree *
unveil_base_tree_snap(struct unveil_base *base)
{
	if (base->tree == NULL)
		return (NULL);
	refcount_acquire(&base->tree->refcount);
	return (base->tree);
}

void
unveil_base_copy(struct unveil_base *dst, struct unveil_base *src)
{
	dst->modified = src->modified;
	for (int i = 0; i < UNVEIL_ON_COUNT; i++)
		dst->on[i] = src->on[i];
	if (src->tree) {
		struct unveil_tree *old_tree = dst->tree;
		dst->tree = unveil_base_tree_snap(src);
		if (old_tree)
			unveil_tree_free(old_tree);
	} else
		unveil_base_clear(dst);
}

static void
unveil_base_own(struct unveil_base *base)
{
	struct unveil_tree *tree;
	if ((tree = base->tree)) {
		if (tree->refcount > 1) {
			base->tree = unveil_tree_dup(tree);
			unveil_tree_free(tree);
		}
	} else
		base->tree = unveil_tree_new();
}

void
unveil_base_clear(struct unveil_base *base)
{
	if (base->tree) {
		unveil_tree_free(base->tree);
		base->tree = NULL;
	}
}

void
unveil_base_reset(struct unveil_base *base)
{
	unveil_base_clear(base);
	base->modified = false;
	for (int i = 0; i < UNVEIL_ON_COUNT; i++)
		base->on[i] = (struct unveil_base_flags){ 0 };
}

void
unveil_base_free(struct unveil_base *base)
{
	unveil_base_clear(base);
	sx_destroy(&base->sx);
}


static unveil_perms
unveil_node_wanted_uperms(struct unveil_node *node, enum unveil_on on)
{
	/*
	 * Go up the cover chain until all wanted permissions have been merged
	 * without any more inheritance required.
	 */
	unveil_perms uperms = UPERM_NONE, mask = UPERM_ALL;
	if (node)
		do {
			uperms |= node->wanted_uperms[on] & mask;
			mask = uperms_inheritable;
		} while (node->inherit[on] && (node = node->cover));
	return (uperms);
}


#define UNVEIL_WRITE_BEGIN(base) \
    do { sx_xlock(&(base)->sx); unveil_base_own(base); } while (0)
#define	UNVEIL_WRITE_ASSERT(base)	sx_assert(&(base)->sx, SA_XLOCKED)
#define UNVEIL_WRITE_END(base)	sx_xunlock(&(base)->sx)
#define UNVEIL_READ_BEGIN(base)	sx_slock(&(base)->sx)
#define UNVEIL_READ_END(base)	sx_sunlock(&(base)->sx)

#define	UNVEIL_FOREACH(node, base) \
	if ((base)->tree) \
		RB_FOREACH(node, unveil_node_tree, &(base)->tree->root)

void
unveil_proc_exec_switch(struct thread *td)
{
	const int s = UNVEIL_ON_EXEC, d = UNVEIL_ON_SELF;
	struct unveil_base *base = &td->td_proc->p_unveils;
	struct unveil_node *node;
	if (!base->on[s].active) {
		/*
		 * This is very important for SUID/SGID execution checks.  When
		 * unveil_exec_is_active() is false, unveil_proc_exec_switch()
		 * must provide a clean execution environment for programs with
		 * elevated privileges.
		 */
		unveil_base_reset(base);
		return;
	}
	if (!base->modified)
		return;

	unveil_base_own(base);
	if (base->on[s].wanted) {
		UNVEIL_FOREACH(node, base)
			node->frozen_uperms[s] &=
			    uperms_expand(unveil_node_wanted_uperms(node, s));
	}
	base->on[s].frozen = true;
	base->on[s].wanted = false;

	base->on[d] = base->on[s];
	UNVEIL_FOREACH(node, base) {
		node->frozen_uperms[d] = node->frozen_uperms[s];
		for (int i = 0; i < UNVEIL_ON_COUNT; i++) {
			node->wanted_uperms[i] = UPERM_NONE;
			node->inherit[i] = true;
		}
	}
	base->modified = false;
	unveil_base_check(base);
}

static struct unveil_node *
unveil_remember(struct unveil_base *base, struct unveil_traversal *trav,
    struct vnode *dvp, const char *name, size_t name_len, struct vnode *vp, bool final)
{
	struct unveil_node *node, *iter;
	bool inserted;

	if (trav->tree->node_count >= unveil_max_nodes_per_process)
		return (NULL);

	if (!name)
		node = unveil_tree_insert(trav->tree, dvp, NULL, 0, &inserted);
	else if ((trav->save->flags & UNVEILREG_NONDIRBYNAME) && (!vp || vp->v_type != VDIR))
		node = unveil_tree_insert(trav->tree, dvp, name, name_len, &inserted);
	else if (vp)
		node = unveil_tree_insert(trav->tree, vp, NULL, 0, &inserted);
	else
		return (NULL);

	/*
	 * Update the cover link of the node.  If directories move around, the
	 * cover hierarchy might become out of date.  This is only updated when
	 * adding unveils for now.
	 *
	 * Note how allowing each process to potentially have its own "view" of
	 * the covering hierarchy has security implications on how the cover
	 * links are to be trusted.
	 */
	if (trav->cover) {
		for (iter = trav->cover; iter; iter = iter->cover)
			if (iter == node)
				break;
		if (!iter) /* prevent loops */
			node->cover = trav->cover;
	}

	/*
	 * Newly added unveil nodes can inherit frozen permissions from their
	 * most immediate covering node (if any).  Note that this is the
	 * covering node that was discovered while traversing the path, it does
	 * not come from a node's cover link.
	 */
	if (inserted)
		for (int i = 0; i < UNVEIL_ON_COUNT; i++) {
			node->wanted_uperms[i] = UPERM_NONE;
			node->frozen_uperms[i] =
			    trav->cover ? uperms_inherit(trav->cover->frozen_uperms[i]) :
			    base->on[i].frozen ? UPERM_NONE : UPERM_ALL;
			node->inherit[i] = true;
		}

	if (trav->save->ter) {
		(*trav->save->tep)[0] = node->cover ? node->cover->index : node->index;
		(*trav->save->tep)[1] = node->index;
		trav->save->tep++, trav->save->ter--;
	} else
		trav->save->te_overflow = true;

	if (trav->save->flags & UNVEILREG_INTERMEDIATE)
		node->fully_covered = true; /* cannot be turned off */

	base->modified = true;
	return (node);
}

static int
unveil_find_cover(struct thread *td, struct unveil_tree *tree,
    struct vnode *dp, struct unveil_node **cover, uint8_t *depth)
{
	int error = 0;
	struct vnode *vp;
	struct componentname cn;

	error = vget(dp, LK_RETRY | LK_SHARED);
	if (error)
		return (error);

	while (true) {
		/* At the start of the loop, dp is locked (and referenced). */

		*cover = unveil_tree_lookup(tree, dp, NULL, 0);
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

int
unveil_traverse_begin(struct thread *td, struct unveil_traversal *trav,
    struct vnode *dvp)
{
	struct unveil_base *base = &td->td_proc->p_unveils;
	int error;
	counter_u64_add(unveil_stats_traversals, 1);
	if (trav->save) {
		UNVEIL_WRITE_ASSERT(base);
		trav->tree = base->tree;
	} else {
		UNVEIL_READ_BEGIN(base);
		trav->tree = unveil_base_tree_snap(base);
		UNVEIL_READ_END(base);
	}
	/* TODO: caching */
	trav->cover = NULL;
	trav->type = VDIR;
	trav->depth = 0;
	error = unveil_find_cover(td, trav->tree, dvp, &trav->cover, &trav->depth);
	if (error)
		return (error);
	if (trav->depth > 0) {
		counter_u64_add(unveil_stats_ascents, 1);
		counter_u64_add(unveil_stats_ascent_total_depth, trav->depth);
	}
	if (trav->save && trav->first) {
		struct unveil_save *save = trav->save;
		size_t cnt;
		struct unveil_node *node;
		unveil_index (*tep)[2];
		for (cnt = 0, node = trav->cover; node; node = node->cover, cnt++);
		if (save->ter < cnt) {
			tep = save->tep += save->ter;
			save->ter = 0;
			save->te_overflow = true;
		} else {
			tep = save->tep += cnt;
			save->ter -= cnt;
		}
		for (node = trav->cover; node && tep != save->tev; node = node->cover) {
			tep--;
			(*tep)[0] = (node->cover && tep != save->tev
			    ? node->cover : node)->index;
			(*tep)[1] = node->index;
		}
	}
	trav->first = false;
	return (0);
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
	struct unveil_base *base = &td->td_proc->p_unveils;
	struct unveil_node *node;

	if (trav->save && (final || (trav->save->flags & UNVEILREG_INTERMEDIATE))) {
		if (name_len > NAME_MAX)
			return (ENAMETOOLONG);
		UNVEIL_WRITE_ASSERT(base);
		MPASS(base->tree == trav->tree);
		node = unveil_remember(base, trav, dvp, name, name_len, vp, final);
		if (!node)
			return (E2BIG);

	} else {
		if (trav->tree) {
			if (vp)
				node = unveil_tree_lookup(trav->tree, vp, NULL, 0);
			else
				node = NULL;
			if (!node)
				node = unveil_tree_lookup(trav->tree, dvp, name, name_len);
		} else
			node = NULL;
	}

	trav->type = vp ? vp->v_type : VNON;
	if (node) {
		trav->cover = node;
		trav->depth = 0;
	} else if (dvp != vp) {
		if (!++trav->depth)
			trav->depth = -1;
	}
	return (0);
}

void
unveil_traverse_dotdot(struct thread *td, struct unveil_traversal *trav,
    struct vnode *dvp)
{
	if (trav->cover && trav->depth == 0)
		trav->cover = trav->cover->fully_covered ? NULL : trav->cover->cover;
	trav->depth = -1;
	trav->type = VDIR;
}

unveil_perms
unveil_traverse_effective_uperms(struct thread *td, struct unveil_traversal *trav)
{
	struct unveil_base *base = &td->td_proc->p_unveils;
	unveil_perms uperms;
	if (trav->cover) {
		uperms = trav->cover->frozen_uperms[UNVEIL_ON_SELF];
		if (!trav->save && base->on[UNVEIL_ON_SELF].wanted)
			uperms &= uperms_expand(unveil_node_wanted_uperms(
			    trav->cover, UNVEIL_ON_SELF));
	} else {
		if (!trav->save)
			uperms = base->on[UNVEIL_ON_SELF].active ? UPERM_NONE : UPERM_ALL;
		else
			uperms = base->on[UNVEIL_ON_SELF].frozen ? UPERM_NONE : UPERM_ALL;
	}
	/* NOTE: This function does not take the depth into consideration. */
	return (uperms);
}

static void unveil_uperms_rights_1(unveil_perms, enum vtype type, uint8_t depth,
    cap_rights_t *);

void
unveil_traverse_effective_rights(struct thread *td, struct unveil_traversal *trav,
    cap_rights_t *rights, int *suggested_error)
{
	unveil_perms uperms;
	uperms = unveil_traverse_effective_uperms(td, trav);
	unveil_uperms_rights_1(uperms, trav->type, trav->depth, rights);

	/* Kludge for directory O_EXEC/O_SEARCH opens. */
	if (trav->type == VDIR && (uperms & UPERM_RPATH))
		cap_rights_set(rights, CAP_FEXECVE, CAP_EXECAT);
	/* Kludge for O_CREAT opens. */
	if (trav->type != VNON && (uperms & UPERM_WPATH))
		cap_rights_set(rights, CAP_CREATE);

	trav->nosetattr = !(uperms & UPERM_APATH); /* TODO: clean up interface */

	if (suggested_error)
		*suggested_error = uperms & ~UPERM_INSPECT ? EACCES : ENOENT;
}

void
unveil_traverse_end(struct thread *td, struct unveil_traversal *trav)
{
	struct unveil_base *base = &td->td_proc->p_unveils;
	if (trav->save) {
		MPASS(base->tree == trav->tree);
		UNVEIL_WRITE_ASSERT(base);
	} else if (trav->tree)
		unveil_tree_free(trav->tree);
}


void
unveil_base_write_begin(struct unveil_base *base)
{
	UNVEIL_WRITE_BEGIN(base);
}

void
unveil_base_write_end(struct unveil_base *base)
{
	UNVEIL_WRITE_END(base);
}

void
unveil_base_activate(struct unveil_base *base, enum unveil_on on)
{
	base->modified = true;
	base->on[on].active = base->on[on].wanted = true;
}

void
unveil_base_enforce(struct unveil_base *base, enum unveil_on on)
{
	struct unveil_node *node;
	base->modified = true;
	base->on[on].frozen = base->on[on].active = base->on[on].wanted = true;
	UNVEIL_FOREACH(node, base)
		node->frozen_uperms[on] &= uperms_expand(
		    unveil_node_wanted_uperms(node, on));
}


int
unveil_index_check(struct unveil_base *base, unsigned index)
{
	struct unveil_node *node;
	UNVEIL_FOREACH(node, base)
		if (node->index == index) /* XXX */
			return (0);
	return (EINVAL);
}

int
unveil_index_set(struct unveil_base *base,
    unsigned index, enum unveil_on on, unveil_perms uperms)
{
	struct unveil_node *node;
	UNVEIL_WRITE_ASSERT(base);
	UNVEIL_FOREACH(node, base) {
		if (node->index == index) /* XXX */ {
			base->modified = true;
			node->wanted_uperms[on] = uperms_expand(uperms);
			node->inherit[on] = false;
			return (0);
		}
	}
	return (EINVAL);
}


static int
do_unveil_add(struct thread *td, struct unveil_base *base, int flags, struct unveilreg reg)
{
	struct nameidata nd;
	struct unveil_traversal *trav;
	struct unveil_save save;
	uint64_t ndflags;
	int error;
	if ((reg.atflags & ~(AT_SYMLINK_NOFOLLOW | AT_RESOLVE_BENEATH)) != 0)
		return (EINVAL);
	ndflags = (reg.atflags & AT_SYMLINK_NOFOLLOW ? NOFOLLOW : FOLLOW) |
	    (reg.atflags & AT_RESOLVE_BENEATH ? RBENEATH : 0);
	NDINIT_ATRIGHTS(&nd, LOOKUP, ndflags,
	    UIO_USERSPACE, reg.path, reg.atfd, &cap_fstat_rights, td);
	trav = &nd.ni_unveil;
	trav->first = true;
	trav->save = &save;
	save = (struct unveil_save){ .flags = flags };
	if (reg.tev) {
		if ((save.ter = reg.tec) > UNVEILREG_MAX_TE)
			save.ter = UNVEILREG_MAX_TE;
		save.tev = save.tep = mallocarray(save.ter,
		    sizeof *save.tev, M_TEMP, M_WAITOK);
		if (!save.tev)
			return (EINVAL);
	}
	error = namei(&nd);
	if (error)
		goto out;
	NDFREE(&nd, 0);
	if (reg.tev) {
		if (save.te_overflow) {
			error = ENAMETOOLONG;
			goto out;
		}
		error = copyout(save.tev, reg.tev,
		    (char *)save.tep - (char *)save.tev);
		if (error)
			goto out;
		td->td_retval[0] = save.tep - save.tev;
	} else
		td->td_retval[0] = trav->cover ? trav->cover->index : -1;
out:	if (reg.tev)
		free(save.tev, M_TEMP);
	return (error);
}

#endif /* UNVEIL */

int
sys_unveilreg(struct thread *td, struct unveilreg_args *uap)
{
#ifdef UNVEIL
	struct unveil_base *base = &td->td_proc->p_unveils;
	int flags, error;
	struct unveilreg reg;
	if (!unveil_enabled)
		return (ENOSYS);
	flags = uap->flags;
	if ((flags & UNVEILREG_VERSION_MASK) != UNVEILREG_VERSION)
		return (EINVAL);
	flags &= ~UNVEILREG_VERSION_MASK;
	error = copyin(uap->reg, &reg, sizeof reg);
	if (error)
		return (error);
	UNVEIL_WRITE_BEGIN(base);
	if (flags & UNVEILREG_REGISTER) {
		error = do_unveil_add(td, base, flags, reg);
		if (error)
			goto out;
	}
out:	unveil_base_check(base);
	UNVEIL_WRITE_END(base);
	return (error);
#else
	return (ENOSYS);
#endif /* UNVEIL */
}

#if defined(UNVEIL)

static void
unveil_proc_init(void *arg __unused, struct proc *p)
{
	unveil_base_init(&p->p_unveils);
	unveil_base_check(&p->p_unveils);
}

static void
unveil_proc_ctor(void *arg __unused, struct proc *p)
{
	unveil_base_check(&p->p_unveils);
}

static void
unveil_proc_dtor(void *arg __unused, struct proc *p)
{
	unveil_base_reset(&p->p_unveils);
	unveil_base_check(&p->p_unveils);
}

static void
unveil_proc_fini(void *arg __unused, struct proc *p)
{
	unveil_base_free(&p->p_unveils);
}

static void
unveil_proc_fork(void *arg __unused, struct proc *parent, struct proc *child, int flags)
{
	struct unveil_base *src, *dst;
	src = &parent->p_unveils;
	dst = &child->p_unveils;
	UNVEIL_READ_BEGIN(src);
	unveil_base_check(src);
	unveil_base_check(dst);
	unveil_base_copy(dst, src);
	unveil_base_check(dst);
	MPASS((src->tree ? src->tree->node_count : 0) ==
	      (dst->tree ? dst->tree->node_count : 0));
	UNVEIL_READ_END(src);
}


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
unveil_uperms_rights_1(unveil_perms uperms, enum vtype type, uint8_t depth,
    cap_rights_t *rights)
{
	CAP_NONE(rights);
	if (uperms & UPERM_INSPECT && depth == 0)
		cap_rights_merge(rights, &inspect_rights);
	if (uperms & UPERM_RPATH)
		cap_rights_merge(rights, &rpath_rights);
	if (uperms & UPERM_WPATH)
		cap_rights_merge(rights, &wpath_rights);
	if (uperms & UPERM_CPATH) {
		cap_rights_merge(rights, &cpath_rights);
		if (uperms & UPERM_RPATH)
			cap_rights_merge(rights, &rcpath_rights);
	}
	if (uperms & UPERM_XPATH)
		cap_rights_merge(rights, &xpath_rights);
	if (uperms & UPERM_APATH) {
		cap_rights_merge(rights, &apath_rights);
		if (uperms & UPERM_CPATH && uperms & UPERM_WPATH && uperms & UPERM_RPATH)
			cap_rights_merge(rights, &rwcapath_rights);
	}
	if (uperms & UPERM_TMPPATH) {
		if (depth == 0)
			cap_rights_merge(rights, &inspect_rights);
		else if (depth == 1 && (type == VNON || type == VREG))
			cap_rights_merge(rights, &tmppath_rights);
	}
}

void
unveil_uperms_rights(unveil_perms uperms, cap_rights_t *rights)
{
	return (unveil_uperms_rights_1(uperms, VBAD, 0, rights));
}

static void
unveil_sysinit(void *arg __unused)
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
	    CAP_FTRUNCATE,
	    CAP_CONNECTAT);
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

	EVENTHANDLER_REGISTER(process_init, unveil_proc_init, NULL, EVENTHANDLER_PRI_ANY);
	EVENTHANDLER_REGISTER(process_ctor, unveil_proc_ctor, NULL, EVENTHANDLER_PRI_ANY);
	EVENTHANDLER_REGISTER(process_dtor, unveil_proc_dtor, NULL, EVENTHANDLER_PRI_ANY);
	EVENTHANDLER_REGISTER(process_fini, unveil_proc_fini, NULL, EVENTHANDLER_PRI_ANY);
	EVENTHANDLER_REGISTER(process_fork, unveil_proc_fork, NULL, EVENTHANDLER_PRI_ANY);
}

SYSINIT(unveil_sysinit, SI_SUB_KLD, SI_ORDER_ANY, unveil_sysinit, NULL);

#endif /* UNVEIL */
