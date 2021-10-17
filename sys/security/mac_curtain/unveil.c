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
#include <sys/filedesc.h>
#include <sys/conf.h>
#include <sys/sysent.h>
#include <sys/syscall.h>
#include <sys/unveil.h>
#include <sys/curtain.h>

#ifdef UNVEIL_SUPPORT

static MALLOC_DEFINE(M_UNVEIL, "unveil", "vnode unveils");

static bool __read_mostly unveil_enabled = true;
static bool __read_mostly unveil_cover_cache_enabled = true;
static unsigned int __read_mostly unveil_max_nodes_per_process = 128;

static SYSCTL_NODE(_vfs, OID_AUTO, unveil, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "Unveil");

SYSCTL_BOOL(_vfs_unveil, OID_AUTO, enabled, CTLFLAG_RW,
    &unveil_enabled, 0, "Allow unveilreg(2) usage");

SYSCTL_BOOL(_vfs_unveil, OID_AUTO, cover_cache, CTLFLAG_RW,
    &unveil_cover_cache_enabled, 0, "");

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
STATNODE_COUNTER(ascents_cached, unveil_stats_ascents_cached, "");
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
	unveil_perms actual_uperms[UNVEIL_ON_COUNT];
	unveil_perms frozen_uperms[UNVEIL_ON_COUNT];
	unveil_perms wanted_uperms[UNVEIL_ON_COUNT];
	bool wanted[UNVEIL_ON_COUNT];
	unveil_index index;
};

CTASSERT(NAME_MAX <= UCHAR_MAX);

struct unveil_tree {
	RB_HEAD(unveil_node_tree, unveil_node) root;
	int refcount;
	unsigned node_count;
};

struct unveil_save {
	int flags;
	int error;
	bool first;
	/* trail entries */
	bool te_overflow /* array overflowed? */;
	size_t ter; /* remaining array slots */
	unveil_index (*tev)[2] /* array base */, (*tep)[2] /* fill pointer */;
};

struct unveil_tracker {
#define	UNVEIL_TRACKER_ENTRIES_COUNT 2
	uint64_t serial;
	struct unveil_tracker_entry {
		struct vnode *vp;
		struct mount *mp;
		unsigned vp_nchash, vp_hash;
		int mp_gen;
		unveil_perms uperms;
	} entries[UNVEIL_TRACKER_ENTRIES_COUNT];
	unsigned fill;
};

struct unveil_cache {
	uint64_t serial;
#define UNVEIL_CACHE_ENTRIES_COUNT 4
	struct unveil_cache_entry {
		struct vnode *vp;
		unsigned vp_nchash, vp_hash;
		struct unveil_node *cover;
	} entries[UNVEIL_CACHE_ENTRIES_COUNT];
};

struct unveil_base {
	struct sx sx;
	struct unveil_tree *tree;
	struct unveil_base_flags flags;
	struct unveil_cache cover_cache;
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

static struct unveil_tree *
unveil_tree_hold(struct unveil_tree *tree)
{
	refcount_acquire(&tree->refcount);
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
		for (int i = 0; i < UNVEIL_ON_COUNT; i++) {
			new_node->actual_uperms[i] = old_node->actual_uperms[i];
			new_node->frozen_uperms[i] = old_node->frozen_uperms[i];
			new_node->wanted_uperms[i] = old_node->wanted_uperms[i];
			new_node->wanted[i] = old_node->wanted[i];
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
	return (base->tree ? unveil_tree_hold(base->tree) : NULL);
}

void
unveil_base_copy(struct unveil_base *dst, struct unveil_base *src)
{
	dst->flags = src->flags;
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
	base->flags = (struct unveil_base_flags){ 0 };
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
	if (node->wanted[on])
		return (node->wanted_uperms[on]);
	while ((node = node->cover))
		if (node->wanted[on])
			return (uperms_inherit(node->wanted_uperms[on]));
	return (UPERM_NONE);
}

#define	UNVEIL_FOREACH(node, base) \
	if ((base)->tree) \
		RB_FOREACH(node, unveil_node_tree, &(base)->tree->root)


void
unveil_stash_init(struct unveil_stash *stash)
{
	*stash = (struct unveil_stash){ 0 };
}

void
unveil_stash_copy(struct unveil_stash *dst, const struct unveil_stash *src)
{
	dst->tree = src->tree ? unveil_tree_hold(src->tree) : NULL;
	dst->flags = src->flags;
}

void
unveil_stash_free(struct unveil_stash *stash)
{
	if (stash->tree)
		unveil_tree_free(stash->tree);
}

static void
unveil_stash_check(struct unveil_stash *stash)
{
	if (stash->tree) {
		MPASS(stash->tree->refcount != 0);
		MPASS((stash->tree->node_count == 0) == RB_EMPTY(&stash->tree->root));
	}
}


unveil_perms
unveil_stash_mount_lookup(struct unveil_stash *stash, struct mount *mp)
{
	const enum unveil_on on = UNVEIL_ON_SELF;
	struct unveil_node *node;
	unveil_perms uperms;
	uperms = UPERM_NONE;
	UNVEIL_FOREACH(node, stash)
		if (node->vp->v_mount == mp) /* XXX linear search */
			uperms |= node->actual_uperms[on];
	return (uperms_expand(uperms));
}

void
unveil_stash_sweep(struct unveil_stash *stash, enum unveil_on on)
{
	struct unveil_node *node;
	UNVEIL_FOREACH(node, stash) {
		node->wanted[on] = false;
		node->wanted_uperms[on] = UPERM_NONE;
	}
	unveil_stash_check(stash);
}

void
unveil_stash_unrestrict(struct unveil_stash *stash, enum unveil_on on)
{
	struct unveil_node *node;
	UNVEIL_FOREACH(node, stash)
		node->actual_uperms[on] = node->frozen_uperms[on];
}

void
unveil_stash_inherit(struct unveil_stash *stash, enum unveil_on on)
{
	struct unveil_node *node;
	UNVEIL_FOREACH(node, stash)
		node->actual_uperms[on] = node->frozen_uperms[on] &
		    unveil_node_wanted_uperms(node, on);
	unveil_stash_check(stash);
}

void
unveil_stash_freeze(struct unveil_stash *stash, enum unveil_on on)
{
	struct unveil_node *node;
	stash->flags.on[on].frozen = true;
	UNVEIL_FOREACH(node, stash)
		node->frozen_uperms[on] &= node->actual_uperms[on];
	unveil_stash_check(stash);
}

bool
unveil_stash_need_exec_switch(const struct unveil_stash *stash)
{
	const int s = UNVEIL_ON_EXEC, d = UNVEIL_ON_SELF;
	struct unveil_node *node;
	UNVEIL_FOREACH(node, stash)
		if (node->actual_uperms[d] != node->actual_uperms[s] ||
		    node->frozen_uperms[d] != node->frozen_uperms[s] ||
		    node->wanted_uperms[d] != node->wanted_uperms[s] ||
		    node->wanted[d] != node->wanted[s])
			return (true);
	return (false);
}

void
unveil_stash_exec_switch(struct unveil_stash *stash)
{
	const int s = UNVEIL_ON_EXEC, d = UNVEIL_ON_SELF;
	struct unveil_node *node;

	UNVEIL_FOREACH(node, stash) {
		node->actual_uperms[d] = node->actual_uperms[s];
		node->frozen_uperms[d] = node->frozen_uperms[s];
		node->wanted_uperms[d] = node->wanted_uperms[s];
		node->wanted[d] = node->wanted[s];
	}
	stash->flags.on[d] = stash->flags.on[s];
	unveil_stash_check(stash);
}

int
unveil_stash_update(struct unveil_stash *stash,
    unsigned index, enum unveil_on on, unveil_perms uperms)
{
	struct unveil_node *node;
	UNVEIL_FOREACH(node, stash) {
		if (node->index == index) /* XXX linear search */ {
			node->wanted[on] = true;
			node->wanted_uperms[on] = uperms_expand(uperms);
			return (0);
		}
	}
	return (ENOENT);
}

void
unveil_stash_begin(struct unveil_stash *stash, struct unveil_base *base)
{
	MPASS(!stash->tree);
	stash->tree = unveil_tree_dup(base->tree);
	stash->flags = base->flags;
	for (int i = 0; i < UNVEIL_ON_COUNT; i++)
		unveil_stash_sweep(stash, i);
}

void
unveil_stash_commit(struct unveil_stash *stash, struct unveil_base *base)
{
	if (base->tree)
		unveil_tree_free(base->tree);
	base->tree = unveil_tree_hold(stash->tree);
	base->flags = stash->flags;
}


static inline uint64_t
unveil_stash_get(struct thread *td, struct unveil_stash **p)
{
	struct curtain *ct;
	if ((ct = curtain_from_cred(td->td_ucred))) {
		if (p)
			*p = &ct->ct_ustash;
		return (curtain_serial(ct));
	}
	if (p)
		*p = NULL;
	return (0);
}


static unveil_perms
unveil_fflags_uperms(enum vtype type, int fflags)
{
	unveil_perms uperms = UPERM_NONE;
	if (fflags & FREAD)
		uperms |= UPERM_READ;
	if (fflags & FWRITE)
		uperms |= UPERM_WRITE | UPERM_SETATTR;
	if (type == VDIR) {
		if (fflags & FSEARCH)
			uperms |= UPERM_SEARCH;
	} else {
		if (fflags & FEXEC)
			uperms |= UPERM_EXECUTE;
	}
	return (uperms_expand(uperms));
}

static struct unveil_tracker *
unveil_tracker_prep(struct thread *td)
{
	struct unveil_tracker *track;
	if ((track = td->td_unveil_tracker)) {
		uint64_t serial;
		serial = unveil_stash_get(td, NULL);
		if (__predict_false(track->serial != serial))
			*track = (struct unveil_tracker){
				.serial = serial,
			};
		return (track);
	}
	return (NULL);
}

static unveil_perms
unveil_tracker_find(struct thread *td, struct vnode *vp)
{
	struct unveil_tracker *track;
	MPASS(vp);
	if ((track = unveil_tracker_prep(td))) {
		unsigned j = UNVEIL_TRACKER_ENTRIES_COUNT - 1;
		do {
			unsigned i = (track->fill + j) % UNVEIL_TRACKER_ENTRIES_COUNT;
			if (track->entries[i].vp == vp &&
			    track->entries[i].vp_nchash == vp->v_nchash &&
			    track->entries[i].vp_hash == vp->v_hash &&
			    track->entries[i].mp == vp->v_mount &&
			    track->entries[i].mp_gen == (vp->v_mount ? vp->v_mount->mnt_gen : 0))
				return (track->entries[i].uperms);
		} while (j--);
	}
	return (UPERM_NONE);
}

static unveil_perms
unveil_tracker_find_mount(struct thread *td, struct mount *mp)
{
	struct unveil_tracker *track;
	MPASS(mp);
	if ((track = unveil_tracker_prep(td))) {
		unsigned j = UNVEIL_TRACKER_ENTRIES_COUNT - 1;
		do {
			unsigned i = (track->fill + j) % UNVEIL_TRACKER_ENTRIES_COUNT;
			if (track->entries[i].mp == mp &&
			    track->entries[i].mp_gen == mp->mnt_gen)
				return (track->entries[i].uperms);
		} while (j--);
	}
	return (UPERM_NONE);
}

static size_t
unveil_tracker_last(struct thread *td)
{
	struct unveil_tracker *track;
	track = td->td_unveil_tracker;
	return ((track->fill != 0 ? track->fill : UNVEIL_TRACKER_ENTRIES_COUNT) - 1);
}

static unveil_perms
unveil_tracker_get(struct thread *td, size_t i)
{
	struct unveil_tracker *track;
	track = td->td_unveil_tracker;
	return (track->entries[i].uperms);
}

static void
unveil_tracker_set(struct thread *td, size_t i, struct vnode *vp, unveil_perms uperms)
{
	struct unveil_tracker *track;
	track = td->td_unveil_tracker;
	track->entries[i] = (struct unveil_tracker_entry){
		.vp = vp,
		.vp_nchash = vp ? vp->v_nchash : 0,
		.vp_hash = vp ? vp->v_hash : 0,
		.mp = vp ? vp->v_mount : NULL,
		.mp_gen = vp && vp->v_mount ? vp->v_mount->mnt_gen : 0,
		.uperms = uperms,
	};
}

static void
unveil_tracker_replace(struct thread *td, size_t i, struct vnode *vp)
{
	struct unveil_tracker *track;
	MPASS(vp);
	track = td->td_unveil_tracker;
	track->entries[i] = (struct unveil_tracker_entry){
		.vp = vp,
		.vp_nchash = vp->v_nchash,
		.vp_hash = vp->v_hash,
		.mp = vp->v_mount,
		.mp_gen = vp->v_mount ? vp->v_mount->mnt_gen : 0,
		.uperms = track->entries[i].uperms,
	};
}

static void
unveil_tracker_substitute(struct thread *td,
    struct vnode *old_vp, struct vnode *new_vp, unveil_perms uperms)
{
	struct unveil_tracker *track;
	if ((track = unveil_tracker_prep(td))) {
		unsigned j = UNVEIL_TRACKER_ENTRIES_COUNT - 1;
		do {
			unsigned i = (track->fill + j) % UNVEIL_TRACKER_ENTRIES_COUNT;
			if (track->entries[i].vp == old_vp) {
				unveil_tracker_replace(td, i, new_vp);
				track->entries[i].uperms = uperms;
				break;
			}
		} while (j--);
	}
}

static size_t
unveil_tracker_push(struct thread *td, struct vnode *vp, unveil_perms uperms)
{
	struct unveil_tracker *track;
	size_t i;
	if (__predict_false(!td->td_unveil_tracker)) {
		uint64_t serial;
		serial = unveil_stash_get(td, NULL);
		track = malloc(sizeof *track, M_UNVEIL, M_WAITOK);
		*track = (struct unveil_tracker){
			.serial = serial,
		};
		td->td_unveil_tracker = track;
	} else
		track = unveil_tracker_prep(td);
	i = track->fill++;
	track->fill %= UNVEIL_TRACKER_ENTRIES_COUNT;
	unveil_tracker_set(td, i, vp, uperms);
	return (i);
}

static void
unveil_tracker_push_file(struct thread *td, struct file *fp)
{
	unveil_perms uperms;
	if (!fp->f_vnode)
		return;
	uperms = fp->f_uperms;
	if ((fp->f_uldgen != unveil_stash_get(td, NULL)))
		uperms &= unveil_fflags_uperms(fp->f_vnode->v_type, fp->f_flag);
	unveil_tracker_push(td, fp->f_vnode, uperms);
}

static void
unveil_tracker_save_file(struct thread *td, struct file *fp, struct vnode *vp)
{
	fp->f_uldgen = unveil_stash_get(td, NULL);
	fp->f_uperms = unveil_active(td) ? unveil_tracker_find(td, vp) : UPERM_ALL;
}


static void
unveil_save_prefix(struct unveil_save *save, struct unveil_node *cover)
{
	size_t cnt;
	struct unveil_node *node;
	unveil_index (*tep)[2];
	if (!save->first)
		return;
	for (cnt = 0, node = cover; node; node = node->cover, cnt++);
	if (save->ter < cnt) {
		tep = save->tep += save->ter;
		save->ter = 0;
		save->te_overflow = true;
	} else {
		tep = save->tep += cnt;
		save->ter -= cnt;
	}
	for (node = cover; node && tep != save->tev; node = node->cover) {
		tep--;
		(*tep)[0] = (node->cover && tep != save->tev ? node->cover : node)->index;
		(*tep)[1] = node->index;
	}
	save->first = false;
}

static struct unveil_node *
unveil_save(struct unveil_base *base, struct unveil_traversal *trav,
    struct vnode *dvp, const char *name, size_t name_len, struct vnode *vp)
{
	struct unveil_node *node, *iter;
	bool inserted;
	MPASS(!(name && !dvp));
	sx_assert(&base->sx, SA_XLOCKED);
	MPASS(trav->tree && base->tree == trav->tree);

	if (name && name_len > NAME_MAX) {
		trav->save->error = ENAMETOOLONG;
		return (NULL);
	}
	if (trav->tree->node_count >= unveil_max_nodes_per_process) {
		trav->save->error = E2BIG;
		return (NULL);
	}

	if (name && (!vp || vp->v_type != VDIR) &&
	    (trav->save->flags & UNVEILREG_NONDIRBYNAME))
		node = unveil_tree_insert(trav->tree, dvp, name, name_len, &inserted);
	else if (vp)
		node = unveil_tree_insert(trav->tree, vp, NULL, 0, &inserted);
	else
		return (NULL);

	/*
	 * Update the cover link of the node.  If directories move around, the
	 * cover hierarchy might become out of date.
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
			node->wanted[i] = false;
			node->wanted_uperms[i] = UPERM_NONE;
			node->frozen_uperms[i] =
			    trav->cover ? uperms_inherit(trav->cover->frozen_uperms[i]) :
			    trav->flags.on[i].frozen ? UPERM_NONE : UPERM_ALL;
			node->actual_uperms[i] =
			    (trav->cover ? uperms_inherit(trav->cover->actual_uperms[i]) :
			     unveil_active(curthread) ? UPERM_NONE : UPERM_ALL) &
			    node->frozen_uperms[i];
		}

	if (trav->save->ter) {
		(*trav->save->tep)[0] = node->cover ? node->cover->index : node->index;
		(*trav->save->tep)[1] = node->index;
		trav->save->tep++, trav->save->ter--;
	} else
		trav->save->te_overflow = true;

	return (node);
}

static int
unveil_find_cover(struct thread *td, struct unveil_tree *tree,
    struct vnode *dp, struct unveil_node **cover, unsigned *depth)
{
	int error, lkflags;
	struct mount *mp;
	struct vnode *vp;
	struct componentname cn;

	if ((mp = dp->v_mount) && (mp->mnt_kern_flag & MNTK_LOOKUP_SHARED) &&
	    !(mp->mnt_kern_flag & MNTK_LOOKUP_EXCL_DOTDOT))
		lkflags = LK_SHARED;
	else
		lkflags = LK_EXCLUSIVE;

	error = vget(dp, LK_RETRY | lkflags);
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
			if (!(mp = dp->v_mount) || !(vp = mp->mnt_vnodecovered))
				break;
			/* Must not lock parent while child lock is held. */
			vref(vp);
			vput(dp);
			error = vn_lock(vp, LK_RETRY | lkflags);
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
			.cn_lkflags = lkflags,
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


static bool
curtain_device_unveil_bypass(struct thread *td, struct cdev *dev)
{
	struct ucred *cr1 = td->td_ucred, *cr2 = dev->si_cred;
	return (cr2 && curtain_cred_visible(cr1, cr2, BARRIER_DEVICE));
}

static unveil_perms
unveil_special_exemptions(struct thread *td, struct vnode *vp, unveil_perms uperms)
{
	unveil_perms add_uperms = UPERM_NONE;
	if (uperms & UPERM_DEVFS) {
		if (vp && vp->v_type == VCHR && vp->v_rdev &&
		    curtain_device_unveil_bypass(td, vp->v_rdev))
			add_uperms |= UPERM_READ | UPERM_WRITE | UPERM_SETATTR;
	}
	if (add_uperms)
		uperms = uperms_expand(add_uperms | uperms);
	return (uperms);
}

static unveil_perms
unveil_traverse_track(struct thread *td, struct unveil_traversal *trav, struct vnode *vp)
{
	unveil_perms uperms;
	uperms = trav->uperms;
	uperms = unveil_special_exemptions(td, vp, uperms);
	unveil_tracker_set(td, trav->fill, vp, uperms);
	return (uperms);
}

static void
unveil_traverse_begin(struct thread *td, struct unveil_traversal *trav,
    bool bypass, bool reuse)
{
	struct unveil_stash *stash;
	counter_u64_add(unveil_stats_traversals, 1);
	if (!(trav->bypass = bypass) && (unveil_stash_get(td, &stash), stash)) {
		unveil_stash_check(stash);
		trav->tree = stash->tree;
		trav->flags = stash->flags;
	} else {
		trav->tree = NULL;
		trav->flags = (struct unveil_base_flags){ 0 };
	}
	trav->save = NULL;
	trav->fill = reuse ? unveil_tracker_last(td)
	                   : unveil_tracker_push(td, NULL, UPERM_NONE);
}

static void
unveil_traverse_begin_save(struct thread *td, struct unveil_traversal *trav,
    struct unveil_save *save)
{
	struct unveil_base *base;
	MPASS(save);
	base = td->td_proc->p_unveils;
	MPASS(base);
	counter_u64_add(unveil_stats_traversals, 1);
	sx_assert(&base->sx, SA_XLOCKED);
	trav->flags = base->flags;
	trav->tree = base->tree;
	trav->save = save;
	trav->fill = unveil_tracker_push(td, NULL, UPERM_NONE);
	trav->bypass = false;
}

static int
unveil_traverse_start(struct thread *td, struct unveil_traversal *trav,
    struct vnode *dvp)
{
	const enum unveil_on on = UNVEIL_ON_SELF;
	struct unveil_base *base;
	uint64_t serial;
	int error;
	unsigned depth;
	MPASS(dvp);
	base = td->td_proc->p_unveils;
	serial = unveil_stash_get(td, NULL);
	if (trav->bypass) {
		trav->cover = NULL;
		trav->uncharted = true;
		trav->uperms = UPERM_ALL;
		unveil_traverse_track(td, trav, dvp);
		return (0);
	}
	depth = 0;
	trav->cover = NULL;
	if (unveil_cover_cache_enabled) {
		struct unveil_cache_entry *ent;
		ent = NULL;
		for (size_t i = 0; i < UNVEIL_CACHE_ENTRIES_COUNT; i++)
			if (base->cover_cache.entries[i].vp == dvp)
				ent = &base->cover_cache.entries[i];
		if (ent) {
			if (trav->save)
				sx_assert(&base->sx, SA_XLOCKED);
			else
				sx_slock(&base->sx);
			if (ent->vp == dvp &&
			    ent->vp_nchash == dvp->v_nchash &&
			    ent->vp_hash == dvp->v_hash &&
			    base->cover_cache.serial == serial) {
				trav->cover = ent->cover;
				depth = -1;
				counter_u64_add(unveil_stats_ascents_cached, 1);
			}
			if (!trav->save)
				sx_sunlock(&base->sx);
		}
	}
	if (!trav->cover && trav->tree) {
		error = unveil_find_cover(td, trav->tree, dvp, &trav->cover, &depth);
		if (error)
			return (error);
		if (depth > 0) {
			counter_u64_add(unveil_stats_ascents, 1);
			counter_u64_add(unveil_stats_ascent_total_depth, depth);
			if (unveil_cover_cache_enabled && trav->cover) {
				struct unveil_cache_entry *ent;
				if (trav->save)
					sx_assert(&base->sx, SA_XLOCKED);
				else
					sx_xlock(&base->sx);
				ent = base->cover_cache.entries;
				memcpy(ent, &ent[1], (UNVEIL_CACHE_ENTRIES_COUNT - 1) * sizeof *ent);
				ent->cover = trav->cover;
				ent->vp = dvp;
				ent->vp_nchash = dvp->v_nchash;
				ent->vp_hash = dvp->v_hash;
				base->cover_cache.serial = serial;
				if (!trav->save)
					sx_xunlock(&base->sx);
			}
		}
	}
	trav->uncharted = true;
	trav->uperms = UPERM_NONE;
	if (trav->save) {
		if (trav->cover)
			unveil_save_prefix(trav->save, trav->cover);
		trav->cover = unveil_save(base, trav, NULL, NULL, 0, dvp);
	}
	if (trav->cover) {
		const enum unveil_on on = UNVEIL_ON_SELF;
		trav->uperms = trav->save ? trav->cover->frozen_uperms[on] :
		                            trav->cover->actual_uperms[on] ;
		if (depth)
			trav->uperms = uperms_inherit(trav->uperms);
		else
			trav->uncharted = false;
	} else {
		trav->uperms =
		    (trav->save ? trav->flags.on[on].frozen : unveil_active(td)) ?
		    UPERM_NONE : UPERM_ALL;
	}
	unveil_traverse_track(td, trav, dvp);

	return (0);
}

static void
unveil_traverse_enter(struct unveil_base *base, struct unveil_traversal *trav,
    struct unveil_node *node)
{
	const enum unveil_on on = UNVEIL_ON_SELF;
	if (node) {
		trav->cover = node;
		trav->uncharted = false;
		trav->uperms = trav->save ? node->frozen_uperms[on] :
		                            node->actual_uperms[on] ;
	} else {
		bool had_tmpdir = trav->uperms & UPERM_TMPDIR;
		trav->uncharted = true;
		trav->uperms = uperms_inherit(trav->uperms);
		if (had_tmpdir)
			trav->uperms |= UPERM_TMPDIR_CHILD;
	}
}

static void
unveil_traverse_backtrack(struct thread *td, struct unveil_traversal *trav,
    struct vnode *dvp)
{
	struct unveil_base *base;
	struct unveil_node *node;
	base = td->td_proc->p_unveils;
	if (!trav->uncharted) {
		trav->cover = NULL;
		trav->uperms = UPERM_NONE;
	}
	node = trav->tree ? unveil_tree_lookup(trav->tree, dvp, NULL, 0) : NULL;
	unveil_traverse_enter(base, trav, node);
	unveil_traverse_track(td, trav, dvp);
}

/*
 * Traverse path component cnp located in directory dvp.  vp may point to the
 * target vnode, if it exists.  dvp and vp may point to the same vnode.  vp may
 * be dvp's parent when ISDOTDOT is set.
 */

static void
unveil_traverse_component(struct thread *td, struct unveil_traversal *trav,
    struct vnode *dvp, struct componentname *cnp, struct vnode *vp)
{
	struct unveil_base *base = td->td_proc->p_unveils;
	struct unveil_node *node = NULL;
	char *name = NULL;
	size_t name_len = 0;
	if (cnp->cn_flags & ISDOTDOT) {
		if (!trav->uncharted) {
			trav->cover = NULL;
			trav->uperms = UPERM_NONE;
		}
	} else {
		/*
		 * When resolving a path that ends with slashes, the last path
		 * component may have a zero-length name.
		 */
		if ((name_len = cnp->cn_namelen))
			name = cnp->cn_nameptr;
	}

	if (trav->save) {
		node = unveil_save(base, trav, dvp, name, name_len, vp);
	} else if (trav->tree) {
		if (vp)
			node = unveil_tree_lookup(trav->tree, vp, NULL, 0);
		if (!node && name && (!vp || vp->v_type != VDIR))
			node = unveil_tree_lookup(trav->tree, dvp, name, name_len);
	}

	unveil_traverse_enter(base, trav, node);
	if (vp)
		unveil_traverse_track(td, trav, vp);
	cnp->cn_uperms = trav->uperms;
}

static void
unveil_traverse_replace(struct thread *td, struct unveil_traversal *trav,
    struct vnode *from_vp, struct vnode *to_vp)
{
	MPASS(td->td_unveil_tracker->entries[trav->fill].vp == from_vp);
	unveil_tracker_replace(td, trav->fill, to_vp);
}

static unveil_perms
unveil_traverse_uperms(struct thread *td, struct unveil_traversal *trav)
{
	return (trav->uperms);
}

static void
unveil_traverse_end(struct thread *td, struct unveil_traversal *trav)
{
	struct unveil_base *base;
	base = td->td_proc->p_unveils;
	MPASS(base);
	if (trav->save) {
		MPASS(base->tree == trav->tree);
		sx_assert(&base->sx, SA_XLOCKED);
	}
}


struct unveil_base *
unveil_proc_get_base(struct proc *p, bool create)
{
	struct unveil_base *base;
	if (!(base = (void *)atomic_load_acq_ptr((void *)&p->p_unveils)) && create) {
		struct unveil_base *new_base;
		new_base = malloc(sizeof *new_base, M_UNVEIL, M_WAITOK);
		unveil_base_init(new_base);
		PROC_LOCK(p);
		if (!(base = p->p_unveils))
			p->p_unveils = base = new_base;
		PROC_UNLOCK(p);
		if (base != new_base) {
			unveil_base_free(new_base);
			free(new_base, M_UNVEIL);
		}
	}
	return (base);
}

void
unveil_proc_drop_base(struct proc *p)
{
	struct unveil_base *base;
	if ((base = p->p_unveils)) {
		unveil_base_free(base);
		free(base, M_UNVEIL);
		p->p_unveils = NULL;
	}
}

void
unveil_base_write_begin(struct unveil_base *base)
{
	sx_xlock(&base->sx);
	unveil_base_own(base);
}

void
unveil_base_write_end(struct unveil_base *base)
{
	sx_xunlock(&base->sx);
}


static int
do_unveil_add(struct thread *td, struct unveil_base *base, int flags, struct unveilreg reg)
{
	struct nameidata nd;
	struct unveil_traversal trav;
	struct unveil_save save;
	uint64_t ndflags;
	int error;
	if ((reg.atflags & ~(AT_SYMLINK_NOFOLLOW | AT_RESOLVE_BENEATH)) != 0)
		return (EINVAL);
	/*
	 * NOTE: When doing a lookup to add an unveil, namei() behaves
	 * similarly to CREATE/REMOVE/RENAME lookups with respect to
	 * non-existent final path components and requires that either
	 * WANTPARENT or LOCKPARENT be enabled.
	 */
	ndflags = WANTPARENT |
	    (reg.atflags & AT_SYMLINK_NOFOLLOW ? NOFOLLOW : FOLLOW) |
	    (reg.atflags & AT_RESOLVE_BENEATH ? RBENEATH : 0);
	NDINIT_ATRIGHTS(&nd, LOOKUP, ndflags,
	    UIO_USERSPACE, reg.path, reg.atfd, &cap_fchdir_rights, td);
	nd.ni_unveil = &trav;
	save = (struct unveil_save){ .flags = flags, .first = true, .error = 0 };
	if (reg.tev) {
		if ((save.ter = reg.tec) > UNVEILREG_MAX_TE)
			save.ter = UNVEILREG_MAX_TE;
		save.tev = save.tep = mallocarray(save.ter,
		    sizeof *save.tev, M_TEMP, M_WAITOK);
		if (!save.tev)
			return (EINVAL);
	}
	unveil_traverse_begin_save(td, &trav, &save);
	error = namei(&nd);
	unveil_traverse_end(td, &trav);
	if (error || (error = save.error))
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
		td->td_retval[0] = trav.cover ? trav.cover->index : -1;
out:	if (reg.tev)
		free(save.tev, M_TEMP);
	return (error);
}

int
sys_unveilreg(struct thread *td, struct unveilreg_args *uap)
{
	struct unveil_base *base;
	int flags, error;
	struct unveilreg reg;
	if (!unveil_enabled)
		return (ENOSYS);
	flags = uap->flags;
	if ((flags & UNVEILREG_VER_MASK) != UNVEILREG_THIS_VERSION)
		return (EINVAL);
	error = copyin(uap->reg, &reg, sizeof reg);
	if (error)
		return (error);
	base = unveil_proc_get_base(td->td_proc, true);
	unveil_base_write_begin(base);
	if (flags & UNVEILREG_REGISTER) {
		error = do_unveil_add(td, base, flags, reg);
		if (error)
			goto out;
	}
out:	unveil_base_check(base);
	unveil_base_write_end(base);
	return (error);
}


static void
unveil_proc_ctor(void *arg __unused, struct proc *p)
{
	p->p_unveils = NULL;
}

static void
unveil_proc_dtor(void *arg __unused, struct proc *p)
{
	unveil_proc_drop_base(p);
}

static void
unveil_proc_fork(void *arg __unused, struct proc *parent, struct proc *child, int flags)
{
	struct unveil_base *src, *dst;
	if ((src = parent->p_unveils)) {
		dst = unveil_proc_get_base(child, true);
		sx_slock(&src->sx);
		unveil_base_check(src);
		unveil_base_check(dst);
		unveil_base_copy(dst, src);
		unveil_base_check(dst);
		MPASS((src->tree ? src->tree->node_count : 0) ==
		      (dst->tree ? dst->tree->node_count : 0));
		sx_sunlock(&src->sx);
	}
}

static void
unveil_thread_ctor(void *arg __unused, struct thread *td)
{
	td->td_unveil_tracker = NULL;
}

static void
unveil_thread_dtor(void *arg __unused, struct thread *td)
{
	if (td->td_unveil_tracker) {
		free(td->td_unveil_tracker, M_UNVEIL);
		td->td_unveil_tracker = NULL;
	}
}

static struct unveil_ops unveil_ops_here = {
	.traverse_begin = unveil_traverse_begin,
	.traverse_start = unveil_traverse_start,
	.traverse_component = unveil_traverse_component,
	.traverse_backtrack = unveil_traverse_backtrack,
	.traverse_replace = unveil_traverse_replace,
	.traverse_uperms = unveil_traverse_uperms,
	.traverse_end = unveil_traverse_end,
	.tracker_find = unveil_tracker_find,
	.tracker_find_mount = unveil_tracker_find_mount,
	.tracker_substitute = unveil_tracker_substitute,
	.tracker_push_file = unveil_tracker_push_file,
	.tracker_save_file = unveil_tracker_save_file,
};

static struct syscall_helper_data unveil_syscalls[] = {
	SYSCALL_INIT_HELPER(unveilreg),
	SYSCALL_INIT_LAST,
};

static eventhandler_tag unveil_proc_ctor_tag,
                        unveil_proc_dtor_tag,
                        unveil_proc_fork_tag;
static eventhandler_tag unveil_thread_ctor_tag,
                        unveil_thread_dtor_tag;

static void
unveil_sysinit(void *arg __unused)
{
	int error;
	if (!unveil_support) {
		printf("%s: kernel not built with UNVEIL_SUPPORT!\n", __FUNCTION__);
		return;
	}
	unveil_proc_ctor_tag = EVENTHANDLER_REGISTER(
	    process_ctor, unveil_proc_ctor, NULL, EVENTHANDLER_PRI_ANY);
	unveil_proc_dtor_tag = EVENTHANDLER_REGISTER(
	    process_dtor, unveil_proc_dtor, NULL, EVENTHANDLER_PRI_ANY);
	unveil_proc_fork_tag = EVENTHANDLER_REGISTER(
	    process_fork, unveil_proc_fork, NULL, EVENTHANDLER_PRI_ANY);
	unveil_thread_ctor_tag = EVENTHANDLER_REGISTER(
	    thread_ctor, unveil_thread_ctor, NULL, EVENTHANDLER_PRI_ANY);
	unveil_thread_dtor_tag = EVENTHANDLER_REGISTER(
	    thread_dtor, unveil_thread_dtor, NULL, EVENTHANDLER_PRI_ANY);
	if (unveil_ops)
		printf("%s: unveil_ops was already set!\n", __FUNCTION__);
	unveil_ops = &unveil_ops_here;
	error = syscall_helper_register(unveil_syscalls,
	    SY_THR_STATIC_KLD | SY_HLP_PRESERVE_SYFLAGS);
	if (error)
		printf("%s: syscall_helper_register error %d\n", __FUNCTION__, error);
}

static void
unveil_sysuninit(void *arg __unused)
{
	if (!unveil_support)
		return;
	if (unveil_ops != &unveil_ops_here)
		printf("%s: unveil_ops was tampered with!\n", __FUNCTION__);
	unveil_ops = NULL;
	syscall_helper_unregister(unveil_syscalls);
	EVENTHANDLER_DEREGISTER(process_ctor, unveil_proc_ctor_tag);
	EVENTHANDLER_DEREGISTER(process_dtor, unveil_proc_dtor_tag);
	EVENTHANDLER_DEREGISTER(process_fork, unveil_proc_fork_tag);
	EVENTHANDLER_DEREGISTER(thread_ctor, unveil_thread_ctor_tag);
	EVENTHANDLER_DEREGISTER(thread_dtor, unveil_thread_dtor_tag);
}

SYSINIT(unveil_sysinit, SI_SUB_KLD, SI_ORDER_ANY, unveil_sysinit, NULL);
SYSUNINIT(unveil_sysinit, SI_SUB_KLD, SI_ORDER_ANY, unveil_sysuninit, NULL);

#endif /* UNVEIL_SUPPORT */
