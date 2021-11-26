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
#include <sys/dirent.h>
#include <sys/sysctl.h>
#include <sys/sx.h>
#include <sys/mutex.h>
#include <sys/refcount.h>
#include <sys/eventhandler.h>
#include <sys/filedesc.h>
#include <sys/conf.h>
#include <sys/sysent.h>
#include <sys/syscall.h>
#include <sys/unveil.h>
#include <sys/curtain.h>

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
STATNODE_COUNTER(dirent_lookups, unveil_stats_dirent_lookups, "");

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
	bool hidden_children[UNVEIL_ON_COUNT];
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

struct unveil_cache {
	struct mtx mtx;
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
			new_node->hidden_children[i] = old_node->hidden_children[i];
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
	mtx_init(&base->cover_cache.mtx, "unveil cover cache", NULL, MTX_DEF | MTX_NEW);
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
	mtx_destroy(&base->cover_cache.mtx);
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
	UNVEIL_FOREACH(node, stash) {
		node->actual_uperms[on] = node->frozen_uperms[on] &
		    unveil_node_wanted_uperms(node, on);
		node->hidden_children[on] = false;
	}
	UNVEIL_FOREACH(node, stash) {
		if (node->cover && !(node->actual_uperms[on] & UPERM_EXPOSE))
			node->cover->hidden_children[on] = true;
	}
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
		node->hidden_children[d] = node->hidden_children[s];
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
unveil_stash_get(struct ucred *cr, struct unveil_stash **p)
{
	struct curtain *ct;
	if ((ct = curtain_from_cred(cr))) {
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

static void
unveil_track_init(struct unveil_tracker *track, uint64_t serial, struct unveil_stash *stash)
{
	if (stash)
		unveil_stash_check(stash);
	*track = (struct unveil_tracker){
		.serial = serial,
		.tree = stash ? stash->tree : NULL,
		.flags = stash ? stash->flags : (struct unveil_base_flags){ 0 },
		.fill = UNVEIL_TRACKER_ENTRIES_COUNT - 1,
	};
}

void
unveil_track_reset(struct unveil_tracker *track)
{
	*track = (struct unveil_tracker){ 0 };
}

struct unveil_tracker *
unveil_track_get(struct ucred *cr, bool create)
{
	struct unveil_tracker *track;
	struct unveil_stash *stash;
	uint64_t serial;
	if ((track = curthread->td_unveil_tracker)) {
		serial = unveil_stash_get(cr, &stash);
		if (!track->save && __predict_false(track->serial != serial))
			unveil_track_init(track, serial, stash);
		return (track);
	} else if (create) {
		serial = unveil_stash_get(cr, &stash);
		track = malloc(sizeof *track, M_UNVEIL, M_WAITOK);
		unveil_track_init(track, serial, stash);
		curthread->td_unveil_tracker = track;
	}
	return (track);
}

static unsigned
unveil_track_roll(struct unveil_tracker *track, int offset)
{
	if (offset > 0) {
		do {
			if (++track->fill == UNVEIL_TRACKER_ENTRIES_COUNT)
				track->fill = 0;
		} while (--offset);
	} else if (offset < 0) {
		do {
			if (track->fill-- == 0)
				track->fill = UNVEIL_TRACKER_ENTRIES_COUNT - 1;
		} while (++offset);
	}
	return (track->fill);
}

static struct unveil_tracker_entry *
unveil_track_peek(struct unveil_tracker *track)
{
	return (&track->entries[track->fill]);
}

static struct unveil_tracker_entry *
unveil_track_fill(struct unveil_tracker *track, struct vnode *vp)
{
	track->entries[track->fill] = (struct unveil_tracker_entry){
		.vp = vp,
		.vp_nchash = vp ? vp->v_nchash : 0,
		.vp_hash = vp ? vp->v_hash : 0,
		.mp = vp ? vp->v_mount : NULL,
		.mp_gen = vp && vp->v_mount ? vp->v_mount->mnt_gen : 0,
	};
	return (&track->entries[track->fill]);
}

struct unveil_tracker_entry *
unveil_track_find(struct unveil_tracker *track, struct vnode *vp)
{
	MPASS(vp);
	for (unsigned j = 0; j < UNVEIL_TRACKER_ENTRIES_COUNT; j++) {
		unsigned i = (track->fill + j) % UNVEIL_TRACKER_ENTRIES_COUNT;
		if (track->entries[i].vp == vp &&
		    track->entries[i].vp_nchash == vp->v_nchash &&
		    track->entries[i].vp_hash == vp->v_hash &&
		    track->entries[i].mp == vp->v_mount &&
		    track->entries[i].mp_gen == (vp->v_mount ? vp->v_mount->mnt_gen : 0))
			return (&track->entries[i]);
	}
	return (NULL);
}

struct unveil_tracker_entry *
unveil_track_find_mount(struct unveil_tracker *track, struct mount *mp)
{
	MPASS(mp);
	for (unsigned j = 0; j < UNVEIL_TRACKER_ENTRIES_COUNT; j++) {
		unsigned i = (track->fill + j) % UNVEIL_TRACKER_ENTRIES_COUNT;
		if (track->entries[i].mp == mp &&
		    track->entries[i].mp_gen == mp->mnt_gen)
			return (&track->entries[i]);
	}
	return (NULL);
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

static void
unveil_node_set_cover(struct unveil_node *node, struct unveil_node *cover)
{
	for (struct unveil_node *iter = cover; iter; iter = iter->cover)
		if (iter == node)
			return; /* prevent loops */
	node->cover = cover;
}

static void
unveil_node_init_uperms(struct unveil_node *node, struct unveil_node *cover,
    struct unveil_base_flags flags, struct ucred *cr)
{
	for (int i = 0; i < UNVEIL_ON_COUNT; i++) {
		node->wanted[i] = false;
		node->wanted_uperms[i] = UPERM_NONE;
		node->frozen_uperms[i] =
		    cover ? uperms_inherit(cover->frozen_uperms[i]) :
		    flags.on[i].frozen ? UPERM_NONE : UPERM_ALL;
		node->actual_uperms[i] =
		    (cover ? uperms_inherit(cover->actual_uperms[i]) :
		     CRED_IN_VFS_VEILED_MODE(cr) ? UPERM_NONE : UPERM_ALL) &
		    node->frozen_uperms[i];
	}
}

static struct unveil_node *
unveil_save(struct ucred *cr, struct unveil_tracker *track,
    struct vnode *dvp, const char *name, size_t name_len, struct vnode *vp)
{
	struct unveil_node *node;
	bool inserted;
	MPASS(!(name && !dvp));

	if (name && name_len > NAME_MAX) {
		track->save->error = ENAMETOOLONG;
		return (NULL);
	}
	if (track->tree->node_count >= unveil_max_nodes_per_process) {
		track->save->error = E2BIG;
		return (NULL);
	}

	if (name && (!vp || vp->v_type != VDIR) &&
	    (track->save->flags & UNVEILREG_NONDIRBYNAME))
		node = unveil_tree_insert(track->tree, dvp, name, name_len, &inserted);
	else if (vp)
		node = unveil_tree_insert(track->tree, vp, NULL, 0, &inserted);
	else
		return (NULL);

	/*
	 * Update the cover link of the node.  If directories move around, the
	 * cover hierarchy might become out of date.
	 */
	if (track->cover)
		unveil_node_set_cover(node, track->cover);

	/*
	 * Newly added unveil nodes can inherit frozen permissions from their
	 * most immediate covering node (if any).  Note that this is the
	 * covering node that was discovered while traversing the path, it does
	 * not come from a node's cover link.
	 */
	if (inserted)
		unveil_node_init_uperms(node, track->cover, track->flags, cr);

	if (track->save->ter) {
		(*track->save->tep)[0] = node->cover ? node->cover->index : node->index;
		(*track->save->tep)[1] = node->index;
		track->save->tep++, track->save->ter--;
	} else
		track->save->te_overflow = true;

	return (node);
}

static int
unveil_find_cover(struct ucred *cr, struct unveil_tree *tree,
    struct vnode *dp, struct unveil_node **cover, unsigned *depth)
{
	int error, lkflags;
	struct mount *mp;
	struct vnode *vp;
	struct componentname cn;

	if ((mp = dp->v_mount) &&
	    (mp->mnt_kern_flag & (MNTK_LOOKUP_SHARED | MNTK_LOOKUP_EXCL_DOTDOT)) ==
	    MNTK_LOOKUP_SHARED)
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
			.cn_cred = cr,
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
curtain_device_unveil_bypass(struct ucred *cr, struct cdev *dev)
{
	return (dev->si_cred && curtain_cred_visible(cr, dev->si_cred, BARRIER_DEVICE));
}

static unveil_perms
unveil_special_exemptions(struct ucred *cr, struct vnode *vp, unveil_perms uperms)
{
	unveil_perms add_uperms = UPERM_NONE;
	if (uperms & UPERM_DEVFS) {
		if (vp && vp->v_type == VCHR && vp->v_rdev &&
		    curtain_device_unveil_bypass(cr, vp->v_rdev))
			add_uperms |= UPERM_READ | UPERM_WRITE | UPERM_SETATTR;
	}
	if (add_uperms != UPERM_NONE)
		uperms = uperms_expand(add_uperms | uperms);
	return (uperms);
}

void
unveil_vnode_walk_roll(struct ucred *cr, int offset)
{
	struct unveil_tracker *track;
	if (!(track = unveil_track_get(cr, false)))
		return;
	unveil_track_roll(track, offset);
}

void
unveil_vnode_walk_annotate_file(struct ucred *cr, struct file *fp, struct vnode *vp)
{
	struct unveil_tracker *track;
	struct unveil_tracker_entry *entry;
	fp->f_uldgen = unveil_stash_get(cr, NULL);
	if (CRED_IN_VFS_VEILED_MODE(cr)) {
		if ((track = unveil_track_get(cr, false)) &&
		    (entry = unveil_track_find(track, vp)))
			fp->f_uperms = entry->uperms;
		else
			fp->f_uperms = UPERM_NONE;
	} else
		fp->f_uperms = UPERM_ALL;
}

int
unveil_vnode_walk_start_file(struct ucred *cr, struct file *fp)
{
	struct unveil_tracker *track;
	unveil_perms uperms;
	if (!fp->f_vnode)
		return (0);
	track = unveil_track_get(cr, true);
	uperms = fp->f_uperms;
	if ((fp->f_uldgen != track->serial))
		uperms &= unveil_fflags_uperms(fp->f_vnode->v_type, fp->f_flag);
	unveil_track_roll(track, 1);
	unveil_track_fill(track, fp->f_vnode)->uperms = uperms;
	return (0);
}

int
unveil_vnode_walk_start(struct ucred *cr, struct vnode *dvp)
{
	const enum unveil_on on = UNVEIL_ON_SELF;
	struct unveil_tracker *track;
	struct unveil_base *base;
	int error;
	unsigned depth;
	MPASS(dvp);
	track = unveil_track_get(cr, true);
	base = curthread->td_proc->p_unveils;
	counter_u64_add(unveil_stats_traversals, 1);
	depth = 0;
	track->cover = NULL;
	if (unveil_cover_cache_enabled && base && !track->save) {
		struct unveil_cache_entry *ent;
		ent = NULL;
		for (size_t i = 0; i < UNVEIL_CACHE_ENTRIES_COUNT; i++)
			if (base->cover_cache.entries[i].vp == dvp)
				ent = &base->cover_cache.entries[i];
		if (ent) {
			mtx_lock(&base->cover_cache.mtx);
			if (ent->vp == dvp &&
			    ent->vp_nchash == dvp->v_nchash &&
			    ent->vp_hash == dvp->v_hash &&
			    base->cover_cache.serial == track->serial) {
				track->cover = ent->cover;
				depth = -1;
				counter_u64_add(unveil_stats_ascents_cached, 1);
			}
			mtx_unlock(&base->cover_cache.mtx);
		}
	}
	if (!track->cover && track->tree) {
		error = unveil_find_cover(cr, track->tree, dvp, &track->cover, &depth);
		if (error)
			return (error);
		if (depth > 0) {
			counter_u64_add(unveil_stats_ascents, 1);
			counter_u64_add(unveil_stats_ascent_total_depth, depth);
			if (unveil_cover_cache_enabled && base && !track->save && track->cover) {
				struct unveil_cache_entry *ent;
				mtx_lock(&base->cover_cache.mtx);
				ent = base->cover_cache.entries;
				memcpy(ent, &ent[1], (UNVEIL_CACHE_ENTRIES_COUNT - 1) * sizeof *ent);
				ent->cover = track->cover;
				ent->vp = dvp;
				ent->vp_nchash = dvp->v_nchash;
				ent->vp_hash = dvp->v_hash;
				base->cover_cache.serial = track->serial;
				mtx_unlock(&base->cover_cache.mtx);
			}
		}
	}
	track->uncharted = true;
	track->uperms = UPERM_NONE;
	if (track->save) {
		if (track->cover)
			unveil_save_prefix(track->save, track->cover);
		track->cover = unveil_save(cr, track, NULL, NULL, 0, dvp);
	}
	if (track->cover) {
		const enum unveil_on on = UNVEIL_ON_SELF;
		track->uperms = track->save ? track->cover->frozen_uperms[on] :
		                              track->cover->actual_uperms[on] ;
		if (depth)
			track->uperms = uperms_inherit(track->uperms);
		else
			track->uncharted = false;
	} else {
		track->uperms =
		    (track->save ? track->flags.on[on].frozen :
		     CRED_IN_VFS_VEILED_MODE(cr)) ?
		    UPERM_NONE : UPERM_ALL;
	}

	unveil_track_fill(track, dvp)->uperms = track->uperms;
	return (0);
}

static void
unveil_traverse_enter(struct unveil_tracker *track, struct unveil_node *node)
{
	const enum unveil_on on = UNVEIL_ON_SELF;
	if (node) {
		track->cover = node;
		track->uncharted = false;
		track->uperms = track->save ? node->frozen_uperms[on] :
		                              node->actual_uperms[on] ;
	} else {
		bool had_tmpdir = track->uperms & UPERM_TMPDIR;
		track->uncharted = true;
		track->uperms = uperms_inherit(track->uperms);
		if (had_tmpdir)
			track->uperms |= UPERM_TMPDIR_CHILD;
	}
}

void
unveil_vnode_walk_backtrack(struct ucred *cr, struct vnode *dvp)
{
	struct unveil_tracker *track;
	struct unveil_node *node;
	if (!(track = unveil_track_get(cr, false)))
		return;
	if (!track->uncharted) {
		track->cover = NULL;
		track->uperms = UPERM_NONE;
	}
	node = track->tree ? unveil_tree_lookup(track->tree, dvp, NULL, 0) : NULL;
	unveil_traverse_enter(track, node);
	unveil_track_fill(track, dvp)->uperms = track->uperms;
}

/*
 * Traverse path component cnp located in directory dvp.  vp may point to the
 * target vnode, if it exists.  dvp and vp may point to the same vnode.  vp may
 * be dvp's parent when ISDOTDOT is set.
 */

void
unveil_vnode_walk_component(struct ucred *cr,
    struct vnode *dvp, struct componentname *cnp, struct vnode *vp)
{
	struct unveil_tracker *track;
	struct unveil_node *node = NULL;
	char *name = NULL;
	size_t name_len = 0;
	if (!(track = unveil_track_get(cr, false)))
		return;
	if (cnp->cn_flags & ISDOTDOT) {
		if (!track->uncharted) {
			track->cover = NULL;
			track->uperms = UPERM_NONE;
		}
	} else {
		/*
		 * When resolving a path that ends with slashes, the last path
		 * component may have a zero-length name.
		 */
		if ((name_len = cnp->cn_namelen))
			name = cnp->cn_nameptr;
	}

	if (track->save) {
		node = unveil_save(cr, track, dvp, name, name_len, vp);
	} else if (track->tree) {
		if (vp)
			node = unveil_tree_lookup(track->tree, vp, NULL, 0);
		if (!node && name && (!vp || vp->v_type != VDIR))
			node = unveil_tree_lookup(track->tree, dvp, name, name_len);
	}

	unveil_traverse_enter(track, node);
	if (vp) {
		track->uperms = unveil_special_exemptions(cr, vp, track->uperms);
		unveil_track_fill(track, vp)->uperms = track->uperms;
	} else {
		struct unveil_tracker_entry *entry;
		if ((entry = unveil_track_find(track, dvp)))
			entry->pending_uperms = track->uperms;
	}
}

void
unveil_vnode_walk_replace(struct ucred *cr,
    struct vnode *from_vp, struct vnode *to_vp)
{
	struct unveil_tracker *track;
	if (!(track = unveil_track_get(cr, false)))
		return;
	if (unveil_track_peek(track)->vp == from_vp)
		unveil_track_fill(track, to_vp)->uperms = track->uperms;
}

void
unveil_vnode_walk_created(struct ucred *cr, struct vnode *dvp, struct vnode *vp)
{
	struct unveil_tracker *track;
	struct unveil_tracker_entry *entry;
	if ((track = unveil_track_get(cr, false)) &&
	    (entry = unveil_track_peek(track))) {
		if (entry->vp == dvp) {
			unveil_perms uperms = entry->pending_uperms;
			unveil_track_fill(track, vp)->uperms = uperms;
		}
	}
}

int
unveil_vnode_walk_fixup_errno(struct ucred *cr, int error)
{
	struct unveil_tracker *track;
	if (!(track = unveil_track_get(cr, false)))
		return (error);
	if (error) {
		/*
		 * Prevent using errnos (like EISDIR/ENOTDIR/etc) to infer the
		 * existence and type of path components after a lookup.  Note
		 * that UPERM_DEVFS gives an inheritable UPERM_TRAVERSE on a
		 * whole directory hierarchy.
		 */
		if (!(track->uperms & UPERM_EXPOSE))
			error = ENOENT;
	} else {
		/*
		 * Many syscalls inspect the target vnodes before calling the
		 * MAC check functions (which would then return ENOENT when
		 * needed permissions are missing and UPERM_EXPOSE is not set)
		 * and may return various errnos instead of ENOENT.
		 *
		 * This errno fixup is to make them fail early with ENOENT
		 * after lookup in the case where the path was not unveiled or
		 * was unveiled with just UPERM_TRAVERSE (which is the default
		 * for intermediate path components when using unveil(3)).
		 *
		 * It also deals with a few special cases (and maybe others?):
		 *
		 * - mac_vnode_check_readlink() should be allowed with just
		 *   UPERM_TRAVERSE when called from within namei() for a path
		 *   lookup, but should be denied when it's done for readlink(2)
		 *   and the user could retrieve the symlink target string.
		 *
		 * - __realpathat(2) lacks MAC checks, and this protects it.
		 */
		if (!(track->uperms & ~UPERM_TRAVERSE))
			error = ENOENT;
	}
	return (error);
}

bool
unveil_vnode_walk_dirent_visible(struct ucred *cr, struct vnode *dvp, struct dirent *dp)
{
	struct unveil_tracker *track;
	struct unveil_tracker_entry *entry;
	struct unveil_node *node;
	struct vnode *vp;
	struct mount *mp;
	struct componentname cn;
	unveil_perms uperms;
	int error;

	if (!((track = unveil_track_get(cr, false)) &&
	      (entry = unveil_track_find(track, dvp))))
		return (false);

	uperms = entry->uperms;
	if (!(uperms & UPERM_LIST))
		return (false);

	if (!dp) { /* request to check if all children are visible */
		if (!(uperms & UPERM_BROWSE))
			return (false); /* children not visible by default */
		node = track->tree ? unveil_tree_lookup(track->tree, dvp, NULL, 0) : NULL;
		return (!(node && node->hidden_children[UNVEIL_ON_SELF]));
	}

	if ((dp->d_namlen == 2 && dp->d_name[0] == '.' && dp->d_name[1] == '.') ||
	    (dp->d_namlen == 1 && dp->d_name[0] == '.'))
		return (true);

	/* TODO: Could skip lookups for non-directories if it were known that
	 * they were always unveiled by name. */

	counter_u64_add(unveil_stats_dirent_lookups, 1);
	cn = (struct componentname){
		.cn_nameiop = LOOKUP,
		.cn_flags = ISLASTCN,
		.cn_lkflags = LK_SHARED,
		.cn_cred = cr,
		.cn_nameptr = dp->d_name,
		.cn_namelen = dp->d_namlen,
	};
	error = VOP_LOOKUP(dvp, &vp, &cn);
	if (error)
		return (false);

	while (vp->v_type == VDIR && (mp = vp->v_mountedhere)) {
		if (vfs_busy(mp, 0))
			continue;
		if (vp != dvp)
			vput(vp);
		else
			vrele(vp);
		error = VFS_ROOT(mp, LK_SHARED, &vp);
		vfs_unbusy(mp);
		if (error)
			return (false);
	}

	if (track->tree) {
		node = unveil_tree_lookup(track->tree, vp, NULL, 0);
		if (!node && vp->v_type != VDIR)
			node = unveil_tree_lookup(track->tree, dvp, cn.cn_nameptr, cn.cn_namelen);
		if (node)
			uperms = node->actual_uperms[UNVEIL_ON_SELF];
		else
			uperms = uperms_inherit(uperms);
	}

	if (vp != dvp)
		vput(vp);
	else
		vrele(vp);

	return (uperms & UPERM_EXPOSE);
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
	struct unveil_tracker *track;
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
	ndflags = FORCEMACWALK | WANTPARENT |
	    (reg.atflags & AT_SYMLINK_NOFOLLOW ? NOFOLLOW : FOLLOW) |
	    (reg.atflags & AT_RESOLVE_BENEATH ? RBENEATH : 0);
	NDINIT_ATRIGHTS(&nd, LOOKUP, ndflags,
	    UIO_USERSPACE, reg.path, reg.atfd, &cap_fchdir_rights);
	save = (struct unveil_save){ .flags = flags, .first = true, .error = 0 };
	if (reg.tev) {
		if ((save.ter = reg.tec) > UNVEILREG_MAX_TE)
			save.ter = UNVEILREG_MAX_TE;
		save.tev = save.tep = mallocarray(save.ter,
		    sizeof *save.tev, M_TEMP, M_WAITOK);
		if (!save.tev)
			return (EINVAL);
	}
	track = unveil_track_get(td->td_ucred, true);
	*track = (struct unveil_tracker){
		.serial = 0,
		.fill = 0,
		.save = &save,
		.tree = base->tree,
		.flags = base->flags,
	};
	error = namei(&nd);
	track->save = NULL;
	if (!error) {
		NDFREE(&nd, 0);
		error = save.error;
	}
	if (error)
		goto out;
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
		td->td_retval[0] = track->cover ? track->cover->index : -1;
out:	if (reg.tev)
		free(save.tev, M_TEMP);
	unveil_track_reset(track);
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
	error = syscall_helper_register(unveil_syscalls,
	    SY_THR_STATIC_KLD | SY_HLP_PRESERVE_SYFLAGS);
	if (error)
		printf("%s: syscall_helper_register error %d\n", __FUNCTION__, error);
}

static void
unveil_sysuninit(void *arg __unused)
{
	syscall_helper_unregister(unveil_syscalls);
	EVENTHANDLER_DEREGISTER(process_ctor, unveil_proc_ctor_tag);
	EVENTHANDLER_DEREGISTER(process_dtor, unveil_proc_dtor_tag);
	EVENTHANDLER_DEREGISTER(process_fork, unveil_proc_fork_tag);
	EVENTHANDLER_DEREGISTER(thread_ctor, unveil_thread_ctor_tag);
	EVENTHANDLER_DEREGISTER(thread_dtor, unveil_thread_dtor_tag);
}

SYSINIT(unveil_sysinit, SI_SUB_KLD, SI_ORDER_ANY, unveil_sysinit, NULL);
SYSUNINIT(unveil_sysinit, SI_SUB_KLD, SI_ORDER_ANY, unveil_sysuninit, NULL);
