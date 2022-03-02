#include <sys/param.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/counter.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sysproto.h>
#include <sys/ucred.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/dirent.h>
#include <sys/sysctl.h>
#include <sys/mutex.h>
#include <sys/eventhandler.h>
#include <sys/conf.h>
#include <sys/sysent.h>
#include <sys/syscall.h>
#include <sys/fnv_hash.h>

#include <security/mac_curtain/curtain_int.h>
#include <security/mac_curtain/unveil.h>

static MALLOC_DEFINE(M_UNVEIL_CACHE, "unveil cache", "mac_curtain per-procecess unveil caches");
static MALLOC_DEFINE(M_UNVEIL_TRACK, "unveil track", "mac_curtain per-thread unveil trackers");

static bool __read_mostly unveil_cover_cache_enabled = true;
static bool __read_mostly unveil_ignore_fixup_vnode_errors = true;
static unsigned int __read_mostly unveil_max_per_curtain = 256;

SYSCTL_BOOL(_security_curtain, OID_AUTO, unveil_cover_cache,
    CTLFLAG_RW, &unveil_cover_cache_enabled, 0, "");

SYSCTL_UINT(_security_curtain, OID_AUTO, max_unveils_per_curtain,
    CTLFLAG_RW, &unveil_max_per_curtain, 0, "Maximum unveils allowed per process");

SYSCTL_BOOL(_security_curtain, OID_AUTO, unveil_ignore_fixup_vnode_errors,
    CTLFLAG_RW, &unveil_ignore_fixup_vnode_errors, 0, "");

#ifdef CURTAIN_STATS

static SYSCTL_NODE(_security_curtain_stats, OID_AUTO, unveil,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0, "");

#define STATNODE_COUNTER(name, varname, descr)					\
	static COUNTER_U64_DEFINE_EARLY(varname);				\
	SYSCTL_COUNTER_U64(_security_curtain_stats_unveil, OID_AUTO, name,	\
	    CTLFLAG_RD, &varname, descr);

STATNODE_COUNTER(traversals, unveil_stats_traversals, "");
STATNODE_COUNTER(ascents, unveil_stats_ascents, "");
STATNODE_COUNTER(ascents_cached, unveil_stats_ascents_cached, "");
STATNODE_COUNTER(ascent_total_depth, unveil_stats_ascent_total_depth, "");
STATNODE_COUNTER(dirent_unknowns, unveil_stats_dirent_unknowns, "");
STATNODE_COUNTER(dirent_vnode_lookups, unveil_stats_dirent_vnode_lookups, "");
STATNODE_COUNTER(dirent_vnode_errors, unveil_stats_dirent_vnode_errors, "");
STATNODE_COUNTER(dirent_name_lookups, unveil_stats_dirent_name_lookups, "");

#endif


static void
unveil_cache_init(struct unveil_cache *cache)
{
	*cache = (struct unveil_cache){ 0 };
	mtx_init(&cache->mtx, "unveil cover cache", NULL, MTX_DEF | MTX_NEW);
}

static void
unveil_cache_copy(struct unveil_cache *dst, const struct unveil_cache *src)
{
	dst->serial = src->serial;
	for (size_t i = 0; i < UNVEIL_CACHE_ENTRIES_COUNT; i++)
		dst->entries[i] = src->entries[i];
}

static void
unveil_cache_free(struct unveil_cache *cache)
{
	mtx_destroy(&cache->mtx);
}


static unveil_perms
unveil_fflags_uperms(enum vtype type, int fflags)
{
	unveil_perms uperms = UPERM_NONE;
	if (type == VDIR) {
		if ((fflags & FSEARCH) != 0)
			uperms |= UPERM_INSPECT;
		if ((fflags & FREAD) != 0)
			uperms |= UPERM_LIST | UPERM_INSPECT;
	} else {
		if ((fflags & FREAD) != 0)
			uperms |= UPERM_READ;
		if ((fflags & FWRITE) != 0)
			uperms |= UPERM_WRITE | UPERM_SETATTR;
		if ((fflags & FEXEC) != 0)
			uperms |= UPERM_EXECUTE;
	}
	return (uperms_expand(uperms));
}

static void
unveil_track_init(struct unveil_tracker *track, struct curtain *ct)
{
	*track = (struct unveil_tracker){
		.ct = ct,
		.serial = ct != NULL ? curtain_serial(ct) : 0,
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
	struct curtain *ct;
	if ((track = curthread->td_unveil_tracker) != NULL) {
		ct = curtain_from_cred(cr);
		if (__predict_false(track->serial != (ct != NULL ? curtain_serial(ct) : 0)))
			unveil_track_init(track, ct);
		return (track);
	} else if (create) {
		ct = curtain_from_cred(cr);
		track = malloc(sizeof *track, M_UNVEIL_TRACK, M_WAITOK);
		unveil_track_init(track, ct);
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
unveil_track_pick(struct unveil_tracker *track, struct vnode *vp)
{
	struct unveil_tracker_entry *entry;
	entry = unveil_track_peek(track);
	if (entry->vp != vp)
		return (NULL);
	return (entry);
}

static struct unveil_tracker_entry *
unveil_track_fill(struct unveil_tracker *track, struct vnode *vp)
{
	track->entries[track->fill] = (struct unveil_tracker_entry){
		.vp = vp,
		.vp_nchash = vp != NULL ? vp->v_nchash : 0,
		.vp_hash = vp != NULL ? vp->v_hash : 0,
		.mp = vp != NULL ? vp->v_mount : NULL,
		.mp_gen = vp != NULL && vp->v_mount != NULL ? vp->v_mount->mnt_gen : 0,
	};
	return (&track->entries[track->fill]);
}

struct unveil_tracker_entry *
unveil_track_find(struct unveil_tracker *track, struct vnode *vp)
{
	for (unsigned j = 0; j < UNVEIL_TRACKER_ENTRIES_COUNT; j++) {
		unsigned i = (track->fill + j) % UNVEIL_TRACKER_ENTRIES_COUNT;
		if (track->entries[i].vp == vp &&
		    track->entries[i].vp_nchash == vp->v_nchash &&
		    track->entries[i].vp_hash == vp->v_hash &&
		    track->entries[i].mp == vp->v_mount &&
		    track->entries[i].mp_gen == (vp->v_mount != NULL ? vp->v_mount->mnt_gen : 0))
			return (&track->entries[i]);
	}
	return (NULL);
}

struct unveil_tracker_entry *
unveil_track_find_mount(struct unveil_tracker *track, struct mount *mp)
{
	for (unsigned j = 0; j < UNVEIL_TRACKER_ENTRIES_COUNT; j++) {
		unsigned i = (track->fill + j) % UNVEIL_TRACKER_ENTRIES_COUNT;
		if (track->entries[i].mp == mp &&
		    track->entries[i].mp_gen == mp->mnt_gen)
			return (&track->entries[i]);
	}
	return (NULL);
}


static inline int
mount_dotdot_lkflags(struct mount *mp)
{
	return (mp != NULL && (mp->mnt_kern_flag & (MNTK_LOOKUP_SHARED | MNTK_LOOKUP_EXCL_DOTDOT)) ==
	    MNTK_LOOKUP_SHARED ? LK_SHARED : LK_EXCLUSIVE);
}

/*
 * On success, returns with dp unlocked and unreferenced (unless it is its own
 * parent directory) and its parent directory in *vpp locked and referenced.
 */
static int
vnode_lookup_dotdot(struct vnode *dp, struct ucred *cr, struct vnode **vpp)
{
	int error, lkflags;
	struct vnode *vp;
	struct componentname cn;

	ASSERT_VOP_LOCKED(dp, __func__);

	do {
		lkflags = mount_dotdot_lkflags(dp->v_mount);
		if ((dp->v_vflag & VV_ROOT) == 0 ||
		    dp->v_mount == NULL ||
		    (vp = dp->v_mount->mnt_vnodecovered) == NULL)
			break;
		vref(vp);
		vput(dp);
		vn_lock(vp, LK_RETRY | lkflags);
		dp = vp;
	} while (true);

	/*
	 * NOTE: The NOEXECCHECK flag is important for two cases:
	 * - Finding the parent directory of directories being unveiled.  The
	 *   user may be able to see them and open them with O_PATH but not be
	 *   able to traverse them.
	 * - Finding the covering unveil of the starting directory during a
	 *   path lookup.  The user may not have the filesystem permissions on
	 *   the directory (though it could have been pre-opened with O_SEARCH)
	 *   or some of its parent directories.
	 */
	cn = (struct componentname){
		.cn_nameiop = LOOKUP,
		.cn_flags = ISLASTCN | ISDOTDOT | NOEXECCHECK,
		.cn_lkflags = lkflags,
		.cn_cred = cr,
		.cn_nameptr = "..",
		.cn_namelen = 2,
	};
	error = VOP_LOOKUP(dp, &vp, &cn);
	if (error != 0)
		return (error);
	if (dp == vp) {
		vrele(dp);
	} else {
		vput(dp);
		dp = vp;
	}
	*vpp = dp;
	return (0);
}


unveil_perms
curtain_lookup_mount(const struct curtain *ct, struct mount *mp)
{
	/* XXX linear search, very ad-hoc function */
	const struct curtain_item *item;
	unveil_perms uperms;
	uperms = UPERM_NONE;
	for (item = ct->ct_slots; item < &ct->ct_slots[ct->ct_nslots]; item++)
		if (item->type == CURTAIN_UNVEIL)
			if (item->key.unveil->vp->v_mount == mp)
				uperms |= item->key.unveil->soft_uperms;
	return (uperms_expand(uperms));
}

#define UNVEIL_MAX_DEPTH 32

static int
curtain_fixup_unveil_parent(struct curtain *ct, struct ucred *cr, struct curtain_unveil *uv,
    size_t pending_depth)
{
	int error;
	if (uv->parent == NULL) {
		/*
		 * Fill in missing unveil parent links.  For directories, do an
		 * actual FS lookup to find the unveil's parent vnode first.
		 */
		struct curtain_item *parent_item;
		struct curtain_unveil uv1;
		struct vnode *vp;
		vp = uv->vp;
		if (vp->v_type != VDIR)
			return (ENOTDIR);
		if (uv->name_len == 0) {
			vget(vp, LK_RETRY | mount_dotdot_lkflags(vp->v_mount));
			error = vnode_lookup_dotdot(vp, cr, &vp);
			if (error != 0 || vp == uv->vp) {
				vput(vp);
				if (error != 0 && !unveil_ignore_fixup_vnode_errors)
					return (error);
				vp = NULL;
			}
		}
		if (vp != NULL) {
			uv1 = (struct curtain_unveil){ .vp = vp, .hash = vp->v_nchash };
			parent_item = curtain_lookup(ct, CURTAIN_UNVEIL,
			    (union curtain_key){ .unveil = &uv1 });
			if (parent_item != NULL)
				uv->parent = parent_item->key.unveil;
			if (uv->name_len == 0)
				vput(vp);
		}
	}
	if (uv->parent != NULL && uv->depth == 0) {
		/*
		 * To avoid stack overflows in other functions, make sure there
		 * are no unveil parent chains longer than UNVEIL_MAX_DEPTH. If
		 * this unveil has a parent but its "depth" is still 0, then it
		 * must not have gone through this code yet.
		 */
		if (pending_depth >= UNVEIL_MAX_DEPTH)
			return (ELOOP);
		error = curtain_fixup_unveil_parent(ct, cr, uv->parent, pending_depth + 1);
		if (error != 0)
			return (error);
		if (uv->parent->depth >= UNVEIL_MAX_DEPTH)
			return (ELOOP);
		uv->depth = uv->parent->depth + 1;
	}
	return (0);
}

int
curtain_fixup_unveils_parents(struct curtain *ct, struct ucred *cr)
{
	struct curtain_item *item;
	int error = 0;
	for (item = ct->ct_slots; item < &ct->ct_slots[ct->ct_nslots]; item++)
		if (item->type == CURTAIN_UNVEIL) {
			error = curtain_fixup_unveil_parent(ct, cr, item->key.unveil, 0);
			if (error != 0)
				break;
		}
	return (error);
}

int
curtain_finish_unveils(struct curtain *ct, struct ucred *cr __unused)
{
	struct curtain_item *item;
	size_t count;
	for (item = ct->ct_slots, count = 0; item < &ct->ct_slots[ct->ct_nslots]; item++)
		if (item->type == CURTAIN_UNVEIL) {
			struct curtain_unveil *uv;
			count++;
			uv = item->key.unveil;
			if (uv->parent != NULL && !uperms_contains(uv->soft_uperms, UPERM_EXPOSE))
				uv->parent->hidden_children = true;
		}
	return (count > unveil_max_per_curtain ? E2BIG : 0);
}

static struct curtain_unveil *
curtain_lookup_unveil(struct curtain *ct, struct vnode *vp, const char *name, size_t name_len)
{
	struct curtain_item *item;
	struct curtain_unveil *uv;
	char ubuf[sizeof *uv + sizeof (const char *)];
	uv = (void *)ubuf;
	*uv = (struct curtain_unveil){ .vp = vp, .hash = vp->v_nchash };
	if ((uv->name_len = name_len) != 0) {
		uv->name_ext = true;
		*(const char **)(uv + 1) = name;
		uv->hash = fnv_32_buf(name, name_len, uv->hash);
	}
	item = curtain_lookup(ct, CURTAIN_UNVEIL, (union curtain_key){ .unveil = uv });
	return (item != NULL ? item->key.unveil : NULL);
}

static unveil_perms
default_uperms(struct unveil_tracker *track)
{
	struct curtain *ct;
	struct curtain_mode mode;
	if ((ct = track->ct) == NULL)
		return (UPERM_ALL);
	mode = curtain_resolve(ct, CURTAIN_ABILITY,
	    (union curtain_key){ .ability = curtain_type_fallback(CURTAIN_UNVEIL) });
	return (mode.soft == CURTAIN_ALLOW ? UPERM_ALL : UPERM_NONE);
}

static int
unveil_find_cover(struct ucred *cr, struct curtain *ct, struct vnode *dp,
    struct curtain_unveil **cover, unsigned *depth)
{
	int error, lkflags;
	lkflags = mount_dotdot_lkflags(dp->v_mount);
	error = vget(dp, LK_RETRY | lkflags);
	if (error != 0)
		return (error);
	while (true) {
		struct vnode *vp;
		*cover = curtain_lookup_unveil(ct, dp, NULL, 0);
		if (*cover != NULL)
			break;
		error = vnode_lookup_dotdot(dp, cr, &vp);
		if (error != 0 || vp == dp)
			break;
		dp = vp;
		if (++*depth == 0)
			*depth = -1;
	}
	vput(dp);
	return (error);
}


static bool
curtain_device_unveil_bypass(struct ucred *cr, struct cdev *dev)
{
	return (dev->si_cred != NULL && curtain_cred_visible(cr, dev->si_cred, BARRIER_DEVICE));
}

static unveil_perms
unveil_special_exemptions(struct ucred *cr, struct vnode *vp, unveil_perms uperms)
{
	unveil_perms add_uperms = UPERM_NONE;
	if (uperms_contains(uperms, UPERM_DEVFS)) {
		if (vp != NULL && vp->v_type == VCHR && vp->v_rdev != NULL &&
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
	if ((track = unveil_track_get(cr, false)) == NULL)
		return;
	unveil_track_roll(track, offset);
}

void
unveil_vnode_walk_annotate_file(struct ucred *cr, struct file *fp, struct vnode *vp)
{
	struct unveil_tracker *track;
	struct unveil_tracker_entry *entry;
	struct curtain *ct;
	fp->f_userial = (ct = curtain_from_cred(cr)) != NULL ? curtain_serial(ct) : 0;
	if (CRED_IN_VFS_VEILED_MODE(cr)) {
		if ((track = unveil_track_get(cr, false)) != NULL &&
		    (entry = unveil_track_find(track, vp)) != NULL)
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
	if (fp->f_vnode == NULL)
		return (0);
	track = unveil_track_get(cr, true);
	uperms = fp->f_uperms;
	if ((fp->f_userial != track->serial))
		uperms &= unveil_fflags_uperms(fp->f_vnode->v_type, fp->f_flag);
	unveil_track_roll(track, 1);
	unveil_track_fill(track, fp->f_vnode)->uperms = uperms;
	return (0);
}

int
unveil_vnode_walk_start(struct ucred *cr, struct vnode *dvp)
{
	struct curtain_unveil *cover;
	struct unveil_tracker *track;
	struct unveil_tracker_entry *entry;
	struct unveil_cache *cache;
	unsigned depth;
	int error;
	MPASS(dvp != NULL);
	track = unveil_track_get(cr, true);
	cache = curthread->td_proc->p_unveil_cache;
#ifdef CURTAIN_STATS
	counter_u64_add(unveil_stats_traversals, 1);
#endif
	depth = 0;
	cover = NULL;
	if (unveil_cover_cache_enabled && cache != NULL) {
		struct unveil_cache_entry *ent;
		ent = NULL;
		for (size_t i = 0; i < UNVEIL_CACHE_ENTRIES_COUNT; i++)
			if (cache->entries[i].vp == dvp)
				ent = &cache->entries[i];
		if (ent != NULL) {
			mtx_lock(&cache->mtx);
			if (ent->vp == dvp &&
			    ent->vp_nchash == dvp->v_nchash &&
			    ent->vp_hash == dvp->v_hash &&
			    cache->serial == track->serial) {
				cover = ent->cover;
				depth = -1;
#ifdef CURTAIN_STATS
				counter_u64_add(unveil_stats_ascents_cached, 1);
#endif
			}
			mtx_unlock(&cache->mtx);
		}
	}
	if (cover == NULL) {
		if (track->ct != NULL) {
			error = unveil_find_cover(cr, track->ct, dvp, &cover, &depth);
			if (error != 0)
				return (error);
		}
		if (depth > 0) {
#ifdef CURTAIN_STATS
			counter_u64_add(unveil_stats_ascents, 1);
			counter_u64_add(unveil_stats_ascent_total_depth, depth);
#endif
			if (unveil_cover_cache_enabled && cache != NULL && cover != NULL) {
				mtx_lock(&cache->mtx);
				if (cache->serial == track->serial) { /* shift */
					for (size_t i = UNVEIL_CACHE_ENTRIES_COUNT - 1; i >= 1; i--)
						cache->entries[i] = cache->entries[i - 1];
				} else { /* clear */
					for (size_t i = 1; i < UNVEIL_CACHE_ENTRIES_COUNT; i++)
						cache->entries[i] = (struct unveil_cache_entry){ 0 };
					cache->serial = track->serial;
				}
				cache->entries[0] = (struct unveil_cache_entry){
					.vp = dvp,
					.vp_nchash = dvp->v_nchash,
					.vp_hash = dvp->v_hash,
					.cover = cover,
				};
				mtx_unlock(&cache->mtx);
			}
		}
	}

	entry = unveil_track_fill(track, dvp);
	if (cover == NULL) {
		entry->uncharted = true;
		entry->uperms = default_uperms(track);
	} else if (depth != 0) {
		entry->uncharted = true;
		entry->uperms = uperms_inherit(cover->soft_uperms);
	} else
		entry->uperms = cover->soft_uperms;
	return (0);
}

void
unveil_vnode_walk_backtrack(struct ucred *cr, struct vnode *from_vp, struct vnode *to_vp)
{
	struct unveil_tracker *track;
	struct unveil_tracker_entry *entry;
	struct curtain_unveil *uv;
	unveil_perms uperms;
	bool uncharted;
	if ((track = unveil_track_get(cr, false)) == NULL ||
	    (entry = unveil_track_pick(track, from_vp)) == NULL)
		return;

	uncharted = false;
	uperms = UPERM_NONE;
	if (track->ct != NULL && (uv = curtain_lookup_unveil(track->ct, to_vp, NULL, 0)) != NULL)
		uperms = uv->soft_uperms;
	else if ((uncharted = entry->uncharted))
		uperms = entry->uperms;

	entry = unveil_track_fill(track, to_vp);
	entry->uperms = uperms;
	entry->uncharted = uncharted;
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
	struct unveil_tracker_entry *entry;
	struct curtain_unveil *uv;
	unveil_perms uperms;
	bool uncharted, parent_exposed;
	if ((track = unveil_track_get(cr, false)) == NULL)
		return;
	/*
	 * vfs_lookup.c's lookup() will sometimes call this function with a
	 * fake intermediate vnode (vp_crossmp) as dvp.  Conveniently, it only
	 * does so when vp is a directory and we won't need dvp in this case.
	 *
	 * The check that dvp is the current tracker entry's vnode is mostly
	 * intended for bug catching and can just be skipped when dvp is fake.
	 */
	if (dvp->v_type == VNON)
		entry = unveil_track_peek(track);
	else if ((entry = unveil_track_pick(track, dvp)) == NULL)
		return;
	parent_exposed = entry->uperms & UPERM_EXPOSE;

	uv = NULL;
	if (track->ct != NULL) {
		if (vp != NULL && vp->v_type == VDIR)
			uv = curtain_lookup_unveil(track->ct, vp, NULL, 0);
		else if ((cnp->cn_flags & ISDOTDOT) == 0 && cnp->cn_namelen != 0)
			uv = curtain_lookup_unveil(track->ct, dvp,
			    cnp->cn_nameptr, cnp->cn_namelen);
	}

	uncharted = false;
	uperms = UPERM_NONE;
	if (uv != NULL) {
		uperms = uv->soft_uperms;
	} else if ((cnp->cn_flags & ISDOTDOT) != 0) {
		if ((uncharted = entry->uncharted))
			uperms = entry->uperms;
	} else {
		uncharted = true;
		uperms = uperms_inherit(entry->uperms);
	}

	if (vp != NULL) {
		uperms = unveil_special_exemptions(cr, vp, uperms);
		entry = unveil_track_fill(track, vp);
		entry->uperms = uperms;
		entry->uncharted = uncharted;
	} else {
		MPASS(entry->vp == dvp);
		entry->create_pending = true;
		entry->pending_uperms = uperms;
	}
	if (parent_exposed && (cnp->cn_flags & ISLASTCN) != 0 && cnp->cn_nameiop == CREATE)
		entry->exposed_create = true;
}

void
unveil_vnode_walk_replace(struct ucred *cr,
    struct vnode *from_vp, struct vnode *to_vp)
{
	struct unveil_tracker *track;
	struct unveil_tracker_entry *entry;
	if ((track = unveil_track_get(cr, false)) == NULL ||
	    (entry = unveil_track_pick(track, from_vp)) == NULL)
		return;
	unveil_perms uperms = entry->uperms;
	unveil_track_fill(track, to_vp)->uperms = uperms;
}

void
unveil_vnode_walk_created(struct ucred *cr, struct vnode *dvp, struct vnode *vp)
{
	struct unveil_tracker *track;
	struct unveil_tracker_entry *entry;
	if ((track = unveil_track_get(cr, false)) == NULL ||
	    (entry = unveil_track_pick(track, dvp)) == NULL ||
	    !entry->create_pending)
		return;
	unveil_perms uperms = entry->pending_uperms;
	unveil_track_fill(track, vp)->uperms = uperms;
}

int
unveil_vnode_walk_finish(struct ucred *cr, struct vnode *dvp, struct vnode *vp)
{
	struct unveil_tracker *track;
	struct unveil_tracker_entry *entry;
	unveil_perms uperms;
	if ((track = unveil_track_get(cr, false)) == NULL)
		return (0);
	if (vp != NULL) {
		if ((entry = unveil_track_pick(track, vp)) == NULL)
			return (ENOENT);
		uperms = entry->uperms;
	} else {
		if ((entry = unveil_track_pick(track, dvp)) == NULL)
			return (ENOENT);
		uperms = entry->pending_uperms;
	}
	/*
	 * Many namei() callers inspect the looked up vnodes before calling the
	 * MAC handlers and may return error numbers to the user that reveal
	 * the existence of files.
	 *
	 * Thus, make namei() fail early when the the looked up vnode isn't
	 * supposed to be visible and doesn't have permissions to do anything
	 * useful with it.
	 *
	 * Some cases that this deals with:
	 *
	 * - access(2)/eaccess(2)/faccessat(2) with F_OK.
	 * - open(2)/openat(2) with O_PATH, O_CREAT|O_EXCL, others...
	 * - readlink(2) on symlinks unveiled with just UPERM_TRAVERSE.
	 * - __realpathat(2).
	 */
	if (uperms_overlaps(uperms, uperms_resolvable))
		return (0);
	if (uperms_contains(uperms, UPERM_TMPDIR_CHILD) && (vp == NULL || vp->v_type == VREG))
		return (0);
	return (entry->exposed_create ? EACCES : ENOENT);
}

int
unveil_vnode_walk_fixup_errno(struct ucred *cr, int error)
{
	struct unveil_tracker *track;
	struct unveil_tracker_entry *entry;
	unveil_perms uperms;
	if ((track = unveil_track_get(cr, false)) == NULL)
		return (error);
	entry = unveil_track_peek(track);
	uperms = entry->create_pending ? entry->pending_uperms : entry->uperms;
	/*
	 * Try to prevent using errnos (like EISDIR/ENOTDIR/etc) to detect the
	 * existence (and type) of files in unexposed traversable directories.
	 *
	 * XXX It is still possible to infer the existence of directories by
	 * testing if ".." components allow to escape to an exposed directory.
	 *
	 * Note that UPERM_DEVFS gives an inheritable UPERM_TRAVERSE on a whole
	 * directory hierarchy.
	 */
	if (uperms_contains(uperms, UPERM_EXPOSE))
		return (error);
	return (entry->exposed_create ? EACCES : ENOENT);
}

bool
unveil_vnode_walk_dirent_visible(struct ucred *cr, struct vnode *dvp, struct dirent *dp)
{
	struct unveil_tracker *track;
	struct unveil_tracker_entry *entry;
	struct curtain_unveil *uv;
	struct vnode *vp;
	struct mount *mp;
	struct componentname cn;
	unveil_perms uperms;
	int error;

	if ((track = unveil_track_get(cr, false)) == NULL ||
	    (entry = unveil_track_find(track, dvp)) == NULL)
		return (false);

	uperms = entry->uperms;
	if (!uperms_contains(uperms, UPERM_LIST))
		return (false);

	if (dp == NULL) { /* request to check if all children are visible */
		if (!uperms_contains(uperms, UPERM_BROWSE))
			return (false); /* children not visible by default */
		uv = track->ct != NULL ? curtain_lookup_unveil(track->ct, dvp, NULL, 0) : NULL;
		return (uv == NULL || !uv->hidden_children);
	}

	if ((dp->d_namlen == 2 && dp->d_name[0] == '.' && dp->d_name[1] == '.') ||
	    (dp->d_namlen == 1 && dp->d_name[0] == '.'))
		return (true);

	if (track->ct != NULL)
		switch (dp->d_type) {
		case DT_UNKNOWN:
#ifdef CURTAIN_STATS
			counter_u64_add(unveil_stats_dirent_unknowns, 1);
#endif
			/* FALLTHROUGH */
		case DT_DIR:
#ifdef CURTAIN_STATS
			counter_u64_add(unveil_stats_dirent_vnode_lookups, 1);
#endif
			cn = (struct componentname){
				.cn_nameiop = LOOKUP,
				.cn_flags = ISLASTCN,
				.cn_lkflags = LK_SHARED,
				.cn_cred = cr,
				.cn_nameptr = dp->d_name,
				.cn_namelen = dp->d_namlen,
			};
			error = VOP_LOOKUP(dvp, &vp, &cn);
			if (error != 0) {
#ifdef CURTAIN_STATS
				counter_u64_add(unveil_stats_dirent_vnode_errors, 1);
#endif
				return (false);
			}
			while (vp->v_type == VDIR && (mp = vp->v_mountedhere) != NULL) {
				if (vfs_busy(mp, 0))
					continue;
				if (vp != dvp)
					vput(vp);
				else
					vrele(vp);
				error = VFS_ROOT(mp, LK_SHARED, &vp);
				vfs_unbusy(mp);
				if (error != 0)
					return (false);
			}
			if (vp != dvp)
				VOP_UNLOCK(vp);
			if (vp->v_type == VDIR) {
				uv = curtain_lookup_unveil(track->ct, vp, NULL, 0);
				vrele(vp);
				break;
			} else
				vrele(vp);
			/* FALLTHROUGH */
		default:
#ifdef CURTAIN_STATS
			counter_u64_add(unveil_stats_dirent_name_lookups, 1);
#endif
			uv = curtain_lookup_unveil(track->ct, dvp, dp->d_name, dp->d_namlen);
			break;
		}
	else
		uv = NULL;

	uperms = uv != NULL ? uv->soft_uperms : uperms_inherit(uperms);
	return (uperms_contains(uperms, UPERM_EXPOSE));
}


struct unveil_cache *
unveil_proc_get_cache(struct proc *p, bool create)
{
	struct unveil_cache *cache;
	if ((cache = (void *)atomic_load_acq_ptr((void *)&p->p_unveil_cache)) == NULL && create) {
		struct unveil_cache *new_cache;
		new_cache = malloc(sizeof *new_cache, M_UNVEIL_CACHE, M_WAITOK);
		unveil_cache_init(new_cache);
		PROC_LOCK(p);
		if ((cache = p->p_unveil_cache) == NULL)
			p->p_unveil_cache = cache = new_cache;
		PROC_UNLOCK(p);
		if (cache != new_cache) {
			unveil_cache_free(new_cache);
			free(new_cache, M_UNVEIL_CACHE);
		}
	}
	return (cache);
}

void
unveil_proc_drop_cache(struct proc *p)
{
	struct unveil_cache *cache;
	if ((cache = p->p_unveil_cache) != NULL) {
		unveil_cache_free(cache);
		free(cache, M_UNVEIL_CACHE);
		p->p_unveil_cache = NULL;
	}
}


static void
unveil_proc_ctor(void *arg __unused, struct proc *p)
{
	p->p_unveil_cache = NULL;
}

static void
unveil_proc_dtor(void *arg __unused, struct proc *p)
{
	unveil_proc_drop_cache(p);
}

static void
unveil_proc_fork(void *arg __unused, struct proc *parent, struct proc *child, int flags)
{
	struct unveil_cache *src, *dst;
	if ((src = parent->p_unveil_cache) != NULL) {
		dst = unveil_proc_get_cache(child, true);
		mtx_lock(&src->mtx);
		unveil_cache_copy(dst, src);
		mtx_unlock(&src->mtx);
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
	if (td->td_unveil_tracker != NULL) {
		free(td->td_unveil_tracker, M_UNVEIL_TRACK);
		td->td_unveil_tracker = NULL;
	}
}

static eventhandler_tag unveil_proc_ctor_tag,
                        unveil_proc_dtor_tag,
                        unveil_proc_fork_tag;
static eventhandler_tag unveil_thread_ctor_tag,
                        unveil_thread_dtor_tag;

static void
unveil_sysinit(void *arg __unused)
{
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
}

static void
unveil_sysuninit(void *arg __unused)
{
	EVENTHANDLER_DEREGISTER(process_ctor, unveil_proc_ctor_tag);
	EVENTHANDLER_DEREGISTER(process_dtor, unveil_proc_dtor_tag);
	EVENTHANDLER_DEREGISTER(process_fork, unveil_proc_fork_tag);
	EVENTHANDLER_DEREGISTER(thread_ctor, unveil_thread_ctor_tag);
	EVENTHANDLER_DEREGISTER(thread_dtor, unveil_thread_dtor_tag);
}

SYSINIT(unveil_sysinit, SI_SUB_KLD, SI_ORDER_ANY, unveil_sysinit, NULL);
SYSUNINIT(unveil_sysinit, SI_SUB_KLD, SI_ORDER_ANY, unveil_sysuninit, NULL);
