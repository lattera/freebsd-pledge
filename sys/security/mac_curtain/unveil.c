#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

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
#include <sys/mount.h>
#include <sys/dirent.h>
#include <sys/sysctl.h>
#include <sys/mutex.h>
#include <sys/eventhandler.h>
#include <sys/conf.h>
#include <sys/sysent.h>
#include <sys/syscall.h>
#include <sys/fnv_hash.h>
#include <sys/unveil.h>
#include <sys/curtain.h>

static MALLOC_DEFINE(M_UNVEIL_CACHE, "unveil cache", "mac_curtain per-procecess unveil caches");
static MALLOC_DEFINE(M_UNVEIL_TRACK, "unveil track", "mac_curtain per-thread unveil trackers");

static bool __read_mostly unveil_cover_cache_enabled = true;
static unsigned int __read_mostly unveil_max_per_curtain = 128;

SYSCTL_BOOL(_security_curtain, OID_AUTO, unveil_cover_cache,
    CTLFLAG_RW, &unveil_cover_cache_enabled, 0, "");

SYSCTL_UINT(_security_curtain, OID_AUTO, max_unveils_per_curtain,
    CTLFLAG_RW, &unveil_max_per_curtain, 0, "Maximum unveils allowed per process");

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
STATNODE_COUNTER(dirent_dirs, unveil_stats_dirent_dirs, "");
STATNODE_COUNTER(dirent_nondirs, unveil_stats_dirent_nondirs, "");

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
unveil_track_init(struct unveil_tracker *track, struct curtain *ct)
{
	*track = (struct unveil_tracker){
		.ct = ct,
		.serial = ct ? curtain_serial(ct) : 0,
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
	if ((track = curthread->td_unveil_tracker)) {
		ct = curtain_from_cred(cr);
		if (__predict_false(track->serial != (ct ? curtain_serial(ct) : 0)))
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


static inline int
mount_dotdot_lkflags(struct mount *mp)
{
	return (mp && (mp->mnt_kern_flag & (MNTK_LOOKUP_SHARED | MNTK_LOOKUP_EXCL_DOTDOT)) ==
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
		if (!(dp->v_vflag & VV_ROOT))
			break;
		if (!dp->v_mount || !(vp = dp->v_mount->mnt_vnodecovered))
			break;
		vref(vp);
		vput(dp);
		vn_lock(vp, LK_RETRY | lkflags);
		dp = vp;
	} while (true);

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
		if (item->type == CURTAINTYP_UNVEIL)
			if (item->key.unveil->vp->v_mount == mp)
				uperms |= item->key.unveil->soft_uperms;
	return (uperms_expand(uperms));
}

#define UNVEIL_MAX_DEPTH 32

static int
unveil_fixup_depth(struct curtain_unveil *unv, size_t depth)
{
	int error;
	if (depth > UNVEIL_MAX_DEPTH)
		return (ELOOP);
	if (unv->parent && unv->depth == 0) {
		error = unveil_fixup_depth(unv->parent, depth + 1);
		if (error)
			return (error);
		if (unv->parent->depth >= UNVEIL_MAX_DEPTH)
			return (ELOOP);
		unv->depth = unv->parent->depth + 1;
	}
	return (0);
}

int
curtain_fixup_unveils_pre_mask(struct curtain *ct, struct ucred *cr)
{
	struct curtain_item *item;
	for (item = ct->ct_slots; item < &ct->ct_slots[ct->ct_nslots]; item++)
		if (item->type == CURTAINTYP_UNVEIL) {
			struct curtain_item *parent_item;
			struct curtain_unveil uv1, *uv;
			struct vnode *vp;
			int error;
			uv = item->key.unveil;
			if (uv->parent)
				continue;
			vp = uv->vp;
			if (vp->v_type != VDIR)
				continue;
			if (!uv->name_len) {
				vget(vp, LK_RETRY | mount_dotdot_lkflags(vp->v_mount));
				error = vnode_lookup_dotdot(vp, cr, &vp);
				if (error || vp == uv->vp) {
					vput(vp);
					continue;
				}
			}
			uv1 = (struct curtain_unveil){
				.vp = vp,
				    .hash = vp->v_nchash,
			};
			parent_item = curtain_lookup(ct, CURTAINTYP_UNVEIL,
			    (union curtain_key){ .unveil = &uv1 });
			if (parent_item)
				uv->parent = parent_item->key.unveil;
			if (!uv->name_len)
				vput(vp);
		}
	for (item = ct->ct_slots; item < &ct->ct_slots[ct->ct_nslots]; item++)
		if (item->type == CURTAINTYP_UNVEIL) {
			int error;
			error = unveil_fixup_depth(item->key.unveil, 0);
			if (error)
				return (error);
		}
	return (0);
}

int
curtain_fixup_unveils_post_mask(struct curtain *ct, struct ucred *cr __unused)
{
	struct curtain_item *item;
	size_t count;
	for (item = ct->ct_slots, count = 0; item < &ct->ct_slots[ct->ct_nslots]; item++)
		if (item->type == CURTAINTYP_UNVEIL) {
			struct curtain_unveil *uv;
			count++;
			uv = item->key.unveil;
			if (uv->parent && !(uv->soft_uperms & UPERM_EXPOSE))
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
	*uv = (struct curtain_unveil){
		.vp = vp,
		.hash = vp->v_nchash,
	};
	if ((uv->name_len = name_len) != 0) {
		uv->name_ext = true;
		*(const char **)(uv + 1) = name;
		uv->hash = fnv_32_buf(name, name_len, uv->hash);
	}
	item = curtain_lookup(ct, CURTAINTYP_UNVEIL, (union curtain_key){ .unveil = uv });
	return (item ? item->key.unveil : NULL);
}

static unveil_perms
default_uperms(struct unveil_tracker *track)
{
	struct curtain *ct;
	struct curtain_mode mode;
	if (!(ct = track->ct))
		return (UPERM_ALL);
	mode = curtain_resolve(ct, CURTAINTYP_ABILITY,
	    (union curtain_key){ .ability = curtain_type_fallback[CURTAINTYP_UNVEIL] });
	return (mode.soft == CURTAINACT_ALLOW ? UPERM_ALL : UPERM_NONE);
}

static int
unveil_find_cover(struct ucred *cr, struct curtain *ct, struct vnode *dp,
    struct curtain_unveil **cover, unsigned *depth)
{
	int error, lkflags;
	lkflags = mount_dotdot_lkflags(dp->v_mount);
	error = vget(dp, LK_RETRY | lkflags);
	if (error)
		return (error);
	while (true) {
		struct vnode *vp;
		*cover = curtain_lookup_unveil(ct, dp, NULL, 0);
		if (*cover)
			break;
		error = vnode_lookup_dotdot(dp, cr, &vp);
		if (error || vp == dp)
			break;
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
	struct curtain *ct;
	fp->f_uldgen = (ct = curtain_from_cred(cr)) ? curtain_serial(ct) : 0;
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
	struct curtain_unveil *cover;
	struct unveil_tracker *track;
	struct unveil_cache *cache;
	int error;
	unsigned depth;
	MPASS(dvp);
	track = unveil_track_get(cr, true);
	cache = curthread->td_proc->p_unveil_cache;
#ifdef CURTAIN_STATS
	counter_u64_add(unveil_stats_traversals, 1);
#endif
	depth = 0;
	cover = NULL;
	if (unveil_cover_cache_enabled && cache) {
		struct unveil_cache_entry *ent;
		ent = NULL;
		for (size_t i = 0; i < UNVEIL_CACHE_ENTRIES_COUNT; i++)
			if (cache->entries[i].vp == dvp)
				ent = &cache->entries[i];
		if (ent) {
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
	if (!cover) {
		if (track->ct) {
			error = unveil_find_cover(cr, track->ct, dvp, &cover, &depth);
			if (error)
				return (error);
		}
		if (depth > 0) {
#ifdef CURTAIN_STATS
			counter_u64_add(unveil_stats_ascents, 1);
			counter_u64_add(unveil_stats_ascent_total_depth, depth);
#endif
			if (unveil_cover_cache_enabled && cache && cover) {
				struct unveil_cache_entry *ent;
				mtx_lock(&cache->mtx);
				ent = cache->entries;
				memcpy(ent, &ent[1], (UNVEIL_CACHE_ENTRIES_COUNT - 1) * sizeof *ent);
				ent->cover = cover;
				ent->vp = dvp;
				ent->vp_nchash = dvp->v_nchash;
				ent->vp_hash = dvp->v_hash;
				cache->serial = track->serial;
				mtx_unlock(&cache->mtx);
			}
		}
	}
	track->uncharted = true;
	track->uperms = UPERM_NONE;
	if (cover) {
		track->uperms = cover->soft_uperms;
		if (depth)
			track->uperms = uperms_inherit(track->uperms);
		else
			track->uncharted = false;
	} else {
		track->uperms = default_uperms(track);
	}

	unveil_track_fill(track, dvp)->uperms = track->uperms;
	return (0);
}

void
unveil_vnode_walk_backtrack(struct ucred *cr, struct vnode *dvp)
{
	struct unveil_tracker *track;
	struct curtain_unveil *uv;
	if (!(track = unveil_track_get(cr, false)))
		return;
	if (!track->uncharted)
		track->uperms = UPERM_NONE;

	if (track->ct && (uv = curtain_lookup_unveil(track->ct, dvp, NULL, 0))) {
		track->uncharted = false;
		track->uperms = uv->soft_uperms;
	} else {
		track->uncharted = true;
		track->uperms = uperms_inherit(track->uperms);
	}

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
	struct curtain_unveil *uv = NULL;
	char *name = NULL;
	size_t name_len = 0;
	if (!(track = unveil_track_get(cr, false)))
		return;
	if (cnp->cn_flags & ISDOTDOT) {
		if (!track->uncharted)
			track->uperms = UPERM_NONE;
	} else {
		/*
		 * When resolving a path that ends with slashes, the last path
		 * component may have a zero-length name.
		 */
		if ((name_len = cnp->cn_namelen))
			name = cnp->cn_nameptr;
	}

	if (track->ct) {
		if (vp && vp->v_type == VDIR)
			uv = curtain_lookup_unveil(track->ct, vp, NULL, 0);
		else if (name)
			uv = curtain_lookup_unveil(track->ct, dvp, name, name_len);
	}

	if (uv) {
		track->uncharted = false;
		track->uperms = uv->soft_uperms;
	} else {
		track->uncharted = true;
		track->uperms = uperms_inherit(track->uperms);
	}

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
	struct curtain_unveil *uv;
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
		uv = track->ct ? curtain_lookup_unveil(track->ct, dvp, NULL, 0) : NULL;
		return (!(uv && uv->hidden_children));
	}

	if ((dp->d_namlen == 2 && dp->d_name[0] == '.' && dp->d_name[1] == '.') ||
	    (dp->d_namlen == 1 && dp->d_name[0] == '.'))
		return (true);

	if (!track->ct) {
		uv = NULL;

	} else if (dp->d_type == DT_DIR) {
#ifdef CURTAIN_STATS
		counter_u64_add(unveil_stats_dirent_dirs, 1);
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

		uv = curtain_lookup_unveil(track->ct, vp, NULL, 0);

		if (vp != dvp)
			vput(vp);
		else
			vrele(vp);

	} else {
#ifdef CURTAIN_STATS
		counter_u64_add(unveil_stats_dirent_nondirs, 1);
#endif
		uv = curtain_lookup_unveil(track->ct, dvp, dp->d_name, dp->d_namlen);
	}

	if (uv)
		uperms = uv->soft_uperms;
	else
		uperms = uperms_inherit(uperms);
	return (uperms & UPERM_EXPOSE);
}


struct unveil_cache *
unveil_proc_get_cache(struct proc *p, bool create)
{
	struct unveil_cache *cache;
	if (!(cache = (void *)atomic_load_acq_ptr((void *)&p->p_unveil_cache)) && create) {
		struct unveil_cache *new_cache;
		new_cache = malloc(sizeof *new_cache, M_UNVEIL_CACHE, M_WAITOK);
		unveil_cache_init(new_cache);
		PROC_LOCK(p);
		if (!(cache = p->p_unveil_cache))
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
	if ((cache = p->p_unveil_cache)) {
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
	if ((src = parent->p_unveil_cache)) {
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
	if (td->td_unveil_tracker) {
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
