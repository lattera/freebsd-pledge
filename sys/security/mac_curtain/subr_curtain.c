#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/refcount.h>
#include <sys/ucred.h>
#include <sys/counter.h>
#include <sys/rwlock.h>
#include <sys/vnode.h>
#include <sys/sysfil.h>
#include <sys/conf.h>

#include <security/mac_curtain/curtain_int.h>

static MALLOC_DEFINE(M_CURTAIN, "curtain", "mac_curtain curtains");
static MALLOC_DEFINE(M_BARRIER, "curtain barrier", "mac_curtain barriers");
static MALLOC_DEFINE(M_CURTAIN_UNVEIL, "curtain unveil", "mac_curtain unveils");

#define STATNODE_COUNTER(name, varname, descr)				\
	static COUNTER_U64_DEFINE_EARLY(varname);			\
	SYSCTL_COUNTER_U64(_security_curtain_stats, OID_AUTO, name,	\
	    CTLFLAG_RD, &varname, descr);

#ifdef CURTAIN_STATS_LOOKUP

STATNODE_COUNTER(lookups, curtain_stats_lookups, "");
STATNODE_COUNTER(probes, curtain_stats_probes, "");
STATNODE_COUNTER(long_lookups, curtain_stats_long_lookups, "");
STATNODE_COUNTER(long_probes, curtain_stats_long_probes, "");

#endif

static inline void
mode_set(struct curtain_mode *mode, enum curtain_action act)
{
	mode->soft = mode->hard = act;
}

static inline void
mode_mask(struct curtain_mode *dst, const struct curtain_mode src)
{
	dst->hard = MAX(src.hard,  dst->hard);
	dst->soft = MAX(dst->soft, dst->hard);
}

static inline void
mode_harden(struct curtain_mode *mode)
{
	mode->hard = mode->soft = MAX(mode->soft, mode->hard);
}

static inline bool
mode_equivalent(struct curtain_mode m0, struct curtain_mode m1)
{
	return (m0.soft == m1.soft && m0.hard == m1.hard);
}

static inline bool
mode_restricted(struct curtain_mode mode)
{
	return (mode.soft != CURTAIN_ALLOW || mode.hard != CURTAIN_ALLOW);
}


static volatile uint64_t barrier_serial = 1;

static void
barrier_init(struct barrier *br)
{
	*br = (struct barrier){
		.br_head = { .cth_barrier = br },
		.br_ref = 1,
		.br_parent = NULL,
		.br_children = LIST_HEAD_INITIALIZER(br.br_children),
		.br_nchildren = 0,
	};
	br->br_serial = atomic_fetchadd_64(&barrier_serial, 1);
}

static inline void
barrier_invariants(const struct barrier *br)
{
	MPASS(br);
	MPASS(br->br_head.cth_barrier == br);
	MPASS(br->br_parent != br);
	MPASS(br->br_ref > 0);
	MPASS(br->br_serial > 0);
}

static void
barrier_invariants_sync(const struct barrier *br)
{
	barrier_invariants(br);
	MPASS(LIST_EMPTY(&br->br_children) == (br->br_nchildren == 0));
}

static struct barrier *
barrier_alloc(void)
{
	struct barrier *br;
	br = malloc(sizeof *br, M_BARRIER, M_WAITOK);
	return (br);
}

static struct barrier *
barrier_make()
{
	struct barrier *br;
	br = barrier_alloc();
	barrier_init(br);
	barrier_invariants_sync(br);
	return (br);
}

static struct rwlock __exclusive_cache_line barrier_tree_lock;

struct barrier *
barrier_hold(struct barrier *br)
{
	refcount_acquire(&br->br_ref);
	return (br);
}

void
barrier_bump(struct barrier *br)
{
	br->br_serial = atomic_fetchadd_64(&barrier_serial, 1);
}

static void
barrier_collapse(const struct barrier *src, struct barrier *dst)
{
	dst->br_mode.soft |= dst->br_mode.hard |= src->br_mode.hard;
}

static void
barrier_unlink_locked(struct barrier *victim)
{
	struct barrier *child;
	MPASS(LIST_EMPTY(&victim->br_children) == (victim->br_nchildren == 0));
	if (victim->br_parent) {
		barrier_invariants_sync(victim->br_parent);
		LIST_REMOVE(victim, br_sibling);
		MPASS(victim->br_parent->br_nchildren != 0);
		victim->br_parent->br_nchildren--;
		barrier_invariants_sync(victim->br_parent);
	}
	while (!LIST_EMPTY(&victim->br_children)) {
		child = LIST_FIRST(&victim->br_children);
		MPASS(child->br_parent == victim);
		barrier_invariants_sync(child);
		MPASS(victim->br_nchildren != 0);
		victim->br_nchildren--;
		LIST_REMOVE(child, br_sibling);
		if ((child->br_parent = victim->br_parent)) {
			LIST_INSERT_HEAD(&child->br_parent->br_children, child, br_sibling);
			child->br_parent->br_nchildren++;
			MPASS(child->br_parent->br_nchildren != 0);
		}
		/*
		 * TODO: This may cutoff child processes from objects they had
		 * access to before a parent process died.  It would be better
		 * to keep some intermediate barriers around (and "collapse"
		 * them when appropriate to prevent them from building up).
		 */
		barrier_collapse(victim, child);
		barrier_invariants_sync(child);
	}
	MPASS(victim->br_nchildren == 0);
	victim->br_parent = NULL;
}

void
barrier_link(struct barrier *child, struct barrier *parent)
{
	rw_wlock(&barrier_tree_lock);
	if (child->br_parent)
		barrier_unlink_locked(child);
	barrier_invariants_sync(child);
#ifdef INVARIANTS
	for (const struct barrier *iter = parent; iter; iter = iter->br_parent)
		MPASS(iter != child);
#endif
	if ((child->br_parent = parent)) {
		barrier_invariants_sync(parent);
		parent->br_nchildren++;
		if (parent->br_nchildren == 0)
			panic("barrier nchildren overflow");
		LIST_INSERT_HEAD(&parent->br_children, child, br_sibling);
		barrier_invariants_sync(parent);
	} else {
#ifdef INVARIANTS
		memset(&child->br_sibling, -1, sizeof child->br_sibling);
#endif
	}
	barrier_invariants_sync(child);
	rw_wunlock(&barrier_tree_lock);
}

void
barrier_unlink(struct barrier *victim)
{
	rw_wlock(&barrier_tree_lock);
	barrier_unlink_locked(victim);
	rw_wunlock(&barrier_tree_lock);
}

void
barrier_free(struct barrier *br)
{
	barrier_invariants(br);
	if (refcount_release(&br->br_ref)) {
		barrier_unlink(br);
		free(br, M_BARRIER);
	}
}

static struct barrier *
barrier_cross_locked(struct barrier *br, barrier_bits bar)
{
	if (br && !(br->br_mode.soft & bar))
		do br = br->br_parent;
		while (br && !(br->br_mode.hard & bar));
	return (br);
}

struct barrier *
barrier_cross(struct barrier *br, barrier_bits bar)
{
	rw_rlock(&barrier_tree_lock);
	br = barrier_cross_locked(br, bar);
	rw_runlock(&barrier_tree_lock);
	return (br);
}

bool
barrier_visible(struct barrier *subject, const struct barrier *target, barrier_bits bar)
{
	/*
	 * NOTE: One or both of subject and target may be NULL (indicating
	 * credentials with no curtain restrictions).
	 */
	if (subject)
		barrier_invariants(subject);
	if (target)
		barrier_invariants(target);
	if (subject == target) /* fast path */
		return (true);
	rw_rlock(&barrier_tree_lock);
	subject = barrier_cross_locked(subject, bar);
	while (target && subject != target)
		target = target->br_parent;
	rw_runlock(&barrier_tree_lock);
	return (subject == target);

}

static void
barrier_copy(struct barrier *dst, const struct barrier *src)
{
	memcpy(dst, src, sizeof *src);
	dst->br_head.cth_barrier = dst;
	dst->br_ref = 1;
	dst->br_parent = NULL;
	dst->br_nchildren = 0;
	LIST_INIT(&dst->br_children);
#ifdef INVARIANTS
	memset(&dst->br_sibling, -1, sizeof dst->br_sibling);
#endif
	barrier_invariants_sync(dst);
}

struct barrier *
barrier_dup(const struct barrier *src)
{
	struct barrier *dst;
	barrier_invariants(src);
	dst = barrier_alloc();
	barrier_copy(dst, src);
	return (dst);
}


static void
curtain_init(struct curtain *ct, size_t nslots)
{
	if (nslots != (curtain_index)nslots)
		panic("invalid curtain nslots %zu", nslots);
	*ct = (struct curtain){
		.ct_head = { .cth_barrier = NULL },
#ifdef INVARIANTS
		.ct_magic = CURTAIN_MAGIC,
#endif
		.ct_ref = 1,
		.ct_cached = { .valid = false },
		.ct_nitems = 0,
		.ct_nslots = nslots,
		.ct_modulo = nslots,
		.ct_cellar = nslots,
	};
	for (curtain_index i = 0; i < nslots; i++)
		ct->ct_slots[i].type = 0;
}

void
curtain_invariants(const struct curtain *ct)
{
	MPASS(ct);
	MPASS(ct->ct_magic == CURTAIN_MAGIC);
	MPASS(ct->ct_ref > 0);
	MPASS(ct->ct_nslots >= ct->ct_nitems);
	MPASS(ct->ct_nslots >= ct->ct_modulo);
	MPASS(ct->ct_nslots >= ct->ct_cellar);
	barrier_invariants(CURTAIN_BARRIER(ct));
	MPASS(ct->ct_on_exec != ct);
	if (ct->ct_on_exec)
		curtain_invariants(ct->ct_on_exec);
}

void
curtain_invariants_sync(const struct curtain *ct)
{
	curtain_invariants(ct);
	barrier_invariants_sync(CURTAIN_BARRIER(ct));
	if (ct->ct_on_exec)
		curtain_invariants_sync(ct->ct_on_exec);
}

static struct curtain *
curtain_alloc(size_t nslots)
{
	struct curtain *ct;
	ct = malloc(sizeof *ct + nslots * sizeof *ct->ct_slots, M_CURTAIN, M_WAITOK);
	return (ct);
}

static struct curtain *
curtain_make_without_barrier(size_t nitems)
{
	size_t nslots;
	struct curtain *ct;
	nslots = nitems + nitems/8;
	ct = curtain_alloc(nslots);
	curtain_init(ct, nslots);
	ct->ct_modulo = nitems + nitems/16;
	return (ct);
}

struct curtain *
curtain_make(size_t nitems)
{
	struct curtain *ct;
	ct = curtain_make_without_barrier(nitems);
	ct->ct_head.cth_barrier = barrier_make();
	curtain_invariants_sync(ct);
	return (ct);
}

struct curtain *
curtain_hold(struct curtain *ct)
{
	refcount_acquire(&ct->ct_ref);
	return (ct);
}

static void curtain_key_free(enum curtain_type, union curtain_key);

static void
curtain_free_1(struct curtain *ct)
{
	struct curtain_item *item;
	for (item = ct->ct_slots; item < &ct->ct_slots[ct->ct_nslots]; item++)
		if (item->type != 0)
			curtain_key_free(item->type, item->key);
	if (ct->ct_on_exec)
		curtain_free(ct->ct_on_exec);
	if (CURTAIN_BARRIER(ct))
		barrier_free(CURTAIN_BARRIER(ct));
	free(ct, M_CURTAIN);
}

void
curtain_free(struct curtain *ct)
{
	curtain_invariants(ct);
	if (refcount_release(&ct->ct_ref))
		curtain_free_1(ct);
}

uint64_t
curtain_serial(const struct curtain *ct)
{
	curtain_invariants(ct);
	return (CURTAIN_BARRIER(ct)->br_serial);
}

static inline void
curtain_dirty(struct curtain *ct)
{
	ct->ct_cached.valid = false;
}


#define CURTAIN_KEY_INVALID_TYPE_CASES	\
	case CURTAIN_ABILITY:

static unsigned
curtain_key_hash(enum curtain_type type, union curtain_key key)
{
	switch (type) {
	CURTAIN_KEY_INVALID_TYPE_CASES
		break;
	case CURTAIN_IOCTL:
		return (key.ioctl ^ key.ioctl >> 5);
	case CURTAIN_SOCKAF:
		return (key.sockaf);
	case CURTAIN_SOCKLVL:
		return (key.socklvl);
	case CURTAIN_GETSOCKOPT:
	case CURTAIN_SETSOCKOPT:
	case CURTAIN_SOCKOPT:
		return (key.sockopt.level ^ key.sockopt.optname);
	case CURTAIN_PRIV:
		return (key.priv);
	case CURTAIN_SYSCTL:
		return ((uintptr_t)key.sysctl >> 5);
	case CURTAIN_FIBNUM:
		return (key.fibnum);
	case CURTAIN_UNVEIL:
		return (key.unveil->hash);
	}
	MPASS(0);
	return (-1);
}

static bool
curtain_key_same(enum curtain_type type,
    union curtain_key key0, union curtain_key key1)
{
	switch (type) {
	CURTAIN_KEY_INVALID_TYPE_CASES
		break;
	case CURTAIN_IOCTL:
		return (key0.ioctl == key1.ioctl);
	case CURTAIN_SOCKAF:
		return (key0.sockaf == key1.sockaf);
	case CURTAIN_SOCKLVL:
		return (key0.socklvl == key1.socklvl);
	case CURTAIN_GETSOCKOPT:
	case CURTAIN_SETSOCKOPT:
	case CURTAIN_SOCKOPT:
		return (key0.sockopt.level == key1.sockopt.level &&
		        key0.sockopt.optname == key1.sockopt.optname);
	case CURTAIN_PRIV:
		return (key0.priv == key1.priv);
	case CURTAIN_SYSCTL:
		return (key0.sysctl == key1.sysctl);
	case CURTAIN_FIBNUM:
		return (key0.fibnum == key1.fibnum);
	case CURTAIN_UNVEIL: {
		char *name0, *name1;
		size_t name_len;
		if (key0.unveil->hash != key1.unveil->hash)
			return (false);
		if (key0.unveil->name_len != key1.unveil->name_len)
			return (false);
		name_len = key0.unveil->name_len;
		if (name_len == 0)
			return (true);
		name0 = key0.unveil->name_ext ? *(char **)(key0.unveil + 1) : key0.unveil->name;
		name1 = key1.unveil->name_ext ? *(char **)(key1.unveil + 1) : key1.unveil->name;
		return (memcmp(name0, name1, name_len) == 0);
	}
	}
	MPASS(0);
	return (false);
}

static void
curtain_key_free(enum curtain_type type, union curtain_key key)
{
	switch (type) {
	case CURTAIN_SYSCTL:
		sysctl_shadow_free(key.sysctl);
		break;
	case CURTAIN_UNVEIL:
		vrele(key.unveil->vp);
		free(key.unveil, M_CURTAIN_UNVEIL);
		break;
	default:
		break;
	}
}

static void
curtain_key_dup(enum curtain_type type, union curtain_key *dst, union curtain_key src)
{
	*dst = src;
	switch (type) {
	case CURTAIN_SYSCTL:
		sysctl_shadow_hold(dst->sysctl);
		break;
	case CURTAIN_UNVEIL: {
		size_t name_size;
		name_size = src.unveil->name_len + (src.unveil->name_len != 0);
		dst->unveil = malloc(sizeof *dst->unveil + name_size, M_CURTAIN_UNVEIL, M_WAITOK);
		memcpy(dst->unveil, src.unveil, sizeof *dst->unveil + name_size);
		vref(dst->unveil->vp);
		break;
	}
	default:
		break;
	}
}

static void
curtain_key_dup_fixup(const struct curtain *ct, enum curtain_type type, union curtain_key *key)
{
	switch (type) {
	case CURTAIN_UNVEIL:
		if (key->unveil->parent) {
			struct curtain_item *item;
			item = curtain_lookup(ct, type,
			    (union curtain_key){ .unveil = key->unveil->parent });
			KASSERT(item || ct->ct_overflowed, ("parent unveil missing"));
			key->unveil->parent = item ? item->key.unveil : NULL;
		}
		break;
	default:
		break;
	}
}

static void
curtain_key_harden(enum curtain_type type, union curtain_key *key)
{
	switch (type) {
	case CURTAIN_UNVEIL:
		key->unveil->hard_uperms &= key->unveil->soft_uperms;
		break;
	default:
		break;
	}
}

enum curtain_ability
curtain_type_fallback(enum curtain_type type)
{
	switch (type) {
	case CURTAIN_IOCTL: return (CURTAINABL_ANY_IOCTL);
	case CURTAIN_SOCKAF: return (CURTAINABL_ANY_SOCKAF);
	case CURTAIN_SOCKLVL:
	case CURTAIN_GETSOCKOPT:
	case CURTAIN_SETSOCKOPT:
	case CURTAIN_SOCKOPT: return (CURTAINABL_ANY_SOCKOPT);
	case CURTAIN_PRIV: return (CURTAINABL_ANY_PRIV);
	case CURTAIN_SYSCTL: return (CURTAINABL_ANY_SYSCTL);
	case CURTAIN_FIBNUM: return (CURTAINABL_ANY_FIBNUM);
	default: return (CURTAINABL_DEFAULT);
	}
}

static inline void
curtain_key_fallback(enum curtain_type *type, union curtain_key *key)
{
	switch (*type) {
	case CURTAIN_GETSOCKOPT:
	case CURTAIN_SETSOCKOPT:
		*type = CURTAIN_SOCKOPT;
		return;
	case CURTAIN_SOCKOPT:
		*key = (union curtain_key){ .socklvl = key->sockopt.level };
		*type = CURTAIN_SOCKLVL;
		return;
	case CURTAIN_SYSCTL:
		if (key->sysctl->parent) {
			*key = (union curtain_key){ .sysctl = key->sysctl->parent };
			return;
		}
		break;
	case CURTAIN_UNVEIL:
		if (key->unveil->parent) {
			*key = (union curtain_key){ .unveil = key->unveil->parent };
			return;
		}
		break;
	default:
		break;
	}
	*key = (union curtain_key){ .ability = curtain_type_fallback(*type) };
	*type = CURTAIN_ABILITY;
}

static void
curtain_key_extend(enum curtain_type dst_type, union curtain_key *dst_key,
    enum curtain_type src_type, union curtain_key src_key, struct curtain_mode src_mode)
{
	switch (dst_type) {
	case CURTAIN_UNVEIL: {
		unveil_perms soft_uperms, hard_uperms;
		if (src_type == dst_type) {
			soft_uperms = src_key.unveil->soft_uperms;
			hard_uperms = src_key.unveil->hard_uperms;
		} else {
			soft_uperms = src_mode.soft == CURTAIN_ALLOW ? UPERM_ALL : UPERM_NONE;
			hard_uperms = src_mode.hard == CURTAIN_ALLOW ? UPERM_ALL : UPERM_NONE;
		}
		dst_key->unveil->soft_uperms = uperms_inherit(soft_uperms);
		dst_key->unveil->hard_uperms = uperms_inherit(hard_uperms);
		break;
	}
	default:
		break;
	}
}

static void
curtain_key_mask(enum curtain_type dst_type, union curtain_key *dst_key,
    enum curtain_type src_type, union curtain_key src_key, struct curtain_mode src_mode)
{
	switch (dst_type) {
	case CURTAIN_UNVEIL: {
		unveil_perms mask_uperms;
		if (src_type == dst_type) {
			mask_uperms = src_key.unveil->hard_uperms;
			if (!curtain_key_same(dst_type, *dst_key, src_key))
				mask_uperms = uperms_inherit(mask_uperms);
		} else
			mask_uperms = src_mode.hard == CURTAIN_ALLOW ? UPERM_ALL : UPERM_NONE;
		dst_key->unveil->soft_uperms &= mask_uperms;
		dst_key->unveil->hard_uperms &= mask_uperms;
		break;
	}
	default:
		break;
	}
}


static inline struct curtain_item *
curtain_hash_head(struct curtain *ct, unsigned key_hash)
{
	if (ct->ct_nslots == 0)
		return (NULL);
	return (&ct->ct_slots[key_hash % ct->ct_modulo]);
}

static inline struct curtain_item *
curtain_hash_next(struct curtain *ct, const struct curtain_item *item)
{
	struct curtain_item *next;
	MPASS(item->type != 0);
	MPASS(item->chain < ct->ct_nslots);
	next = &ct->ct_slots[item->chain];
	MPASS(next->type != 0);
	return (next == item ? NULL : next);
}

static inline void
curtain_hash_init(struct curtain *ct, struct curtain_item *item)
{
	item->chain = item - ct->ct_slots;
	MPASS(item->chain < ct->ct_nslots);
}

static inline void
curtain_hash_link(struct curtain *ct,
    struct curtain_item *item, const struct curtain_item *next)
{
	MPASS(item->type != 0);
	MPASS(next->type != 0);
	item->chain = (next ? next : item) - ct->ct_slots;
	MPASS(curtain_hash_next(ct, item) == next);
}

struct curtain_item *
curtain_lookup(const struct curtain *ctc, enum curtain_type type, union curtain_key key)
{
	struct curtain *ct = __DECONST(struct curtain *, ctc);
	struct curtain_item *item;
	size_t probes = 0;
	item = curtain_hash_head(ct, curtain_key_hash(type, key));
	if (item && item->type != 0) {
		do {
			probes++;
			if (item->type == type && curtain_key_same(type, key, item->key))
				break;
		} while ((item = curtain_hash_next(ct, item)));
	} else {
		item = NULL;
		probes = 1;
	}
#ifdef CURTAIN_STATS_LOOKUP
	counter_u64_add(curtain_stats_lookups, 1);
	counter_u64_add(curtain_stats_probes, probes);
	if (probes > 5) {
		counter_u64_add(curtain_stats_long_lookups, 1);
		counter_u64_add(curtain_stats_long_probes, probes);
	}
#endif
	return (item);
}

struct curtain_item *
curtain_search(struct curtain *ct, enum curtain_type type, union curtain_key key,
    bool *inserted)
{
	struct curtain_item *item, *prev;
	item = curtain_hash_head(ct, curtain_key_hash(type, key));
	if (item && item->type != 0) {
		do {
			prev = item;
			if (item->type == type && curtain_key_same(type, key, item->key))
				break;
		} while ((item = curtain_hash_next(ct, item)));
		if (!item)
			while (ct->ct_cellar != 0)
				if (ct->ct_slots[--ct->ct_cellar].type == 0) {
					item = &ct->ct_slots[ct->ct_cellar];
					break;
				}
	} else
		prev = NULL;
	if (!item) {
		ct->ct_overflowed = true;
		if (inserted)
			*inserted = false;
		return (NULL);
	}
	curtain_dirty(ct);
	if (item->type == 0) {
		if (inserted)
			*inserted = true;
		ct->ct_nitems++;
		item->type = type;
		item->key = key;
		curtain_hash_init(ct, item);
		if (prev)
			curtain_hash_link(ct, prev, item);
		mode_set(&item->mode, CURTAIN_KILL);
	} else if (inserted)
		*inserted = false;
	return (item);
}

struct curtain *
curtain_dup(const struct curtain *src)
{
	struct curtain_item *di;
	const struct curtain_item *si;
	struct curtain *dst;
	curtain_invariants(src);
	dst = curtain_make_without_barrier(src->ct_nitems);
	if (src->ct_on_exec && !curtain_equivalent(src, src->ct_on_exec))
		dst->ct_on_exec = curtain_dup(src->ct_on_exec);
	dst->ct_head.cth_barrier = barrier_hold(CURTAIN_BARRIER(src));
	dst->ct_overflowed = src->ct_overflowed;
	memcpy(dst->ct_abilities, src->ct_abilities, sizeof dst->ct_abilities);
	for (si = src->ct_slots; si < &src->ct_slots[src->ct_nslots]; si++)
		if (si->type != 0) {
			bool inserted;
			di = curtain_search(dst, si->type, si->key, &inserted);
			MPASS(inserted);
			di->mode = si->mode;
			curtain_key_dup(di->type, &di->key, si->key);
		}
	for (di = dst->ct_slots; di < &dst->ct_slots[dst->ct_nslots]; di++)
		if (di->type != 0)
			curtain_key_dup_fixup(dst, di->type, &di->key);
	MPASS(!dst->ct_overflowed);
	dst->ct_cached = src->ct_cached;
#ifdef INVARIANTS
	for (si = src->ct_slots; si < &src->ct_slots[src->ct_nslots]; si++)
		if (si->type != 0) {
			di = curtain_lookup(dst, si->type, si->key);
			MPASS(di);
			MPASS(mode_equivalent(di->mode, si->mode));
		}
#endif
	curtain_invariants_sync(dst);
	return (dst);
}


const sysfilset_t curtain_preserve_sysfils = SYSFIL_UNCAPSICUM;

const sysfilset_t curtain_abilities_sysfils[CURTAINABL_COUNT] = {
	[CURTAINABL_DEFAULT] = SYSFIL_CATCHALL,
	[CURTAINABL_STDIO] = SYSFIL_STDIO,
	[CURTAINABL_VFS_MISC] = SYSFIL_VFS_MISC,
	[CURTAINABL_VFS_READ] = SYSFIL_VFS_READ,
	[CURTAINABL_VFS_WRITE] = SYSFIL_VFS_WRITE,
	[CURTAINABL_VFS_CREATE] = SYSFIL_VFS_CREATE,
	[CURTAINABL_VFS_DELETE] = SYSFIL_VFS_DELETE,
	[CURTAINABL_FATTR] = SYSFIL_FATTR,
	[CURTAINABL_FLOCK] = SYSFIL_FLOCK,
	[CURTAINABL_TTY] = SYSFIL_TTY,
	[CURTAINABL_SOCK] = SYSFIL_SOCK,
	[CURTAINABL_PROC] = SYSFIL_PROC,
	[CURTAINABL_THREAD] = SYSFIL_THREAD,
	[CURTAINABL_EXEC] = SYSFIL_EXEC,
	[CURTAINABL_CURTAIN] = SYSFIL_CURTAIN,
	[CURTAINABL_RLIMIT] = SYSFIL_RLIMIT,
	[CURTAINABL_SETTIME] = SYSFIL_SETTIME,
	[CURTAINABL_CRED] = SYSFIL_CRED,
	[CURTAINABL_CHOWN] = SYSFIL_CHOWN_CHECKED,
	[CURTAINABL_MLOCK] = SYSFIL_MLOCK,
	[CURTAINABL_AIO] = SYSFIL_AIO,
	[CURTAINABL_EXTATTR] = SYSFIL_EXTATTR,
	[CURTAINABL_ACL] = SYSFIL_ACL,
	[CURTAINABL_CPUSET] = SYSFIL_CPUSET,
	[CURTAINABL_SYSVIPC] = SYSFIL_SYSVIPC,
	[CURTAINABL_POSIXIPC] = SYSFIL_POSIXIPC,
	[CURTAINABL_POSIXRT] = SYSFIL_POSIXRT,
	[CURTAINABL_MAC] = SYSFIL_MAC,
	[CURTAINABL_CHROOT] = SYSFIL_CHROOT,
	[CURTAINABL_JAIL] = SYSFIL_JAIL,
	[CURTAINABL_SCHED] = SYSFIL_SCHED,
	[CURTAINABL_PS] = SYSFIL_PS,
	[CURTAINABL_DEBUG] = SYSFIL_DEBUG,
	[CURTAINABL_FMODE_SPECIAL] = SYSFIL_FMODE_SPECIAL,
	[CURTAINABL_SENDFILE] = SYSFIL_SENDFILE,
	[CURTAINABL_MOUNT] = SYSFIL_MOUNT,
	[CURTAINABL_QUOTA] = SYSFIL_QUOTA,
	[CURTAINABL_FH] = SYSFIL_FH,
	[CURTAINABL_RECVFD] = SYSFIL_RECVFD,
	[CURTAINABL_SENDFD] = SYSFIL_SENDFD,
	[CURTAINABL_PASSDIR] = SYSFIL_PASSDIR,
	[CURTAINABL_REAP] = SYSFIL_REAP,
	[CURTAINABL_FFCLOCK] = SYSFIL_FFCLOCK,
	[CURTAINABL_AUDIT] = SYSFIL_AUDIT,
	[CURTAINABL_RFORK] = SYSFIL_RFORK,
	[CURTAINABL_KMOD] = SYSFIL_KMOD,
};

static struct curtain_mode
curtain_resolve_1(const struct curtain *ct,
    enum curtain_type *type, union curtain_key *key)
{
	const struct curtain_item *item;
	do {
		if (*type == CURTAIN_ABILITY)
			return (ct->ct_abilities[key->ability]);
		item = curtain_lookup(ct, *type, *key);
		if (item) {
			*key = item->key;
			return (item->mode);
		}
		curtain_key_fallback(type, key);
	} while (true);
}

struct curtain_mode
curtain_resolve(const struct curtain *ct,
    enum curtain_type type, union curtain_key key)
{
	return (curtain_resolve_1(ct, &type, &key));
}

bool
curtain_restrictive(const struct curtain *ct)
{
	const struct curtain_item *item;
	const struct barrier *br;
	for (enum curtain_ability abl = 0; abl <= CURTAINABL_LAST; abl++)
		if (mode_restricted(ct->ct_abilities[abl]))
			return (true);
	for (item = ct->ct_slots; item < &ct->ct_slots[ct->ct_nslots]; item++)
		if (item->type != 0 && mode_restricted(item->mode))
			return (true);
	br = CURTAIN_BARRIER(ct);
	if (br->br_mode.soft != BARRIER_NONE || br->br_mode.hard != BARRIER_NONE)
		return (true);
	return (false);
}

bool
curtain_equivalent(const struct curtain *ct0, const struct curtain *ct1)
{
	return (false); /* XXX */
}

void
curtain_cache_update(struct curtain *ct)
{
	sysfilset_t handled_sfs;

	ct->ct_cached.restrictive = curtain_restrictive(ct);

	for (unsigned i = 0; i < SYSFILSET_BITS; i++)
		ct->ct_cached.sysfilacts[i] = ct->ct_abilities[CURTAINABL_DEFAULT].soft;
	handled_sfs = SYSFIL_NONE;
	for (enum curtain_ability abl = 0; abl < nitems(curtain_abilities_sysfils); abl++) {
		sysfilset_t sfs = curtain_abilities_sysfils[abl];
		while (sfs) {
			unsigned i = ffsll(sfs) - 1;
			ct->ct_cached.sysfilacts[i] = MIN(
			    handled_sfs & SYSFIL_INDEX(i) ? ct->ct_cached.sysfilacts[i]
			                                  : CURTAIN_KILL,
			    ct->ct_abilities[abl].soft);
			handled_sfs |= SYSFIL_INDEX(i);
			sfs ^= SYSFIL_INDEX(i);
		}
	}
	if (ct->ct_cached.restrictive) {
		ct->ct_cached.sysfilset = SYSFIL_NONE;
		for (unsigned i = 0; i < SYSFILSET_BITS; i++)
			if (ct->ct_cached.sysfilacts[i] == CURTAIN_ALLOW)
				ct->ct_cached.sysfilset |= SYSFIL_INDEX(i);
	} else {
		/* NOTE: Unrestricted processes must have their whole sysfilset
		 * filled, not just the bits for existing sysfils. */
		ct->ct_cached.sysfilset = SYSFIL_FULL;
	}
	MPASS(SYSFILSET_IS_RESTRICTED(ct->ct_cached.sysfilset) == ct->ct_cached.restrictive);

	if (ct->ct_on_exec)
		curtain_cache_update(ct->ct_on_exec);

	ct->ct_cached.valid = true;
}

void
curtain_harden(struct curtain *ct)
{
	struct curtain_item *item;
	for (item = ct->ct_slots; item < &ct->ct_slots[ct->ct_nslots]; item++)
		if (item->type != 0) {
			mode_harden(&item->mode);
			curtain_key_harden(item->type, &item->key);
		}
	for (enum curtain_ability abl = 0; abl <= CURTAINABL_LAST; abl++)
		mode_harden(&ct->ct_abilities[abl]);
	CURTAIN_BARRIER(ct)->br_mode.hard |= CURTAIN_BARRIER(ct)->br_mode.soft;
	if (ct->ct_on_exec)
		curtain_harden(ct->ct_on_exec);
}

void
curtain_mask_sysfils(struct curtain *ct, sysfilset_t sfs)
{
	struct curtain_mode deny;
	mode_set(&deny, CURTAIN_DENY);
	KASSERT(ct->ct_ref == 1, ("modifying shared curtain"));
	for (enum curtain_ability abl = 0; abl < nitems(curtain_abilities_sysfils); abl++)
		if (curtain_abilities_sysfils[abl] & ~sfs)
			mode_mask(&ct->ct_abilities[abl], deny);
	if (ct->ct_on_exec)
		curtain_mask_sysfils(ct->ct_on_exec, sfs);
	curtain_dirty(ct);
}

struct curtain_item *
curtain_extend(struct curtain *ct, enum curtain_type type, union curtain_key key)
{
	struct curtain_item *item, *fallback_item;
	bool inserted;
	item = curtain_search(ct, type, key, &inserted);
	if (!item)
		return (NULL);
	if (inserted) {
		curtain_key_dup(type, &item->key, key);
		curtain_key_fallback(&type, &key);
		if (type == CURTAIN_ABILITY) {
			item->mode = ct->ct_abilities[key.ability];
		} else {
			fallback_item = curtain_extend(ct, type, key);
			if (fallback_item) {
				key = fallback_item->key;
				item->mode = fallback_item->mode;
			}
		}
		curtain_key_dup_fixup(ct, item->type, &item->key);
		curtain_key_extend(item->type, &item->key, type, key, item->mode);
	}
	return (item);
}

static void
curtain_item_mask(struct curtain_item *item, const struct curtain *src)
{
	enum curtain_type type = item->type;
	union curtain_key key = item->key;
	struct curtain_mode mode;
	mode = curtain_resolve_1(src, &type, &key);
	mode_mask(&item->mode, mode);
	curtain_key_mask(item->type, &item->key, type, key, mode);
}

void
curtain_mask(struct curtain *dst, const struct curtain *src)
{
	struct curtain_item *di;
	const struct curtain_item *si;
	curtain_invariants(src);
	KASSERT(dst->ct_ref == 1, ("modifying shared curtain"));
	if (src->ct_on_exec && !dst->ct_on_exec)
		dst->ct_on_exec = curtain_dup(dst);
	for (si = src->ct_slots; si < &src->ct_slots[src->ct_nslots]; si++)
		/* Insert missing items and mask them in the next loop. */
		if (si->type != 0)
			curtain_extend(dst, si->type, si->key);
	for (di = dst->ct_slots; di < &dst->ct_slots[dst->ct_nslots]; di++)
		if (di->type != 0)
			curtain_item_mask(di, src);
	for (enum curtain_ability abl = 0; abl <= CURTAINABL_LAST; abl++)
		mode_mask(&dst->ct_abilities[abl], src->ct_abilities[abl]);
	curtain_dirty(dst);
	curtain_invariants(dst);
	if (dst->ct_on_exec)
		curtain_mask(dst->ct_on_exec, src->ct_on_exec ? src->ct_on_exec : src);
}


static int
curtain_finish_1(struct curtain *ct, struct ucred *cr)
{
	return (curtain_finish_unveils(ct, cr));
}

int
curtain_finish(struct curtain *ct, struct ucred *cr)
{
	int error;
	error = curtain_finish_1(ct, cr);
	if (error)
		return (error);
	if (ct->ct_on_exec) {
		error = curtain_finish_1(ct->ct_on_exec, cr);
		if (error)
			return (error);
	}
	curtain_cache_update(ct);
	return (0);
}

static sysfilset_t
curtain_to_sysfils(const struct curtain *ct, const struct ucred *cr)
{
	sysfilset_t sysfils;
	MPASS(ct->ct_cached.valid);
	sysfils = (cr->cr_sysfilset & curtain_preserve_sysfils) |
	    (ct->ct_cached.sysfilset & ~curtain_preserve_sysfils);
	MPASS(SYSFILSET_IS_RESTRICTED(sysfils) ==
	    SYSFILSET_IS_RESTRICTED(cr->cr_sysfilset | ~curtain_preserve_sysfils) ||
	    ct->ct_cached.restrictive);
	return (sysfils);
}

bool
curtain_cred_restricted(const struct curtain *ct, const struct ucred *cr)
{
	curtain_invariants(ct);
	return (SYSFILSET_IS_RESTRICTED(curtain_to_sysfils(ct, cr)));
}

void
curtain_cred_update(const struct curtain *ct, struct ucred *cr)
{
	sysfilset_t sysfils;
	curtain_invariants(ct);
	sysfils = curtain_to_sysfils(ct, cr);
	cr->cr_sysfilset = sysfils;
	MPASS(SYSFILSET_IS_RESTRICTED(sysfils) == CRED_IN_RESTRICTED_MODE(cr));
}


static void
subr_curtain_sysinit(void *arg)
{
	rw_init(&barrier_tree_lock, "barrier_tree");
}

static void
subr_curtain_sysuninit(void *arg __unused)
{
	rw_destroy(&barrier_tree_lock);
}

SYSINIT(curtain_sysinit, SI_SUB_MAC_POLICY, SI_ORDER_FIRST, subr_curtain_sysinit, NULL);
SYSUNINIT(curtain_sysuninit, SI_SUB_MAC_POLICY, SI_ORDER_FIRST, subr_curtain_sysuninit, NULL);

