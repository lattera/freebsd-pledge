#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_capsicum.h"

#include <sys/param.h>
#include <sys/sysproto.h>
#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/ucred.h>
#include <sys/syslog.h>
#include <sys/sysctl.h>
#include <sys/priv.h>
#include <sys/jail.h>
#include <sys/signalvar.h>
#include <sys/mman.h>
#include <sys/counter.h>
#include <sys/sdt.h>
#include <sys/rwlock.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/syscall.h>
#include <sys/sysfil.h>
#include <sys/socket.h>
#include <sys/sockopt.h>
#include <sys/sbuf.h>
#include <sys/stat.h>
#include <sys/unveil.h>
#include <sys/curtain.h>

#include <security/mac/mac_policy.h>

#include <sys/filio.h>
#include <sys/tty.h>

static MALLOC_DEFINE(M_CURTAIN, "curtain", "curtain restrictions");

SDT_PROVIDER_DEFINE(curtain);
SDT_PROBE_DEFINE3(curtain,, curtain_build, begin,
    "int", "size_t", "const struct curtainreq *");
SDT_PROBE_DEFINE1(curtain,, curtain_build, harden, "struct curtain *");
SDT_PROBE_DEFINE1(curtain,, curtain_build, done, "struct curtain *");
SDT_PROBE_DEFINE0(curtain,, curtain_build, failed);
SDT_PROBE_DEFINE1(curtain,, do_curtainctl, mask, "struct curtain *");
SDT_PROBE_DEFINE1(curtain,, do_curtainctl, compact, "struct curtain *");
SDT_PROBE_DEFINE1(curtain,, do_curtainctl, assign, "struct curtain *");


static bool __read_mostly curtainctl_enabled = true;
static unsigned __read_mostly curtain_log_level = CURTAINLVL_TRAP;

SYSCTL_NODE(_security, OID_AUTO, curtain,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "Curtain");

SYSCTL_BOOL(_security_curtain, OID_AUTO, enabled,
    CTLFLAG_RW, &curtainctl_enabled, 0,
    "Allow curtainctl(2) usage");

SYSCTL_UINT(_security_curtain, OID_AUTO, log_level,
    CTLFLAG_RW, &curtain_log_level, 0,
    "");

#define CURTAIN_STATS

#ifdef CURTAIN_STATS

SYSCTL_NODE(_security_curtain, OID_AUTO, stats,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0, "");

#define STATNODE_COUNTER(name, varname, descr)				\
	static COUNTER_U64_DEFINE_EARLY(varname);			\
	SYSCTL_COUNTER_U64(_security_curtain_stats, OID_AUTO, name,	\
	    CTLFLAG_RD, &varname, descr);

STATNODE_COUNTER(lookups, curtain_stats_lookups, "");
STATNODE_COUNTER(probes, curtain_stats_probes, "");
STATNODE_COUNTER(long_lookups, curtain_stats_long_lookups, "");
STATNODE_COUNTER(long_probes, curtain_stats_long_probes, "");

#endif

CTASSERT(CURTAINCTL_MAX_ITEMS <= (curtain_index)-1);

static volatile uint64_t curtain_serial = 1;

static int __read_mostly curtain_slot;
#define	SLOT(l) ((l) ? (struct curtain *)mac_label_get((l), curtain_slot) : NULL)
#define	SLOT_SET(l, val) mac_label_set((l), curtain_slot, (uintptr_t)(val))
#define	CRED_SLOT(cr) SLOT((cr)->cr_label)


static inline void
mode_set(struct curtain_mode *mode, enum curtain_level lvl)
{
	mode->on_self = mode->on_exec = lvl;
	mode->on_self_max = mode->on_exec_max = lvl;
}

static inline void
mode_mask(struct curtain_mode *dst, const struct curtain_mode *src)
{
	dst->on_self_max = MAX(src->on_self_max, dst->on_self_max);
	dst->on_exec_max = MAX(src->on_exec_max, dst->on_exec_max);
	dst->on_self = MAX(dst->on_self, dst->on_self_max);
	dst->on_exec = MAX(dst->on_exec, dst->on_exec_max);
}

static inline void
mode_cap(struct curtain_mode *mode, enum curtain_level lvl)
{
	struct curtain_mode cap;
	mode_set(&cap, lvl);
	mode_mask(mode, &cap);
}

static inline void
mode_harden(struct curtain_mode *mode)
{
	mode->on_self = mode->on_self_max = MAX(mode->on_self, mode->on_self_max);
	mode->on_exec = mode->on_exec_max = MAX(mode->on_exec, mode->on_exec_max);
}


static void
curtain_init(struct curtain *ct, size_t nslots)
{
	if (nslots != (curtain_index)nslots)
		panic("invalid curtain nslots %zu", nslots);
	/* NOTE: zeroization leads to all levels being set to CURTAINLVL_PASS */
	*ct = (struct curtain){
		.ct_ref = 1,
		.ct_parent = NULL,
		.ct_children = SLIST_HEAD_INITIALIZER(ct.ct_children),
		.ct_nchildren = 0,
		.ct_cache_valid = false,
		.ct_nitems = 0,
		.ct_nslots = nslots,
		.ct_modulo = nslots,
		.ct_cellar = nslots,
	};
	ct->ct_serial = atomic_fetchadd_64(&curtain_serial, 1);
	for (curtain_index i = 0; i < nslots; i++)
		ct->ct_slots[i].type = 0;
}

static void
curtain_invariants(const struct curtain *ct)
{
	MPASS(ct);
	MPASS(ct->ct_parent != ct);
	MPASS(ct->ct_ref > 0);
	MPASS(ct->ct_nslots >= ct->ct_nitems);
	MPASS(ct->ct_nslots >= ct->ct_modulo);
	MPASS(ct->ct_nslots >= ct->ct_cellar);
}

static void
curtain_invariants_sync(const struct curtain *ct)
{
	curtain_invariants(ct);
	MPASS(LIST_EMPTY(&ct->ct_children) == (ct->ct_nchildren == 0));
}

static struct curtain *
curtain_alloc(size_t nslots)
{
	struct curtain *ct;
	ct = malloc(sizeof *ct + nslots * sizeof *ct->ct_slots, M_CURTAIN, M_WAITOK);
	return (ct);
}

static struct curtain *
curtain_make(size_t nitems)
{
	size_t nslots;
	struct curtain *ct;
	nslots = nitems + nitems/8;
	ct = curtain_alloc(nslots);
	curtain_init(ct, nslots);
	ct->ct_modulo = nitems + nitems/16;
	curtain_invariants_sync(ct);
	return (ct);
}

static struct rwlock __exclusive_cache_line curtain_tree_lock;

static struct curtain *
curtain_hold(struct curtain *ct)
{
	refcount_acquire(&ct->ct_ref);
	return (ct);
}

static void
curtain_link(struct curtain *child, struct curtain *parent)
{
	rw_wlock(&curtain_tree_lock);
	curtain_invariants_sync(child);
#ifdef INVARIANTS
	if (parent)
		for (const struct curtain *iter = child; iter; iter = iter->ct_parent)
			MPASS(iter != parent);
#endif
	if ((child->ct_parent = parent)) {
		curtain_invariants_sync(parent);
		parent->ct_nchildren++;
		MPASS(parent->ct_nchildren != 0);
		LIST_INSERT_HEAD(&parent->ct_children, child, ct_sibling);
		curtain_invariants_sync(parent);
	} else {
#ifdef INVARIANTS
		memset(&child->ct_sibling, -1, sizeof child->ct_sibling);
#endif
	}
	curtain_invariants_sync(child);
	rw_wunlock(&curtain_tree_lock);
}

static void
curtain_unlink(struct curtain *victim)
{
	struct curtain *child;
	rw_wlock(&curtain_tree_lock);
	MPASS(LIST_EMPTY(&victim->ct_children) == (victim->ct_nchildren == 0));
	if (victim->ct_parent) {
		curtain_invariants_sync(victim->ct_parent);
		LIST_REMOVE(victim, ct_sibling);
		MPASS(victim->ct_parent->ct_nchildren != 0);
		victim->ct_parent->ct_nchildren--;
		curtain_invariants_sync(victim->ct_parent);
	}
	while (!LIST_EMPTY(&victim->ct_children)) {
		child = LIST_FIRST(&victim->ct_children);
		MPASS(child->ct_parent == victim);
		curtain_invariants_sync(child);
		MPASS(victim->ct_nchildren != 0);
		victim->ct_nchildren--;
		LIST_REMOVE(child, ct_sibling);
		if ((child->ct_parent = victim->ct_parent)) {
			LIST_INSERT_HEAD(&child->ct_parent->ct_children, child, ct_sibling);
			child->ct_parent->ct_nchildren++;
			MPASS(child->ct_parent->ct_nchildren != 0);
		}
		if (victim->ct_barrier)
			child->ct_barrier = child->ct_barrier_on_exec = true;
		curtain_invariants_sync(child);
	}
	MPASS(victim->ct_nchildren == 0);
	victim->ct_parent = NULL;
	rw_wunlock(&curtain_tree_lock);
}

static void
curtain_free(struct curtain *ct)
{
	curtain_invariants(ct);
	if (refcount_release(&ct->ct_ref)) {
		curtain_unlink(ct);
		free(ct, M_CURTAIN);
	}
}

static bool
curtain_visible(const struct curtain *subject, const struct curtain *target, bool strict)
{
	/*
	 * NOTE: One or both of subject and target may be NULL (indicating
	 * credentials with no curtain restrictions).
	 */
	if (subject)
		curtain_invariants(subject);
	if (target)
		curtain_invariants(target);
	if (subject == target) /* fast path */
		return (true);
	rw_rlock(&curtain_tree_lock);
	if (!strict)
		while (subject && !subject->ct_barrier)
			subject = subject->ct_parent;
	while (target && subject != target)
		target = target->ct_parent;
	rw_runlock(&curtain_tree_lock);
	return (subject == target);

}

static void
curtain_copy(struct curtain *dst, const struct curtain *src)
{
	memcpy(dst, src, sizeof *src + src->ct_nslots * sizeof *src->ct_slots);
	dst->ct_ref = 1;
	dst->ct_parent = NULL;
	dst->ct_nchildren = 0;
	LIST_INIT(&dst->ct_children);
#ifdef INVARIANTS
	memset(&dst->ct_sibling, -1, sizeof dst->ct_sibling);
#endif
	curtain_invariants_sync(dst);
}

static struct curtain *
curtain_dup_unlinked(const struct curtain *src)
{
	struct curtain *dst;
	curtain_invariants(src);
	dst = curtain_alloc(src->ct_nslots);
	curtain_copy(dst, src);
	return (dst);
}

static struct curtain *
curtain_dup(const struct curtain *src)
{
	struct curtain *dst;
	dst = curtain_dup_unlinked(src);
	curtain_link(dst, src->ct_parent);
	return (dst);
}

static struct curtain *
curtain_dup_child(struct curtain *src)
{
	struct curtain *dst;
	dst = curtain_dup_unlinked(src);
	curtain_link(dst, src);
	return (dst);
}

static inline void
curtain_dirty(struct curtain *ct)
{
	ct->ct_cache_valid = false;
}

#define CURTAIN_KEY_INVALID_TYPE_CASES	\
	case CURTAINTYP_DEFAULT:	\
	case CURTAINTYP_SYSFIL:		\
	case CURTAINTYP_UNVEIL:

static unsigned
curtain_key_hash(enum curtain_type type, union curtain_key key)
{
	switch (type) {
	CURTAIN_KEY_INVALID_TYPE_CASES
		break;
	case CURTAINTYP_IOCTL:
		return (key.ioctl ^ key.ioctl >> 5);
	case CURTAINTYP_SOCKAF:
		return (key.sockaf);
	case CURTAINTYP_SOCKLVL:
		return (key.socklvl);
	case CURTAINTYP_SOCKOPT:
		return (key.sockopt.level ^ key.sockopt.optname);
	case CURTAINTYP_PRIV:
		return (key.priv);
	case CURTAINTYP_SYSCTL:
		return (key.sysctl.serial);
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
	case CURTAINTYP_IOCTL:
		return (key0.ioctl == key1.ioctl);
	case CURTAINTYP_SOCKAF:
		return (key0.sockaf == key1.sockaf);
	case CURTAINTYP_SOCKLVL:
		return (key0.socklvl == key1.socklvl);
	case CURTAINTYP_SOCKOPT:
		return (key0.sockopt.level == key1.sockopt.level &&
		        key0.sockopt.optname == key1.sockopt.optname);
	case CURTAINTYP_PRIV:
		return (key0.priv == key1.priv);
	case CURTAINTYP_SYSCTL:
		return (key0.sysctl.serial == key1.sysctl.serial);
	}
	MPASS(0);
	return (false);
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

static struct curtain_item *
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
#ifdef CURTAIN_STATS
	counter_u64_add(curtain_stats_lookups, 1);
	counter_u64_add(curtain_stats_probes, probes);
	if (probes > 5) {
		counter_u64_add(curtain_stats_long_lookups, 1);
		counter_u64_add(curtain_stats_long_probes, probes);
	}
#endif
	return (item);
}

static struct curtain_item *
curtain_search(struct curtain *ct, enum curtain_type type, union curtain_key key)
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
	} else {
		curtain_dirty(ct);
		if (item->type == 0) {
			ct->ct_nitems++;
			item->type = type;
			item->key = key;
			curtain_hash_init(ct, item);
			if (prev)
				curtain_hash_link(ct, prev, item);
			mode_set(&item->mode, CURTAINLVL_PASS);
		}
	}
	return (item);
}

static struct curtain *
curtain_dup_compact(const struct curtain *src)
{
	struct curtain_item *di;
	const struct curtain_item *si;
	struct curtain *dst;
	curtain_invariants(src);
	dst = curtain_make(src->ct_nitems);
	dst->ct_overflowed = src->ct_overflowed;
	if ((dst->ct_cache_valid = src->ct_cache_valid))
		dst->ct_cached = src->ct_cached;
	dst->ct_serial = src->ct_serial;
	dst->ct_barrier = src->ct_barrier;
	dst->ct_barrier_on_exec = src->ct_barrier_on_exec;
	memcpy(dst->ct_sysfils, src->ct_sysfils, sizeof dst->ct_sysfils);
	for (si = src->ct_slots; si < &src->ct_slots[src->ct_nslots]; si++)
		if (si->type != 0) {
			di = curtain_search(dst, si->type, si->key);
			if (di)
				di->mode = si->mode;
		}
#ifdef INVARIANTS
	for (si = src->ct_slots; si < &src->ct_slots[src->ct_nslots]; si++)
		if (si->type != 0) {
			di = curtain_lookup(dst, si->type, si->key);
			MPASS(di);
			MPASS(memcmp(&di->mode, &si->mode, sizeof di->mode) == 0);
		}
#endif
	curtain_link(dst, src->ct_parent);
	curtain_invariants_sync(dst);
	return (dst);
}

static int
sysfil_for_type(enum curtain_type type)
{
	switch (type) {
	CURTAIN_KEY_INVALID_TYPE_CASES
		break;
	case CURTAINTYP_IOCTL:
		return (SYSFIL_ANY_IOCTL);
	case CURTAINTYP_SOCKAF:
		return (SYSFIL_ANY_SOCKAF);
	case CURTAINTYP_SOCKLVL:
		return (SYSFIL_ANY_SOCKOPT);
	case CURTAINTYP_SOCKOPT:
		return (SYSFIL_ANY_SOCKOPT);
	case CURTAINTYP_PRIV:
		return (SYSFIL_ANY_PRIV);
	case CURTAINTYP_SYSCTL:
		return (SYSFIL_ANY_SYSCTL);
	}
	MPASS(0);
	return (SYSFIL_DEFAULT);
}

typedef union curtain_key ctkey;

static bool
curtain_need_exec_switch(const struct curtain *ct)
{
	const struct curtain_item *item;
	for (int sf = 0; sf <= SYSFIL_LAST; sf++)
		if (ct->ct_sysfils[sf].on_self != ct->ct_sysfils[sf].on_exec ||
		    ct->ct_sysfils[sf].on_self_max != ct->ct_sysfils[sf].on_exec_max)
			return (true);
	for (item = ct->ct_slots; item < &ct->ct_slots[ct->ct_nslots]; item++)
		if (item->type != 0 &&
		    (item->mode.on_self != item->mode.on_exec ||
		     item->mode.on_self_max != item->mode.on_exec_max))
			return (true);
	if (ct->ct_barrier != ct->ct_barrier_on_exec)
		return (true);
	return (false);
}

static bool
curtain_is_restricted_on_self(const struct curtain *ct)
{
	const struct curtain_item *item;
	for (int sf = 0; sf <= SYSFIL_LAST; sf++)
		if (ct->ct_sysfils[sf].on_self     != CURTAINLVL_PASS ||
		    ct->ct_sysfils[sf].on_self_max != CURTAINLVL_PASS)
			return (true);
	for (item = ct->ct_slots; item < &ct->ct_slots[ct->ct_nslots]; item++)
		if (item->type != 0)
			if (item->mode.on_self     != CURTAINLVL_PASS ||
			    item->mode.on_self_max != CURTAINLVL_PASS)
				return (true);
	return (false);
}

static bool
curtain_is_restricted_on_exec(const struct curtain *ct)
{
	const struct curtain_item *item;
	for (int sf = 0; sf <= SYSFIL_LAST; sf++)
		if (ct->ct_sysfils[sf].on_exec     != CURTAINLVL_PASS ||
		    ct->ct_sysfils[sf].on_exec_max != CURTAINLVL_PASS)
			return (true);
	for (item = ct->ct_slots; item < &ct->ct_slots[ct->ct_nslots]; item++)
		if (item->type != 0)
			if (item->mode.on_exec     != CURTAINLVL_PASS ||
			    item->mode.on_exec_max != CURTAINLVL_PASS)
				return (true);
	return (false);
}

static void
curtain_to_sysfilset(const struct curtain *ct, sysfilset_t *sfs)
{
	BIT_ZERO(SYSFILSET_BITS, sfs);
	for (int sf = 0; sf <= SYSFIL_LAST; sf++)
		if (ct->ct_sysfils[sf].on_self == CURTAINLVL_PASS)
			BIT_SET(SYSFILSET_BITS, sf, sfs);
}

static void
curtain_cache_update(struct curtain *ct)
{
	sysfilset_t sfs;
	curtain_to_sysfilset(ct, &sfs);
	ct->ct_cached.need_exec_switch = curtain_need_exec_switch(ct);
	ct->ct_cached.is_restricted_on_self = curtain_is_restricted_on_self(ct);
	ct->ct_cached.is_restricted_on_exec = curtain_is_restricted_on_exec(ct);
	ct->ct_cache_valid = true;
}

static void
curtain_cred_sysfil_update(struct ucred *cr, const struct curtain *ct)
{
	if (curtain_is_restricted_on_self(ct)) {
		curtain_to_sysfilset(ct, &cr->cr_sysfilset);
		MPASS(SYSFILSET_IS_RESTRICTED(&cr->cr_sysfilset));
		MPASS(CRED_IN_RESTRICTED_MODE(cr));
	} else {
		BIT_FILL(SYSFILSET_BITS, &cr->cr_sysfilset);
		MPASS(!SYSFILSET_IS_RESTRICTED(&cr->cr_sysfilset));
		MPASS(!CRED_IN_RESTRICTED_MODE(cr));
	}
}

static void
curtain_exec_switch(struct curtain *ct)
{
	struct curtain_item *item;
	for (int sf = 0; sf <= SYSFIL_LAST; sf++) {
		ct->ct_sysfils[sf].on_self     = ct->ct_sysfils[sf].on_exec;
		ct->ct_sysfils[sf].on_self_max = ct->ct_sysfils[sf].on_exec_max;
	}
	for (item = ct->ct_slots; item < &ct->ct_slots[ct->ct_nslots]; item++)
		if (item->type != 0) {
			item->mode.on_self     = item->mode.on_exec;
			item->mode.on_self_max = item->mode.on_exec_max;
		}
	ct->ct_barrier = ct->ct_barrier_on_exec;
	curtain_dirty(ct);
}

static void
curtain_harden(struct curtain *ct)
{
	struct curtain_item *item;
	for (item = ct->ct_slots; item < &ct->ct_slots[ct->ct_nslots]; item++)
		if (item->type != 0)
			mode_harden(&item->mode);
	for (int sf = 0; sf <= SYSFIL_LAST; sf++)
		mode_harden(&ct->ct_sysfils[sf]);
}

static void
curtain_mask_sysfils(struct curtain *ct, const sysfilset_t *sfs)
{
	struct curtain_item *item;
	KASSERT(ct->ct_ref == 1, ("modifying shared curtain"));
	for (int sf = 0; sf <= SYSFIL_LAST; sf++)
		if (!BIT_ISSET(SYSFILSET_BITS, sf, sfs))
			mode_cap(&ct->ct_sysfils[sf], CURTAINLVL_DENY);
	for (item = ct->ct_slots; item < &ct->ct_slots[ct->ct_nslots]; item++)
		if (item->type != 0)
			if (!BIT_ISSET(SYSFILSET_BITS, sysfil_for_type(item->type), sfs))
				mode_cap(&item->mode, CURTAINLVL_DENY);
	if (!BIT_ISSET(SYSFILSET_BITS, SYSFIL_ANY_PROCESS, sfs))
		ct->ct_barrier = ct->ct_barrier_on_exec = true;
	curtain_dirty(ct);
}

static void
curtain_mask_item(struct curtain_mode *mode,
    enum curtain_type type, union curtain_key key, const struct curtain *ct)
{
	const struct curtain_item *item;
	item = curtain_lookup(ct, type, key);
	if (!item && type == CURTAINTYP_SOCKOPT)
		item = curtain_lookup(ct, CURTAINTYP_SOCKLVL,
		    (ctkey){ .socklvl = key.sockopt.level });
	mode_mask(mode, item ? &item->mode :
	    &ct->ct_sysfils[sysfil_for_type(type)]);
}

static void
curtain_mask(struct curtain *dst, const struct curtain *src)
{
	struct curtain_item *di;
	const struct curtain_item *si;
	curtain_invariants(src);
	KASSERT(dst->ct_ref == 1, ("modifying shared curtain"));
	for (si = src->ct_slots; si < &src->ct_slots[src->ct_nslots]; si++)
		if (si->type != 0 && !curtain_lookup(dst, si->type, si->key)) {
			struct curtain_mode mode = si->mode;
			curtain_mask_item(&mode, si->type, si->key, dst);
			di = curtain_search(dst, si->type, si->key);
			if (di)
				di->mode = mode;
		}
	for (di = dst->ct_slots; di < &dst->ct_slots[dst->ct_nslots]; di++)
		if (di->type != 0)
			curtain_mask_item(&di->mode, di->type, di->key, src);
	for (int sf = 0; sf <= SYSFIL_LAST; sf++)
		mode_mask(&dst->ct_sysfils[sf], &src->ct_sysfils[sf]);
	curtain_dirty(dst);
	curtain_invariants(dst);
}

/* Some sysfils shouldn't be disabled via curtainctl(2). */
static const int sysfils_always[] = { SYSFIL_ALWAYS, SYSFIL_UNCAPSICUM };
/* Some sysfils don't make much sense without some others. */
static const int sysfils_expand[][2] = {
	/* NOTE: Make sure dependencies can be handled in a single pass! */
	{ SYSFIL_VFS_READ,	SYSFIL_VFS_MISC		},
	{ SYSFIL_VFS_WRITE,	SYSFIL_VFS_MISC		},
	{ SYSFIL_VFS_CREATE,	SYSFIL_VFS_MISC		},
	{ SYSFIL_VFS_DELETE,	SYSFIL_VFS_MISC		},
	{ SYSFIL_FATTR,		SYSFIL_VFS_MISC		},
	{ SYSFIL_PROT_EXEC,	SYSFIL_PROT_EXEC_LOOSE	},
	{ SYSFIL_UNIX,		SYSFIL_NET		},
	{ SYSFIL_CPUSET,	SYSFIL_SCHED		},
};

static inline void
mode_update(struct curtain_mode *mode, int flags, enum curtain_level lvl)
{
	if (flags & CURTAINREQ_ON_SELF)
		mode->on_self = lvl;
	if (flags & CURTAINREQ_ON_EXEC)
		mode->on_exec = lvl;
}

static struct curtain *
curtain_build(int flags, size_t reqc, const struct curtainreq *reqv)
{
	struct curtain *ct;
	const struct curtainreq *req;
	enum curtain_level def_on_self, def_on_exec;

	SDT_PROBE3(curtain,, curtain_build, begin, flags, reqc, reqv);

	ct = curtain_make(CURTAINCTL_MAX_ITEMS);

	def_on_self = def_on_exec = CURTAINLVL_DENY;
	for (req = reqv; req < &reqv[reqc]; req++)
		if (req->type == CURTAINTYP_DEFAULT) {
			if (req->flags & CURTAINREQ_ON_SELF)
				def_on_self = req->level;
			if (req->flags & CURTAINREQ_ON_EXEC)
				def_on_exec = req->level;
		}
	for (int sf = 0; sf <= SYSFIL_LAST; sf++) {
		ct->ct_sysfils[sf].on_self = def_on_self;
		ct->ct_sysfils[sf].on_exec = def_on_exec;
	}
	for (size_t i = 0; i < nitems(sysfils_always); i++) {
		ct->ct_sysfils[sysfils_always[i]].on_self = CURTAINLVL_PASS;
		ct->ct_sysfils[sysfils_always[i]].on_exec = CURTAINLVL_PASS;
	}

	for (req = reqv; req < &reqv[reqc]; req++)
		switch (req->type) {
		case CURTAINTYP_DEFAULT:
			break; /* handled earlier */
		case CURTAINTYP_SYSFIL: {
			int *sfp = req->data;
			size_t sfc = req->size / sizeof *sfp;
			while (sfc--) {
				int sf = *sfp++;
				if (!SYSFIL_USER_VALID(sf))
					goto fail;
				mode_update(&ct->ct_sysfils[sf], req->flags, req->level);
			}
			break;
		}
		case CURTAINTYP_UNVEIL:
			break; /* handled elsewhere */
		case CURTAINTYP_IOCTL: {
			unsigned long *p = req->data;
			size_t c = req->size / sizeof *p;
			while (c--) {
				struct curtain_item *item;
				item = curtain_search(ct, req->type,
				    (ctkey){ .ioctl = *p++ });
				if (!item)
					goto fail;
				mode_update(&item->mode, req->flags, req->level);
			}
			break;
		}
		case CURTAINTYP_SOCKAF: {
			int *p = req->data;
			size_t c = req->size / sizeof *p;
			while (c--) {
				struct curtain_item *item;
				item = curtain_search(ct, req->type,
				    (ctkey){ .sockaf = *p++ });
				if (!item)
					goto fail;
				mode_update(&item->mode, req->flags, req->level);
			}
			break;
		}
		case CURTAINTYP_SOCKLVL: {
			int *p = req->data;
			size_t c = req->size / sizeof *p;
			while (c--) {
				struct curtain_item *item;
				item = curtain_search(ct, req->type,
				    (ctkey){ .socklvl = *p++ });
				if (!item)
					goto fail;
				mode_update(&item->mode, req->flags, req->level);
			}
			break;
		}
		case CURTAINTYP_SOCKOPT: {
			int (*p)[2] = req->data;
			size_t c = req->size / sizeof *p;
			while (c--) {
				struct curtain_item *item;
				item = curtain_search(ct, req->type,
				    (ctkey){ .sockopt = { (*p)[0], (*p)[1] } });
				p++;
				if (!item)
					goto fail;
				mode_update(&item->mode, req->flags, req->level);
			}
			break;
		}
		case CURTAINTYP_PRIV: {
			int *p = req->data;
			size_t c = req->size / sizeof *p;
			while (c--) {
				struct curtain_item *item;
				item = curtain_search(ct, req->type,
				    (ctkey){ .priv = *p++ });
				if (!item)
					goto fail;
				mode_update(&item->mode, req->flags, req->level);
			}
			break;
		}
		case CURTAINTYP_SYSCTL: {
			int *namep = req->data;
			size_t namec = req->size / sizeof *namep, namei = 0;
			while (namei < namec) {
				struct curtain_item *item;
				struct sysctl_oid *oidp;
				int error;
				if (namep[namei] >= 0) {
					namei++;
					continue;
				}
				error = sysctl_lookup(namep, namei, &oidp, NULL, NULL);
				if (error && error != ENOENT)
					goto fail;
				namep += namei + 1;
				namec -= namei + 1;
				namei = 0;
				item = curtain_search(ct, req->type,
				    (ctkey){ .sysctl = { .serial = oidp->oid_serial } });
				if (!item)
					goto fail;
				mode_update(&item->mode, req->flags, req->level);
			}
			break;
		}
		default:
			goto fail;
		}

	if (ct->ct_nitems > CURTAINCTL_MAX_ITEMS)
		goto fail;

	ct->ct_barrier         = ct->ct_sysfils[SYSFIL_ANY_PROCESS].on_self != CURTAINLVL_PASS;
	ct->ct_barrier_on_exec = ct->ct_sysfils[SYSFIL_ANY_PROCESS].on_exec != CURTAINLVL_PASS;

	for (size_t i = 0; i < nitems(sysfils_expand); i++) {
		ct->ct_sysfils[sysfils_expand[i][1]].on_self =
		    MIN(ct->ct_sysfils[sysfils_expand[i][0]].on_self,
		        ct->ct_sysfils[sysfils_expand[i][1]].on_self);
		ct->ct_sysfils[sysfils_expand[i][1]].on_exec =
		    MIN(ct->ct_sysfils[sysfils_expand[i][0]].on_exec,
		        ct->ct_sysfils[sysfils_expand[i][1]].on_exec);
	}
	ct->ct_sysfils[SYSFIL_PROT_EXEC_LOOSE].on_exec =
	    MIN(MIN(ct->ct_sysfils[SYSFIL_EXEC].on_self,
	            ct->ct_sysfils[SYSFIL_EXEC].on_exec),
		ct->ct_sysfils[SYSFIL_PROT_EXEC_LOOSE].on_exec);

	if (curtain_is_restricted_on_self(ct))
		ct->ct_sysfils[SYSFIL_DEFAULT].on_self = MAX(CURTAINLVL_DENY, def_on_self);
	if (curtain_is_restricted_on_exec(ct))
		ct->ct_sysfils[SYSFIL_DEFAULT].on_exec = MAX(CURTAINLVL_DENY, def_on_exec);

	if (flags & CURTAINCTL_ENFORCE) {
		SDT_PROBE1(curtain,, curtain_build, harden, ct);
		curtain_harden(ct);
	}

	SDT_PROBE1(curtain,, curtain_build, done, ct);
	curtain_invariants_sync(ct);
	return (ct);

fail:	SDT_PROBE0(curtain,, curtain_build, failed);
	curtain_free(ct);
	return (NULL);
}


static void
curtain_cred_exec_switch(struct ucred *cr)
{
	struct curtain *ct;
	KASSERT(cr->cr_ref == 1, ("modifying shared ucred"));
	if (!(ct = CRED_SLOT(cr)))
		return; /* NOTE: sysfilset kept as-is */

	if (!(ct->ct_cache_valid ? ct->ct_cached.is_restricted_on_exec
	                         : curtain_is_restricted_on_exec(ct))) {
		curtain_free(ct);
		SLOT_SET(cr->cr_label, NULL);
		sysfil_cred_init(cr);
		MPASS(!CRED_IN_RESTRICTED_MODE(cr));
		return;
	}

	ct = curtain_dup(ct);
	ct->ct_serial = atomic_fetchadd_64(&curtain_serial, 1);
	curtain_exec_switch(ct);
	curtain_cache_update(ct);
	curtain_cred_sysfil_update(cr, ct);
	curtain_free(CRED_SLOT(cr));
	SLOT_SET(cr->cr_label, ct);
	MPASS(CRED_IN_RESTRICTED_MODE(cr));
}

bool
curtain_cred_visible(const struct ucred *subject, const struct ucred *target, bool strict)
{
	return (curtain_visible(CRED_SLOT(subject), CRED_SLOT(target), strict));
}


static int
do_curtainctl(struct thread *td, int flags, size_t reqc, const struct curtainreq *reqv)
{
	struct proc *p = td->td_proc;
	struct ucred *cr, *old_cr;
	struct curtain *ct;
	const struct curtainreq *req;
	int error = 0;
#ifdef UNVEIL_SUPPORT
	struct unveil_base *base;
#endif
	bool on_self, on_exec;

	if (!curtainctl_enabled)
		return (ENOSYS);

#ifdef UNVEIL_SUPPORT
	if (!unveil_support)
		return (ENOSYS);

	base = unveil_proc_get_base(p, true);
	unveil_base_write_begin(base);

	/*
	 * Validate the unveil indexes first since there's no bailing out once
	 * we've started updating them.
	 */
	for (req = reqv; req < &reqv[reqc]; req++)
		if (req->type == CURTAINTYP_UNVEIL) {
			struct curtainent_unveil *entp = req->data;
			size_t entc = req->size / sizeof *entp;
			while (entc--) {
				error = unveil_index_check(base, (entp++)->index);
				if (error)
					goto out2;
			}
		}
#endif

	ct = curtain_build(flags, reqc, reqv);
	if (!ct) {
		error = EINVAL;
		goto out2;
	}

	on_self = curtain_is_restricted_on_self(ct);
	on_exec = curtain_is_restricted_on_exec(ct);

	do {
		struct curtain *new_ct;
		cr = crget();
		PROC_LOCK(p);
		old_cr = crcopysafe(p, cr);
		if (CRED_SLOT(cr))
			curtain_mask(ct, CRED_SLOT(cr));
		else
			curtain_mask_sysfils(ct, &cr->cr_sysfilset);
		crhold(old_cr);
		PROC_UNLOCK(p);
		SDT_PROBE1(curtain,, do_curtainctl, mask, ct);
		new_ct = curtain_dup_compact(ct);
		curtain_cache_update(new_ct);
		if (CRED_SLOT(cr)) {
			curtain_link(new_ct, CRED_SLOT(cr));
			curtain_free(CRED_SLOT(cr));
		}
		SLOT_SET(cr->cr_label, new_ct);
		SDT_PROBE1(curtain,, do_curtainctl, compact, CRED_SLOT(cr));
		PROC_LOCK(p);
		if (old_cr == p->p_ucred) {
			crfree(old_cr);
			curtain_free(ct);
			ct = CRED_SLOT(cr);
			break;
		}
		PROC_UNLOCK(p);
		crfree(old_cr);
		crfree(cr);
	} while (true);

	if (ct->ct_overflowed) {
		error = EINVAL;
		goto out1;
	}

	curtain_cred_sysfil_update(cr, ct);

	if (!(flags & (CURTAINCTL_ENFORCE | CURTAINCTL_ENGAGE)))
		goto out1;

	proc_set_cred(p, cr);
	crfree(old_cr);
	if (CRED_IN_RESTRICTED_MODE(cr) != PROC_IN_RESTRICTED_MODE(p))
		panic("PROC_IN_RESTRICTED_MODE() bogus");
	PROC_UNLOCK(p);
	SDT_PROBE1(curtain,, do_curtainctl, assign, ct);

#ifdef UNVEIL_SUPPORT
	for (req = reqv; req < &reqv[reqc]; req++) {
		bool req_on_self = req->flags & CURTAINREQ_ON_SELF;
		bool req_on_exec = req->flags & CURTAINREQ_ON_EXEC;
		if (req->type == CURTAINTYP_UNVEIL) {
			struct curtainent_unveil *entp = req->data;
			size_t entc = req->size / sizeof *entp;
			while (entc--) {
				if (req_on_self)
					unveil_index_set(base, entp->index,
					    UNVEIL_ON_SELF, entp->uperms);
				if (req_on_exec)
					unveil_index_set(base, entp->index,
					    UNVEIL_ON_EXEC, entp->uperms);
				entp++;
			}
		}
	}
	if (on_self)
		unveil_base_enable(base, UNVEIL_ON_SELF);
	else
		unveil_base_disable(base, UNVEIL_ON_SELF);
	if (on_exec)
		unveil_base_enable(base, UNVEIL_ON_EXEC);
	else
		unveil_base_disable(base, UNVEIL_ON_EXEC);
	if (flags & CURTAINCTL_ENFORCE) {
		if (on_self)
			unveil_base_freeze(base, UNVEIL_ON_SELF);
		if (on_exec)
			unveil_base_freeze(base, UNVEIL_ON_EXEC);
	}
	unveil_lockdown_fd(td);
#endif
	goto out2;
out1:
	PROC_UNLOCK(p);
	crfree(cr);
out2:
#ifdef UNVEIL_SUPPORT
	unveil_base_write_end(base);
#endif
	return (error);
}

int
sys_curtainctl(struct thread *td, struct curtainctl_args *uap)
{
	size_t reqc, reqi, avail;
	struct curtainreq *reqv;
	int flags, error;
	flags = uap->flags;
	if ((flags & CURTAINCTL_VERSION_MASK) != CURTAINCTL_VERSION)
		return (EINVAL);
	flags &= ~CURTAINCTL_VERSION_MASK;
	reqc = uap->reqc;
	if (reqc > CURTAINCTL_MAX_REQS)
		return (EINVAL);
	reqi = 0;
	reqv = mallocarray(reqc, sizeof *reqv, M_TEMP, M_WAITOK);
	error = copyin(uap->reqv, reqv, reqc * sizeof *reqv);
	if (error)
		goto out;
	avail = CURTAINCTL_MAX_SIZE;
	while (reqi < reqc) {
		struct curtainreq *req = &reqv[reqi];
		void *udata = req->data;
		if (avail < req->size || (req->data == NULL && req->size != 0)) {
			error = EINVAL;
			goto out;
		}
		reqi++;
		if (udata) {
			avail -= req->size;
			req->data = malloc(req->size, M_TEMP, M_WAITOK);
			error = copyin(udata, req->data, req->size);
			if (error)
				goto out;
		}
	}
	error = do_curtainctl(td, flags, reqc, reqv);
out:	while (reqi--)
		if (reqv[reqi].data)
			free(reqv[reqi].data, M_TEMP);
	free(reqv, M_TEMP);
	return (error);
}


static const char lvl2str[][5] = {
	[CURTAINLVL_PASS] = "pass",
	[CURTAINLVL_DENY] = "deny",
	[CURTAINLVL_TRAP] = "trap",
	[CURTAINLVL_KILL] = "kill",
};

static const int lvl2err[] = {
	[CURTAINLVL_PASS] = 0,
	[CURTAINLVL_DENY] = SYSFIL_FAILED_ERRNO,
	[CURTAINLVL_TRAP] = ERESTRICTEDTRAP,
	[CURTAINLVL_KILL] = ERESTRICTEDKILL,
};

#define	CURTAIN_LOG(td, lvl, fmt, ...) do { \
	if ((lvl) >= curtain_log_level) \
		log(LOG_ERR, "curtain %s: pid %d (%s), jid %d, uid %d: " fmt "\n", \
		    lvl2str[lvl], (td)->td_proc->p_pid, (td)->td_proc->p_comm, \
		    (td)->td_ucred->cr_prison->pr_id, (td)->td_ucred->cr_uid, \
		    __VA_ARGS__); \
} while (0)

#define	CURTAIN_CRED_LOG(cr, lvl, fmt, ...) do { \
	if ((cr) == curthread->td_ucred) \
		CURTAIN_LOG(curthread, (lvl), fmt, __VA_ARGS__); \
} while (0)

static enum curtain_level
curtain_cred_level(const struct ucred *cr, enum curtain_type type, union curtain_key key)
{
	const struct curtain *ct;
	if ((ct = CRED_SLOT(cr))) {
		if (type == CURTAINTYP_SYSFIL) {
			return (ct->ct_sysfils[key.sysfil].on_self);
		} else {
			const struct curtain_item *item;
			item = curtain_lookup(ct, type, key);
			if (item)
				return (item->mode.on_self);
		}
		return (CURTAINLVL_KILL);
	} else {
		if (type == CURTAINTYP_SYSFIL)
			if (sysfil_match_cred(cr, key.sysfil))
				return (CURTAINLVL_PASS);
		return (CURTAINLVL_DENY);
	}
}

static enum curtain_level
curtain_cred_sysfil_level(const struct ucred *cr, int sf)
{
	return (curtain_cred_level(cr, CURTAINTYP_SYSFIL, (ctkey){ .sysfil = sf }));
}


static void
curtain_init_label(struct label *label)
{
	if (label)
		SLOT_SET(label, NULL);
}

static void
curtain_copy_label(struct label *src, struct label *dst)
{
	if (dst) {
		if (SLOT(dst))
			curtain_free(SLOT(dst));
		if (src && SLOT(src))
			SLOT_SET(dst, curtain_hold(SLOT(src)));
		else
			SLOT_SET(dst, NULL);
	}
}

static void
curtain_destroy_label(struct label *label)
{
	if (label) {
		if (SLOT(label))
			curtain_free(SLOT(label));
		SLOT_SET(label, NULL);
	}
}

static int
curtain_externalize_label(struct label *label, char *element_name,
    struct sbuf *sb, int *claimed)
{
	struct curtain *ct;
	if (!(ct = SLOT(label)) || strcmp("curtain", element_name) != 0)
		return (0);
	(*claimed)++;
	sbuf_printf(sb, "%ju%s", (uintmax_t)ct->ct_serial,
	    ct->ct_barrier ? "*" : "");
	return (sbuf_error(sb) ? EINVAL : 0);
}


static int
curtain_cred_check_visible(struct ucred *cr1, struct ucred *cr2)
{
	if (!curtain_visible(CRED_SLOT(cr1), CRED_SLOT(cr2), false))
		return (ESRCH);
	return (0);
}

static int
curtain_proc_check_signal(struct ucred *cr, struct proc *p, int signum)
{
	int error;
	if ((error = sysfil_check_cred(cr, SYSFIL_PROC)))
		return (error);
	if (!curtain_visible(CRED_SLOT(cr), CRED_SLOT(p->p_ucred), false))
		return (ESRCH);
	return (0);
}

static int
curtain_proc_check_sched(struct ucred *cr, struct proc *p)
{
	int error;
	if ((error = sysfil_check_cred(cr, SYSFIL_SCHED)))
		return (error);
	if (!curtain_visible(CRED_SLOT(cr), CRED_SLOT(p->p_ucred), false))
		return (ESRCH);
	return (0);
}

static int
curtain_proc_check_debug(struct ucred *cr, struct proc *p)
{
	int error;
	if ((error = sysfil_check_cred(cr, SYSFIL_DEBUG)))
		return (error);
	if (!curtain_visible(CRED_SLOT(cr), CRED_SLOT(p->p_ucred), false))
		return (ESRCH);
	return (0);
}


static int
curtain_socket_check_create(struct ucred *cr, int domain, int type, int protocol)
{
	enum curtain_level lvl;
	lvl = curtain_cred_level(cr, CURTAINTYP_SOCKAF, (ctkey){ .sockaf = domain });
	if (lvl == CURTAINLVL_PASS)
		return (0);
	lvl = MIN(lvl, curtain_cred_sysfil_level(cr, SYSFIL_ANY_SOCKAF));
	if (lvl == CURTAINLVL_PASS)
		return (0);
	CURTAIN_CRED_LOG(cr, lvl, "sockaf %d", domain);
	return (lvl2err[lvl]);
}

static int
curtain_socket_check_connect(struct ucred *cr, struct socket *so, struct label *solabel,
    struct sockaddr *sa)
{
	enum curtain_level lvl;
	int domain;
	domain = sa->sa_family;
	lvl = curtain_cred_level(cr, CURTAINTYP_SOCKAF, (ctkey){ .sockaf = domain });
	if (lvl == CURTAINLVL_PASS)
		return (0);
	lvl = MIN(lvl, curtain_cred_sysfil_level(cr, SYSFIL_ANY_SOCKAF));
	if (lvl == CURTAINLVL_PASS)
		return (0);
	CURTAIN_CRED_LOG(cr, lvl, "sockaf %d", domain);
	return (lvl2err[lvl]);
}

static int
curtain_socket_check_sockopt(struct ucred *cr, struct socket *so, struct label *solabel,
    struct sockopt *sopt)
{
	enum curtain_level lvl;
	int level, name;
	level = sopt->sopt_level;
	name = sopt->sopt_name;
	lvl = curtain_cred_level(cr, CURTAINTYP_SOCKOPT,
	    (ctkey){ .sockopt = { level, name } });
	if (lvl == CURTAINLVL_PASS)
		return (0);
	lvl = MIN(lvl, curtain_cred_level(cr, CURTAINTYP_SOCKLVL,
	    (ctkey){ .socklvl = level }));
	if (lvl == CURTAINLVL_PASS)
		return (0);
	lvl = MIN(lvl, curtain_cred_sysfil_level(cr, SYSFIL_ANY_SOCKOPT));
	if (lvl == CURTAINLVL_PASS)
		return (0);
	CURTAIN_CRED_LOG(cr, lvl, "sockopt %d:%d", level, name);
	return (lvl2err[lvl]);
}


static inline int
unveil_check_uperms(unveil_perms uhave, unveil_perms uneed)
{
	if (!(uneed & ~uhave))
		return (0);
	return (uhave & UPERM_EXPOSE ? EACCES : ENOENT);
}

static inline int
unveil_check_uperms_create(unveil_perms uhave, unveil_perms uneed)
{
	if (!(uneed & ~uhave))
		return (0);
	return (uhave & UPERM_BROWSE ? EACCES : ENOENT);
}

static unveil_perms
get_vp_uperms(struct vnode *vp)
{
	if (unveil_active(curthread))
		return (unveil_ops->tracker_find(curthread, vp));
	return (UPERM_ALL);
}

static int
check_fmode(struct ucred *cr, mode_t mode)
{
	int error;
	if (mode & ~ACCESSPERMS) {
		if ((error = sysfil_check_cred(cr, SYSFIL_CHMOD_SPECIAL)))
			return (error);
	}
	return (0);
}

static int
check_vattr(struct ucred *cr, struct vattr *vap)
{
	int error;
	if (vap->va_mode != (mode_t)VNOVAL &&
	    (error = check_fmode(cr, vap->va_mode)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_open(struct ucred *cr,
    struct vnode *vp, struct label *vplabel, accmode_t accmode)
{
	unveil_perms uperms;
	int error;

	uperms = get_vp_uperms(vp);
	switch (vp->v_type) {
	case VSOCK:
		if ((error = unveil_check_uperms(uperms, UPERM_CONNECT)))
			return (error);
		break;
	case VDIR:
		if (accmode & VREAD &&
		    (error = unveil_check_uperms(uperms, UPERM_BROWSE)))
			return (error);
		if (accmode & VWRITE &&
		    (error = unveil_check_uperms(uperms, UPERM_WRITE)))
			return (error);
		if (accmode & VEXEC &&
		    (error = unveil_check_uperms(uperms, UPERM_SEARCH)))
			return (error);
		break;
	case VREG:
		if (!(uperms & UPERM_TMPDIR_CHILD)) {
	default:	if (accmode & VREAD &&
			    (error = unveil_check_uperms(uperms, UPERM_READ)))
				return (error);
			if (accmode & VWRITE &&
			    (error = unveil_check_uperms(uperms, UPERM_WRITE)))
				return (error);
		}
		if (accmode & VEXEC &&
		    (error = unveil_check_uperms(uperms, UPERM_EXECUTE)))
			return (error);
		break;
	}

	if (vp->v_type == VSOCK) {
		if ((error = sysfil_check_cred(cr, SYSFIL_UNIX)))
			return (error);
	} else {
		if (accmode & VREAD && (error = sysfil_check_cred(cr, SYSFIL_VFS_READ)))
			return (error);
		if (accmode & VWRITE && (error = sysfil_check_cred(cr, SYSFIL_VFS_WRITE)))
			return (error);
		if (accmode & VEXEC) {
			int sf = vp->v_type == VDIR ? SYSFIL_VFS_READ : SYSFIL_EXEC;
			if ((error = sysfil_check_cred(cr, sf)))
				return (error);
		}
	}

	return (0);
}

static int
curtain_vnode_check_read(struct ucred *cr, struct ucred *file_cr,
    struct vnode *vp, struct label *vplabel)
{
	unveil_perms uperms;
	int error;
	if (file_cr)
		return (0);
	uperms = get_vp_uperms(vp);
	if (!(uperms & UPERM_TMPDIR_CHILD && vp->v_type == VREG) &&
	    (error = unveil_check_uperms(uperms, UPERM_READ)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_VFS_READ)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_write(struct ucred *cr, struct ucred *file_cr,
    struct vnode *vp, struct label *vplabel)
{
	unveil_perms uperms;
	int error;
	if (file_cr)
		return (0);
	uperms = get_vp_uperms(vp);
	if (!(uperms & UPERM_TMPDIR_CHILD && vp->v_type == VREG) &&
	    (error = unveil_check_uperms(uperms, UPERM_WRITE)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_VFS_WRITE)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_create(struct ucred *cr,
    struct vnode *dvp, struct label *dvplabel,
    struct componentname *cnp, struct vattr *vap)
{
	unveil_perms uperms;
	int error;

	uperms = get_vp_uperms(dvp);

	if ((error = check_vattr(cr, vap)))
		return (error);

	if (vap->va_type == VSOCK) {
		if ((error = unveil_check_uperms_create(uperms, UPERM_BIND)))
			return (error);
	} else {
		if (!(uperms & UPERM_TMPDIR_CHILD && vap->va_type == VREG) &&
		    (error = unveil_check_uperms_create(uperms, UPERM_CREATE)))
			return (error);
	}

	if (vap->va_type == VSOCK) {
		if ((error = sysfil_check_cred(cr, SYSFIL_UNIX)))
			return (error);
	} else {
		if (vap->va_type == VFIFO) {
			if ((error = sysfil_check_cred(cr, SYSFIL_MKFIFO)))
				return (error);
		}
		if ((error = sysfil_check_cred(cr, SYSFIL_VFS_CREATE)))
			return (error);
	}

	return (0);
}

static int
curtain_vnode_check_link(struct ucred *cr,
    struct vnode *to_dvp, struct label *to_dvplabel,
    struct vnode *from_vp, struct label *from_vplabel,
    struct componentname *to_cnp)
{
	int error;
	/*
	 * Hard-linking a file in a new directory will then allow to access and
	 * alter the file with the permissions of the target directory.  This
	 * could allow both to read files that shouldn't be readable but also
	 * to alter files that are still reachable from the source directory,
	 * which would effectively be like having higher permissions on the
	 * source directory.
	 *
	 * Thus, require all permissions on the source that might allow to
	 * access or alter linked files if they were available on the target.
	 * Also require permissions to create/delete files even though it might
	 * not be strictly required (since directories cannot be hard-linked)
	 * just because hard-links could be dangerous if they are not expected
	 * by programs outside of the sandbox.
	 */
	if ((error = unveil_check_uperms(get_vp_uperms(from_vp),
	    UPERM_READ | UPERM_WRITE | UPERM_SETATTR | UPERM_CREATE | UPERM_DELETE)))
		return (error);
	if ((error = unveil_check_uperms_create(get_vp_uperms(to_dvp), UPERM_CREATE)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_VFS_CREATE)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_unlink(struct ucred *cr,
    struct vnode *dvp, struct label *dvplabel,
    struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{
	unveil_perms uperms;
	int error;

	uperms = get_vp_uperms(vp);

	if (vp->v_type == VSOCK) {
		if ((error = unveil_check_uperms(uperms, UPERM_BIND)))
			return (error);
	} else {
		if (!(uperms & UPERM_TMPDIR_CHILD && vp->v_type == VREG) &&
		    (error = unveil_check_uperms(uperms, UPERM_DELETE)))
			return (error);
	}

	if (vp->v_type == VSOCK) {
		if ((error = sysfil_check_cred(cr, SYSFIL_UNIX)))
			return (error);
	} else {
		if ((error = sysfil_check_cred(cr, SYSFIL_VFS_DELETE)))
			return (error);
	}

	return (0);
}

static int
curtain_vnode_check_rename_from(struct ucred *cr,
    struct vnode *dvp, struct label *dvplabel,
    struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{
	int error;
	/*
	 * To prevent a file with write-only permissions from being moved to a
	 * directory that allows reading, only allow renaming files that
	 * already have read permissions.
	 */
	if ((error = unveil_check_uperms(get_vp_uperms(vp), UPERM_DELETE | UPERM_READ)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_VFS_DELETE)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_rename_to(struct ucred *cr,
    struct vnode *dvp, struct label *dvplabel,
    struct vnode *vp, struct label *vplabel,
    int samedir, struct componentname *cnp)
{
	int error;
	if (vp && (error = unveil_check_uperms(get_vp_uperms(vp), UPERM_DELETE)))
		return (error);
	if ((error = unveil_check_uperms_create(get_vp_uperms(vp ? vp : dvp), UPERM_CREATE)))
		return (error);
	if (vp && (error = sysfil_check_cred(cr, SYSFIL_VFS_DELETE)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_VFS_CREATE)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_chdir(struct ucred *cr, struct vnode *dvp, struct label *dvplabel)
{
	int error;
	if ((error = unveil_check_uperms(get_vp_uperms(dvp), UPERM_SEARCH)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_VFS_READ)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_stat(struct ucred *cr, struct ucred *file_cr,
    struct vnode *vp, struct label *vplabel)
{
	unveil_perms uperms;
	int error;
	if (file_cr)
		return (0);
	uperms = get_vp_uperms(vp);
	if (!(uperms & UPERM_TMPDIR_CHILD && vp->v_type == VREG) &&
	    (error = unveil_check_uperms(uperms, UPERM_STATUS)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_VFS_READ)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_lookup(struct ucred *cr,
    struct vnode *dvp, struct label *dvplabel, struct componentname *cnp)
{
	int error;
	if ((error = unveil_check_uperms(get_vp_uperms(dvp), UPERM_TRAVERSE)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_VFS_MISC)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_readlink(struct ucred *cr, struct vnode *vp, struct label *vplabel)
{
	int error;
	if ((error = unveil_check_uperms(get_vp_uperms(vp), UPERM_TRAVERSE)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_VFS_MISC)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_setflags(struct ucred *cr,
    struct vnode *vp, struct label *vplabel, u_long flags)
{
	int error;
	if ((error = unveil_check_uperms(get_vp_uperms(vp), UPERM_SETATTR)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_FATTR)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_setmode(struct ucred *cr,
    struct vnode *vp, struct label *vplabel, mode_t mode)
{
	int error;
	if ((error = check_fmode(cr, mode)))
		return (error);
	if ((error = unveil_check_uperms(get_vp_uperms(vp), UPERM_SETATTR)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_FATTR)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_setowner(struct ucred *cr,
    struct vnode *vp, struct label *vplabel, uid_t uid, gid_t gid)
{
	int error;
	if ((error = unveil_check_uperms(get_vp_uperms(vp), UPERM_SETATTR)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_FATTR)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_setutimes(struct ucred *cr,
    struct vnode *vp, struct label *vplabel,
    struct timespec atime, struct timespec mtime)
{
	int error;
	if ((error = unveil_check_uperms(get_vp_uperms(vp), UPERM_SETATTR)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_FATTR)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_listextattr(struct ucred *cr,
    struct vnode *vp, struct label *vplabel, int attrnamespace)
{
	int error;
	if ((error = unveil_check_uperms(get_vp_uperms(vp), UPERM_READ)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_EXTATTR)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_VFS_READ)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_getextattr(struct ucred *cr,
    struct vnode *vp, struct label *vplabel, int attrnamespace, const char *name)
{
	int error;
	if ((error = unveil_check_uperms(get_vp_uperms(vp), UPERM_READ)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_EXTATTR)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_VFS_READ)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_setextattr(struct ucred *cr,
    struct vnode *vp, struct label *vplabel, int attrnamespace, const char *name)
{
	int error;
	if ((error = unveil_check_uperms(get_vp_uperms(vp), UPERM_SETATTR)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_EXTATTR)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_FATTR)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_deleteextattr(struct ucred *cr,
    struct vnode *vp, struct label *vplabel, int attrnamespace, const char *name)
{
	int error;
	if ((error = unveil_check_uperms(get_vp_uperms(vp), UPERM_SETATTR)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_EXTATTR)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_FATTR)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_getacl(struct ucred *cr,
    struct vnode *vp, struct label *vplabel, acl_type_t type)
{
	int error;
	if ((error = unveil_check_uperms(get_vp_uperms(vp), UPERM_READ)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_ACL)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_VFS_READ)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_setacl(struct ucred *cr,
    struct vnode *vp, struct label *vplabel, acl_type_t type, struct acl *acl)
{
	int error;
	if ((error = unveil_check_uperms(get_vp_uperms(vp), UPERM_SETATTR)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_ACL)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_FATTR)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_deleteacl(struct ucred *cr,
    struct vnode *vp, struct label *vplabel, acl_type_t type)
{
	int error;
	if ((error = unveil_check_uperms(get_vp_uperms(vp), UPERM_SETATTR)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_ACL)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_FATTR)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_relabel(struct ucred *cr,
    struct vnode *vp, struct label *vplabel, struct label *newlabel)
{
	int error;
	if ((error = unveil_check_uperms(get_vp_uperms(vp), UPERM_SETATTR)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_MAC)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_FATTR)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_revoke(struct ucred *cr, struct vnode *vp, struct label *vplabel)
{
	int error;
	if ((error = unveil_check_uperms(get_vp_uperms(vp), UPERM_SETATTR)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_TTY)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_exec(struct ucred *cr,
    struct vnode *vp, struct label *vplabel,
    struct image_params *imgp, struct label *execlabel)
{
	int error;
	if ((error = unveil_check_uperms(get_vp_uperms(vp), UPERM_EXECUTE)))
		return (error);
	if ((error = sysfil_check_cred(cr, SYSFIL_EXEC)))
		return (error);
	return (0);
}


static void curtain_posixshm_create(struct ucred *cr,
    struct shmfd *shmfd, struct label *shmlabel)
{
	curtain_copy_label(cr->cr_label, shmlabel);
}

static int
curtain_posixshm_check_open(struct ucred *cr,
    struct shmfd *shmfd, struct label *shmlabel,
    accmode_t accmode)
{
	if (!curtain_visible(CRED_SLOT(cr), SLOT(shmlabel), false))
		return (ENOENT);
	return (0);
}

static int
curtain_posixshm_check_unlink(struct ucred *cr,
    struct shmfd *shmfd, struct label *shmlabel)
{
	if (!curtain_visible(CRED_SLOT(cr), SLOT(shmlabel), false))
		return (ENOENT);
	return (0);
}


static void curtain_posixsem_create(struct ucred *cr,
    struct ksem *sem, struct label *semlabel)
{
	curtain_copy_label(cr->cr_label, semlabel);
}

static int
curtain_posixsem_check_open_unlink(struct ucred *cr,
    struct ksem *sem, struct label *semlabel)
{
	if (!curtain_visible(CRED_SLOT(cr), SLOT(semlabel), false))
		return (ENOENT);
	return (0);
}


static void
curtain_sysvshm_create(struct ucred *cr,
    struct shmid_kernel *shm, struct label *shmlabel)
{
	curtain_copy_label(cr->cr_label, shmlabel);
}

static int
curtain_sysvshm_check_something(struct ucred *cr,
    struct shmid_kernel *shm, struct label *shmlabel, int something)
{
	if (!curtain_visible(CRED_SLOT(cr), SLOT(shmlabel), false))
		return (ENOENT);
	return (0);
}



static void
curtain_sysvsem_create(struct ucred *cr,
    struct semid_kernel *sem, struct label *semlabel)
{
	curtain_copy_label(cr->cr_label, semlabel);
}

static int
curtain_sysvsem_check_semctl(struct ucred *cr,
    struct semid_kernel *sem, struct label *semlabel,
    int cmd)
{
	if (!curtain_visible(CRED_SLOT(cr), SLOT(semlabel), false))
		return (ENOENT);
	return (0);
}

static int
curtain_sysvsem_check_semget(struct ucred *cr,
    struct semid_kernel *sem, struct label *semlabel)
{
	if (!curtain_visible(CRED_SLOT(cr), SLOT(semlabel), false))
		return (ENOENT);
	return (0);
}

static int
curtain_sysvsem_check_semop(struct ucred *cr,
    struct semid_kernel *sem, struct label *semlabel,
    size_t accesstype)
{
	if (!curtain_visible(CRED_SLOT(cr), SLOT(semlabel), false))
		return (ENOENT);
	return (0);
}


static void
curtain_sysvmsq_create(struct ucred *cr,
    struct msqid_kernel *msq, struct label *msqlabel)
{
	curtain_copy_label(cr->cr_label, msqlabel);
}

static int
curtain_sysvmsq_check_1(struct ucred *cr,
    struct msqid_kernel *msq, struct label *msqlabel)
{
	if (!curtain_visible(CRED_SLOT(cr), SLOT(msqlabel), false))
		return (ENOENT);
	return (0);
}

static int
curtain_sysvmsq_check_2(struct ucred *cr,
    struct msqid_kernel *msq, struct label *msqlabel, int something)
{
	if (!curtain_visible(CRED_SLOT(cr), SLOT(msqlabel), false))
		return (ENOENT);
	return (0);
}


static int
curtain_generic_ipc_name_prefix(struct ucred *cr, char **prefix, char *end)
{
	if (sysfil_probe_cred(cr, SYSFIL_NOTMPIPC) != 0) {
		struct curtain *ct;
		size_t n, m;
		m = end - *prefix;
		ct = CRED_SLOT(cr);
		while (ct && !ct->ct_barrier)
			ct = ct->ct_parent;
		if (ct) {
			ssize_t r;
			r = snprintf(*prefix, m,
			    "/curtain/%ju", (uintmax_t)ct->ct_serial);
			n = r > 0 ? r : 0;
		} else
			n = strlcpy(*prefix, "/curtain/tmp", m);
		if (n >= m)
			return (ENAMETOOLONG);
		*prefix += n;
	}
	return (0);
}

static int
curtain_generic_check_ioctl(struct ucred *cr, struct file *fp, u_long com, void *data)
{
	enum curtain_level lvl;
	int sf;
	lvl = curtain_cred_level(cr, CURTAINTYP_IOCTL, (ctkey){ .ioctl = com });
	if (lvl == CURTAINLVL_PASS)
		return (0);
	switch (com) {
	case FIOCLEX:
	case FIONCLEX:
	case FIONREAD:
	case FIONWRITE:
	case FIONSPACE:
	case FIONBIO:
	case FIOASYNC:
	case FIOGETOWN:
	case FIODTYPE:
		/* always allowed ioctls */
		sf = SYSFIL_ALWAYS;
		break;
	case TIOCGETA:
		/* needed for isatty(3) */
		sf = SYSFIL_STDIO;
		break;
	case FIOSETOWN:
		/* also checked in setown() */
		sf = SYSFIL_PROC;
		break;
	default:
		sf = SYSFIL_ANY_IOCTL;
		break;
	}
	if (sf != SYSFIL_ANY_IOCTL) {
		lvl = MIN(lvl, curtain_cred_sysfil_level(cr, sf));
		if (lvl == CURTAINLVL_PASS)
			return (0);
		sf = SYSFIL_ANY_IOCTL;
	}
	lvl = MIN(lvl, curtain_cred_sysfil_level(cr, sf));
	if (lvl == CURTAINLVL_PASS)
		return (0);
	CURTAIN_CRED_LOG(cr, lvl, "ioctl %#jx", (uintmax_t)com);
	return (lvl2err[lvl]);
}

static int
curtain_generic_check_vm_prot(struct ucred *cr, struct file *fp, vm_prot_t prot)
{
	if (prot & VM_PROT_EXECUTE) {
		bool loose = fp && fp->f_ops == &vnops;
		return (sysfil_check_cred(cr, loose && !(prot & VM_PROT_WRITE) ?
		    SYSFIL_PROT_EXEC_LOOSE : SYSFIL_PROT_EXEC));
	}
	return (0);
}


static int
curtain_system_check_sysctl(struct ucred *cr,
    struct sysctl_oid *oidp, void *arg1, int arg2,
    struct sysctl_req *req)
{
	if (oidp->oid_kind & (CTLFLAG_RESTRICT|CTLFLAG_CAPRW))
		return (0);
	if (CRED_SLOT(cr))
		do {
			const struct curtain_item *item;
			item = curtain_lookup(CRED_SLOT(cr), CURTAINTYP_SYSCTL,
			    (ctkey){ .sysctl = { .serial = oidp->oid_serial } });
			if (item && item->mode.on_self == CURTAINLVL_PASS)
				return (0);
		} while ((oidp = SYSCTL_PARENT(oidp))); /* XXX locking */
	/* TODO handle levels here too */
	return (sysfil_probe_cred(cr, sysfil_for_type(CURTAINTYP_SYSCTL)));
}


static int
curtain_priv_check(struct ucred *cr, int priv)
{
	enum curtain_level lvl;
	int sf;
	lvl = curtain_cred_level(cr, CURTAINTYP_PRIV, (ctkey){ .priv = priv });
	if (lvl == CURTAINLVL_PASS)
		return (0);
	/*
	 * Mostly a subset of what's being allowed for jails (see
	 * prison_priv_check()) with some extra conditions based on sysfils.
	 */
	switch (priv) {
	case PRIV_AUDIT_CONTROL:
	case PRIV_AUDIT_FAILSTOP:
	case PRIV_AUDIT_GETAUDIT:
	case PRIV_AUDIT_SETAUDIT:
	case PRIV_AUDIT_SUBMIT:
		sf = SYSFIL_AUDIT;
		break;
	case PRIV_CRED_SETUID:
	case PRIV_CRED_SETEUID:
	case PRIV_CRED_SETGID:
	case PRIV_CRED_SETEGID:
	case PRIV_CRED_SETGROUPS:
	case PRIV_CRED_SETREUID:
	case PRIV_CRED_SETREGID:
	case PRIV_CRED_SETRESUID:
	case PRIV_CRED_SETRESGID:
	case PRIV_PROC_SETLOGIN:
	case PRIV_PROC_SETLOGINCLASS:
		sf = SYSFIL_ID;
		break;
	case PRIV_SEEOTHERGIDS:
	case PRIV_SEEOTHERUIDS:
		sf = SYSFIL_PS;
		break;
	case PRIV_DEBUG_DIFFCRED:
	case PRIV_DEBUG_SUGID:
	case PRIV_DEBUG_UNPRIV:
		sf = SYSFIL_DEBUG;
		break;
	case PRIV_PROC_LIMIT:
	case PRIV_PROC_SETRLIMIT:
		sf = SYSFIL_RLIMIT;
		break;
	case PRIV_JAIL_ATTACH:
	case PRIV_JAIL_SET:
	case PRIV_JAIL_REMOVE:
		sf = SYSFIL_JAIL;
		break;
	case PRIV_VFS_READ:
	case PRIV_VFS_WRITE:
	case PRIV_VFS_ADMIN:
	case PRIV_VFS_EXEC:
	case PRIV_VFS_LOOKUP:
	case PRIV_VFS_BLOCKRESERVE:	/* XXXRW: Slightly surprising. */
	case PRIV_VFS_CHFLAGS_DEV:
	case PRIV_VFS_LINK:
	case PRIV_VFS_STAT:
	case PRIV_VFS_STICKYFILE:
		sf = SYSFIL_VFS_MISC;
		break;
	case PRIV_VFS_SYSFLAGS:
#if 0
	case PRIV_VFS_EXTATTR_SYSTEM:
#endif
		sf = SYSFIL_SYSFLAGS;
		break;
	case PRIV_VFS_READ_DIR:
		/* Let other policies handle this (like is done for jails). */
		sf = SYSFIL_VFS_MISC;
		break;
	case PRIV_VFS_CHOWN:
	case PRIV_VFS_SETGID:
	case PRIV_VFS_RETAINSUGID:
		sf = SYSFIL_CHOWN;
		break;
	case PRIV_VFS_CHROOT:
	case PRIV_VFS_FCHROOT:
		sf = SYSFIL_CHROOT;
		break;
	case PRIV_VFS_MKNOD_DEV:
		sf = SYSFIL_MAKEDEV;
		break;
	case PRIV_VM_MLOCK:
	case PRIV_VM_MUNLOCK:
		sf = SYSFIL_MLOCK;
		break;
	case PRIV_NETINET_RESERVEDPORT:
#if 0
	case PRIV_NETINET_REUSEPORT:
	case PRIV_NETINET_SETHDROPTS:
#endif
		sf = SYSFIL_NET;
		break;
#if 0
	case PRIV_NETINET_GETCRED:
		sf = SYSFIL_NET;
		break;
#endif
	case PRIV_ADJTIME:
	case PRIV_NTP_ADJTIME:
	case PRIV_CLOCK_SETTIME:
		sf = SYSFIL_SETTIME;
		break;
	case PRIV_VFS_GETFH:
	case PRIV_VFS_FHOPEN:
	case PRIV_VFS_FHSTAT:
	case PRIV_VFS_FHSTATFS:
	case PRIV_VFS_GENERATION:
		sf = SYSFIL_FH;
		break;
	default:
		sf = SYSFIL_ANY_PRIV;
		break;
	}
	if (sf != SYSFIL_ANY_PRIV) {
		lvl = MIN(lvl, curtain_cred_sysfil_level(cr, sf));
		if (lvl == CURTAINLVL_PASS)
			return (0);
		sf = SYSFIL_ANY_PRIV;
	}
	lvl = MIN(lvl, curtain_cred_sysfil_level(cr, sf));
	if (lvl == CURTAINLVL_PASS)
		return (0);
	/*
	 * Some priv_check()/priv_check_cred() callers just compare the error
	 * value against 0 without returning it.  Some privileges are checked
	 * in this way so often that it shouldn't be logged.
	 */
	switch (priv) {
	case PRIV_VFS_GENERATION:
		break;
	default:
		CURTAIN_CRED_LOG(cr, lvl, "priv %d", priv);
		break;
	}
	return (lvl2err[lvl]);
}

static int
curtain_sysfil_check(struct ucred *cr, int sf)
{
	enum curtain_level lvl;
	lvl = curtain_cred_sysfil_level(cr, sf);
	if (lvl == CURTAINLVL_PASS)
		return (0);
	CURTAIN_CRED_LOG(cr, lvl, "sysfil %d", sf);
	return (lvl2err[lvl]);
}

static bool
curtain_sysfil_exec_restricted(struct thread *td, struct ucred *cr)
{
	const struct curtain *ct;
	if ((ct = CRED_SLOT(cr))) {
		if (ct->ct_cache_valid ? ct->ct_cached.is_restricted_on_exec
	                               : curtain_is_restricted_on_exec(ct))
			return (true);
	} else {
		if (CRED_IN_RESTRICTED_MODE(cr))
			return (true);
	}
	return (false);
}

static bool
curtain_sysfil_need_exec_adjust(struct thread *td, struct ucred *cr)
{
	const struct curtain *ct;
	if ((ct = CRED_SLOT(cr))) {
		if (ct->ct_cache_valid ? ct->ct_cached.need_exec_switch
		                       : curtain_need_exec_switch(ct))
			return (true);
	}
	if (unveil_proc_need_exec_switch(td->td_proc))
		return (true);
	return (false);
}

static void
curtain_sysfil_exec_adjust(struct thread *td, struct ucred *cr)
{
	struct curtain *ct;
	if (!(ct = CRED_SLOT(cr)))
		return;
	curtain_cred_exec_switch(cr);
	if (ct->ct_cache_valid ? ct->ct_cached.is_restricted_on_exec
	                       : curtain_is_restricted_on_exec(ct))
		unveil_proc_exec_switch(td->td_proc);
	else
		unveil_proc_drop_base(td->td_proc);
}

static int curtain_sysfil_update_mask(struct ucred *cr, const sysfilset_t *mask_sfs)
{
	struct curtain *ct;
	if (!CRED_SLOT(cr))
		return (0);
	ct = curtain_dup_child(CRED_SLOT(cr));
	curtain_mask_sysfils(ct, mask_sfs);
	curtain_free(CRED_SLOT(cr));
	SLOT_SET(cr->cr_label, ct);
	return (0);
}


static struct mac_policy_ops curtain_policy_ops = {
	.mpo_cred_init_label = curtain_init_label,
	.mpo_cred_copy_label = curtain_copy_label,
	.mpo_cred_destroy_label = curtain_destroy_label,
	.mpo_cred_externalize_label = curtain_externalize_label,
	.mpo_cred_check_visible = curtain_cred_check_visible,

	.mpo_proc_check_signal = curtain_proc_check_signal,
	.mpo_proc_check_sched = curtain_proc_check_sched,
	.mpo_proc_check_debug = curtain_proc_check_debug,

	.mpo_socket_check_create = curtain_socket_check_create,
	.mpo_socket_check_connect = curtain_socket_check_connect,
	.mpo_socket_check_setsockopt = curtain_socket_check_sockopt,
	.mpo_socket_check_getsockopt = curtain_socket_check_sockopt,

	.mpo_vnode_check_access = curtain_vnode_check_open,
	.mpo_vnode_check_open = curtain_vnode_check_open,
	.mpo_vnode_check_read = curtain_vnode_check_read,
	.mpo_vnode_check_write = curtain_vnode_check_write,
	.mpo_vnode_check_create = curtain_vnode_check_create,
	.mpo_vnode_check_link = curtain_vnode_check_link,
	.mpo_vnode_check_unlink = curtain_vnode_check_unlink,
	.mpo_vnode_check_rename_from = curtain_vnode_check_rename_from,
	.mpo_vnode_check_rename_to = curtain_vnode_check_rename_to,
	.mpo_vnode_check_chdir = curtain_vnode_check_chdir,
	.mpo_vnode_check_chroot = curtain_vnode_check_chdir,
	.mpo_vnode_check_stat = curtain_vnode_check_stat,
	.mpo_vnode_check_setflags = curtain_vnode_check_setflags,
	.mpo_vnode_check_setmode = curtain_vnode_check_setmode,
	.mpo_vnode_check_setowner = curtain_vnode_check_setowner,
	.mpo_vnode_check_setutimes = curtain_vnode_check_setutimes,
	.mpo_vnode_check_lookup = curtain_vnode_check_lookup,
	.mpo_vnode_check_readlink = curtain_vnode_check_readlink,
	.mpo_vnode_check_listextattr = curtain_vnode_check_listextattr,
	.mpo_vnode_check_getextattr = curtain_vnode_check_getextattr,
	.mpo_vnode_check_setextattr = curtain_vnode_check_setextattr,
	.mpo_vnode_check_deleteextattr = curtain_vnode_check_deleteextattr,
	.mpo_vnode_check_getacl = curtain_vnode_check_getacl,
	.mpo_vnode_check_setacl = curtain_vnode_check_setacl,
	.mpo_vnode_check_deleteacl = curtain_vnode_check_deleteacl,
	.mpo_vnode_check_relabel = curtain_vnode_check_relabel,
	.mpo_vnode_check_exec = curtain_vnode_check_exec,
	.mpo_vnode_check_revoke = curtain_vnode_check_revoke,

	.mpo_posixshm_init_label = curtain_init_label,
	.mpo_posixshm_destroy_label = curtain_destroy_label,
	.mpo_posixshm_create = curtain_posixshm_create,
	.mpo_posixshm_check_open = curtain_posixshm_check_open,
	.mpo_posixshm_check_unlink = curtain_posixshm_check_unlink,

	.mpo_posixsem_init_label = curtain_init_label,
	.mpo_posixsem_destroy_label = curtain_destroy_label,
	.mpo_posixsem_create = curtain_posixsem_create,
	.mpo_posixsem_check_open = curtain_posixsem_check_open_unlink,
	.mpo_posixsem_check_unlink = curtain_posixsem_check_open_unlink,

	.mpo_sysvshm_init_label = curtain_init_label,
	.mpo_sysvshm_cleanup = curtain_destroy_label,
	.mpo_sysvshm_destroy_label = curtain_destroy_label,
	.mpo_sysvshm_create = curtain_sysvshm_create,
	.mpo_sysvshm_check_shmat = curtain_sysvshm_check_something,
	.mpo_sysvshm_check_shmctl = curtain_sysvshm_check_something,
	.mpo_sysvshm_check_shmget = curtain_sysvshm_check_something,

	.mpo_sysvsem_init_label = curtain_init_label,
	.mpo_sysvsem_cleanup = curtain_destroy_label,
	.mpo_sysvsem_destroy_label = curtain_destroy_label,
	.mpo_sysvsem_create = curtain_sysvsem_create,
	.mpo_sysvsem_check_semctl = curtain_sysvsem_check_semctl,
	.mpo_sysvsem_check_semget = curtain_sysvsem_check_semget,
	.mpo_sysvsem_check_semop = curtain_sysvsem_check_semop,

	.mpo_sysvmsq_init_label = curtain_init_label,
	.mpo_sysvmsq_cleanup = curtain_destroy_label,
	.mpo_sysvmsq_destroy_label = curtain_destroy_label,
	.mpo_sysvmsq_create = curtain_sysvmsq_create,
	.mpo_sysvmsq_check_msqctl = curtain_sysvmsq_check_2,
	.mpo_sysvmsq_check_msqget = curtain_sysvmsq_check_1,
	.mpo_sysvmsq_check_msqrcv = curtain_sysvmsq_check_1,
	.mpo_sysvmsq_check_msqsnd = curtain_sysvmsq_check_1,

	.mpo_generic_ipc_name_prefix = curtain_generic_ipc_name_prefix,
	.mpo_generic_check_ioctl = curtain_generic_check_ioctl,
	.mpo_generic_check_vm_prot = curtain_generic_check_vm_prot,

	.mpo_system_check_sysctl = curtain_system_check_sysctl,

	.mpo_priv_check = curtain_priv_check,

	.mpo_sysfil_check = curtain_sysfil_check,
	.mpo_sysfil_exec_restricted = curtain_sysfil_exec_restricted,
	.mpo_sysfil_need_exec_adjust = curtain_sysfil_need_exec_adjust,
	.mpo_sysfil_exec_adjust = curtain_sysfil_exec_adjust,
	.mpo_sysfil_update_mask = curtain_sysfil_update_mask,
};


static struct syscall_helper_data curtain_syscalls[] = {
	SYSCALL_INIT_HELPER(curtainctl),
	SYSCALL_INIT_LAST,
};

static void
curtain_sysinit(void *arg)
{
	int error;
	rw_init(&curtain_tree_lock, "curtain_tree");
	error = syscall_helper_register(curtain_syscalls,
	    SY_THR_STATIC_KLD | SY_HLP_PRESERVE_SYFLAGS);
	if (error)
		printf("%s: syscall_helper_register error %d\n", __FUNCTION__, error);
}

static void
curtain_sysuninit(void *arg __unused)
{
	syscall_helper_unregister(curtain_syscalls);
	rw_destroy(&curtain_tree_lock);
}

SYSINIT(curtain_sysinit, SI_SUB_MAC_POLICY, SI_ORDER_ANY, curtain_sysinit, NULL);
SYSUNINIT(curtain_sysuninit, SI_SUB_MAC_POLICY, SI_ORDER_ANY, curtain_sysuninit, NULL);

MAC_POLICY_SET(&curtain_policy_ops, mac_curtain, "MAC/curtain", 0, &curtain_slot);
