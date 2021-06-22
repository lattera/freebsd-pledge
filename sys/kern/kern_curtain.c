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
#include <sys/conf.h>
#include <sys/sysfil.h>
#include <sys/unveil.h>
#include <sys/curtain.h>

#include <sys/filio.h>
#include <sys/tty.h>

static MALLOC_DEFINE(M_CURTAIN, "curtain", "curtain restrictions");

SDT_PROVIDER_DEFINE(curtain);
SDT_PROBE_DEFINE3(curtain,, curtain_build, begin,
    "int", "size_t", "const struct curtainreq *");
SDT_PROBE_DEFINE1(curtain,, curtain_build, harden, "struct curtain *");
SDT_PROBE_DEFINE1(curtain,, curtain_build, done, "struct curtain *");
SDT_PROBE_DEFINE0(curtain,, curtain_build, failed);
SDT_PROBE_DEFINE1(curtain,, do_curtainctl, limit, "struct curtain *");
SDT_PROBE_DEFINE1(curtain,, do_curtainctl, compact, "struct curtain *");
SDT_PROBE_DEFINE1(curtain,, do_curtainctl, assign, "struct curtain *");


static bool __read_mostly sysfil_enabled = true;
static unsigned __read_mostly sysfil_violation_log_level = 1;

SYSCTL_NODE(_security, OID_AUTO, curtain,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "Curtain");

SYSCTL_BOOL(_security_curtain, OID_AUTO, enabled,
    CTLFLAG_RW, &sysfil_enabled, 0,
    "Allow curtainctl(2) usage");

SYSCTL_UINT(_security_curtain, OID_AUTO, log_sysfil_violation,
    CTLFLAG_RW, &sysfil_violation_log_level, 0,
    "Log violations of sysfil restrictions");

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

#endif

CTASSERT(CURTAINCTL_MAX_ITEMS <= (curtain_index)-1);

#ifdef SYSFIL

static void
curtain_init(struct curtain *ct, size_t nslots)
{
	if (!powerof2(nslots) || nslots != (curtain_index)nslots)
		panic("invalid curtain nslots %zu", nslots);
	/* NOTE: zeroization leads to all levels being set to CURTAINLVL_PASS */
	*ct = (struct curtain){
		.ct_ref = 1,
		.ct_nitems = 0,
		.ct_nslots = nslots,
		.ct_fill = 0,
	};
	for (curtain_index i = 0; i < nslots; i++)
		ct->ct_slots[i].type = 0;
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
	for (nslots = nitems != 0; nslots != 0 && nslots < nitems; nslots <<= 1);
	if (nslots < nitems)
		return (NULL);
	ct = curtain_alloc(nslots);
	curtain_init(ct, nslots);
	return (ct);
}

void
curtain_hold(struct curtain *ct)
{
	refcount_acquire(&ct->ct_ref);
}

void
curtain_free(struct curtain *ct)
{
	if (refcount_release(&ct->ct_ref))
		free(ct, M_CURTAIN);
}

static void
curtain_copy(struct curtain *dst, const struct curtain *src)
{
	memcpy(dst, src, sizeof *src + src->ct_nslots * sizeof *src->ct_slots);
	dst->ct_ref = 1;
}

static struct curtain *
curtain_dup(const struct curtain *src)
{
	struct curtain *dst;
	dst = curtain_alloc(src->ct_nslots);
	curtain_copy(dst, src);
	return (dst);
}

bool
curtain_cred_need_exec_switch(const struct ucred *cr)
{
	struct curtain *ct = cr->cr_curtain;
	struct curtain_item *item;
	if (!ct)
		return (false);
	for (int sf = 0; sf <= SYSFIL_LAST; sf++)
		if (ct->ct_sysfils[sf].on_self != ct->ct_sysfils[sf].on_exec ||
		    ct->ct_sysfils[sf].on_self_max != ct->ct_sysfils[sf].on_exec_max)
			return (true);
	for (item = ct->ct_slots; item < &ct->ct_slots[ct->ct_nslots]; item++)
		if (item->type != 0 &&
		    (item->mode.on_self != item->mode.on_exec ||
		     item->mode.on_self_max != item->mode.on_exec_max))
			return (true);
	return (false);
}

bool
curtain_cred_exec_restricted(const struct ucred *cr)
{
	struct curtain *ct = cr->cr_curtain;
	struct curtain_item *item;
	if (!ct)
		return (false);
	for (int sf = 0; sf <= SYSFIL_LAST; sf++)
		if (ct->ct_sysfils[sf].on_exec != CURTAINLVL_PASS ||
		    ct->ct_sysfils[sf].on_exec_max != CURTAINLVL_PASS)
			return (true);
	for (item = ct->ct_slots; item < &ct->ct_slots[ct->ct_nslots]; item++)
		if (item->type != 0 &&
		    (item->mode.on_exec != CURTAINLVL_PASS ||
		     item->mode.on_exec_max != CURTAINLVL_PASS))
			return (true);
	return (false);
}

void
curtain_cred_exec_switch(struct ucred *cr)
{
	struct curtain_item *item;
	struct curtain *ct;
	KASSERT(cr->cr_ref == 1, ("modifying shared ucred"));
	if (!(ct = cr->cr_curtain))
		return; /* NOTE: sysfilset kept as-is */

	if (!curtain_cred_exec_restricted(cr)) {
		curtain_free(ct);
		sysfil_cred_init(cr);
		return;
	}

	ct = curtain_dup(ct);
	BIT_ZERO(SYSFILSET_BITS, &cr->cr_sysfilset);
	for (int sf = 0; sf <= SYSFIL_LAST; sf++) {
		ct->ct_sysfils[sf].on_self     = ct->ct_sysfils[sf].on_exec;
		ct->ct_sysfils[sf].on_self_max = ct->ct_sysfils[sf].on_exec_max;
		if (ct->ct_sysfils[sf].on_self == CURTAINLVL_PASS)
			BIT_SET(SYSFILSET_BITS, sf, &cr->cr_sysfilset);
	}
	MPASS(SYSFILSET_IS_RESTRICTED(&cr->cr_sysfilset));
	for (item = ct->ct_slots; item < &ct->ct_slots[ct->ct_nslots]; item++)
		if (item->type != 0) {
			item->mode.on_self     = item->mode.on_exec;
			item->mode.on_self_max = item->mode.on_exec_max;
		}

	curtain_free(cr->cr_curtain);
	cr->cr_curtain = ct;
	MPASS(CRED_IN_RESTRICTED_MODE(cr));
}

bool
curtain_device_unveil_bypass(struct thread *td, struct cdev *dev)
{
	return (td->td_ucred == dev->si_cred &&
	        dev->si_devsw->d_flags & D_TTY &&
	        sysfil_check(td, SYSFIL_TTY) == 0);
}


static inline void
mode_set(struct curtain_mode *mode, enum curtain_level lvl)
{
	mode->on_self = mode->on_exec = lvl;
	mode->on_self_max = mode->on_exec_max = lvl;
}

static inline void
mode_limit(struct curtain_mode *dst, const struct curtain_mode *src)
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
	mode_limit(mode, &cap);
}

static inline void
mode_harden(struct curtain_mode *mode)
{
	mode->on_self = mode->on_self_max = MAX(mode->on_self, mode->on_self_max);
	mode->on_exec = mode->on_exec_max = MAX(mode->on_exec, mode->on_exec_max);
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
		return ((unsigned)key.ioctl);
	case CURTAINTYP_SOCKAF:
		return ((unsigned)key.sockaf);
	case CURTAINTYP_SOCKLVL:
		return ((unsigned)key.socklvl);
	case CURTAINTYP_SOCKOPT:
		return ((unsigned)(key.sockopt.level ^ key.sockopt.optname));
	case CURTAINTYP_PRIV:
		return ((unsigned)key.priv);
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
	}
	MPASS(0);
	return (false);
}

static inline struct curtain_item *
curtain_hash_head(struct curtain *ct, unsigned key_hash)
{
	if (ct->ct_nslots == 0)
		return (NULL);
	return (&ct->ct_slots[key_hash & (ct->ct_nslots - 1)]);
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
		if (!item) {
			struct curtain_item *fill;
			while (ct->ct_fill < ct->ct_nslots)
				if ((fill = &ct->ct_slots[ct->ct_fill++])->type == 0) {
					item = fill;
					break;
				}
		}
	} else
		prev = NULL;
	if (!item) {
		ct->ct_overflowed = true;
	} else if (item->type == 0) {
		ct->ct_nitems++;
		item->type = type;
		item->key = key;
		curtain_hash_init(ct, item);
		if (prev)
			curtain_hash_link(ct, prev, item);
		mode_set(&item->mode, CURTAINLVL_PASS);
	}
	return (item);
}

static struct curtain *
curtain_dup_compact(const struct curtain *src)
{
	struct curtain_item *di;
	const struct curtain_item *si;
	struct curtain *dst;
	dst = curtain_make(src->ct_nitems);
	dst->ct_overflowed = src->ct_overflowed;
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
	return (dst);
}

static void
curtain_compact(struct curtain **old)
{
	struct curtain *new;
	new = curtain_dup_compact(*old);
	curtain_free(*old);
	*old = new;
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
	}
	MPASS(0);
	return (SYSFIL_DEFAULT);
}

static int
curtain_check_cred(const struct ucred *cr, enum curtain_type type, union curtain_key key)
{
	const struct curtain *ct;
	/* TODO: handle level */
	if ((ct = cr->cr_curtain)) {
		const struct curtain_item *item;
		item = curtain_lookup(ct, type, key);
		if (item && item->mode.on_self == CURTAINLVL_PASS)
			return (0);
	}
	return (sysfil_check_cred(cr, sysfil_for_type(type)));
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
curtain_limit_sysfils(struct curtain *ct, const sysfilset_t *sfs)
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
}

static void
curtain_limit_item(struct curtain_mode *mode,
    enum curtain_type type, union curtain_key key, const struct curtain *ct)
{
	const struct curtain_item *item;
	item = curtain_lookup(ct, type, key);
	if (!item && type == CURTAINTYP_SOCKOPT)
		item = curtain_lookup(ct, CURTAINTYP_SOCKLVL,
		    (union curtain_key){ .socklvl = key.sockopt.level });
	mode_limit(mode, item ? &item->mode :
	    &ct->ct_sysfils[sysfil_for_type(type)]);
}

static void
curtain_limit(struct curtain *dst, const struct curtain *src)
{
	struct curtain_item *di;
	const struct curtain_item *si;
	KASSERT(dst->ct_ref == 1, ("modifying shared curtain"));
	for (si = src->ct_slots; si < &src->ct_slots[src->ct_nslots]; si++)
		if (si->type != 0 && !curtain_lookup(dst, si->type, si->key)) {
			struct curtain_mode mode = si->mode;
			curtain_limit_item(&mode, si->type, si->key, dst);
			di = curtain_search(dst, si->type, si->key);
			if (di)
				di->mode = mode;
		}
	for (di = dst->ct_slots; di < &dst->ct_slots[dst->ct_nslots]; di++)
		if (di->type != 0)
			curtain_limit_item(&di->mode, di->type, di->key, src);
	for (int sf = 0; sf <= SYSFIL_LAST; sf++)
		mode_limit(&dst->ct_sysfils[sf], &src->ct_sysfils[sf]);
}

/* Some sysfils shouldn't be disabled via curtainctl(2). */
static const int sysfils_always[] = { SYSFIL_ALWAYS, SYSFIL_UNCAPSICUM };
/* Some sysfils don't make much sense without some others. */
static const int sysfils_expand[][2] = {
	{ SYSFIL_RPATH,		SYSFIL_PATH		},
	{ SYSFIL_WPATH,		SYSFIL_PATH		},
	{ SYSFIL_CPATH,		SYSFIL_PATH		},
	{ SYSFIL_DPATH,		SYSFIL_PATH		},
	{ SYSFIL_PROT_EXEC,	SYSFIL_PROT_EXEC_LOOSE	},
	{ SYSFIL_INET_RAW,	SYSFIL_NET		},
	{ SYSFIL_UNIX,		SYSFIL_NET		},
	{ SYSFIL_CPUSET,	SYSFIL_SCHED		},
	{ SYSFIL_ANY_PROCESS,	SYSFIL_SAME_SESSION	},
	{ SYSFIL_SAME_SESSION,	SYSFIL_SAME_PGRP	},
	{ SYSFIL_SAME_PGRP,	SYSFIL_CHILD_PROCESS	},
};
CTASSERT(SYSFIL_SAME_SESSION > SYSFIL_ANY_PROCESS);
CTASSERT(SYSFIL_SAME_PGRP > SYSFIL_SAME_SESSION);
CTASSERT(SYSFIL_CHILD_PROCESS > SYSFIL_SAME_PGRP);

static struct curtain *
curtain_build(int flags, size_t reqc, const struct curtainreq *reqv)
{
	struct curtain *ct;
	const struct curtainreq *req;
	enum curtain_level def_on_self, def_on_exec;
	bool on_self, on_exec;

	SDT_PROBE3(curtain,, curtain_build, begin, flags, reqc, reqv);

	on_self = flags & CURTAINCTL_ON_SELF;
	on_exec = flags & CURTAINCTL_ON_EXEC;

	ct = curtain_make(CURTAINCTL_MAX_ITEMS);

	def_on_self = def_on_exec = CURTAINLVL_DENY;
	for (req = reqv; req < &reqv[reqc]; req++) {
		bool req_on_self = on_self && req->flags & CURTAINREQ_ON_SELF;
		bool req_on_exec = on_exec && req->flags & CURTAINREQ_ON_EXEC;
		if (req->type == CURTAINTYP_DEFAULT) {
			if (req_on_self)
				def_on_self = req->level;
			if (req_on_exec)
				def_on_exec = req->level;
		}
	}
	for (int sf = 0; sf <= SYSFIL_LAST; sf++) {
		if (on_self)
			ct->ct_sysfils[sf].on_self = def_on_self;
		if (on_exec)
			ct->ct_sysfils[sf].on_exec = def_on_exec;
	}
	if (on_self)
		ct->ct_sysfils[SYSFIL_DEFAULT].on_self = MAX(CURTAINLVL_DENY, def_on_self);
	if (on_exec)
		ct->ct_sysfils[SYSFIL_DEFAULT].on_exec = MAX(CURTAINLVL_DENY, def_on_exec);
	for (size_t i = 0; i < nitems(sysfils_always); i++) {
		if (on_self)
			ct->ct_sysfils[sysfils_always[i]].on_self = CURTAINLVL_PASS;
		if (on_exec)
			ct->ct_sysfils[sysfils_always[i]].on_exec = CURTAINLVL_PASS;
	}

	for (req = reqv; req < &reqv[reqc]; req++) {
		bool req_on_self = on_self && req->flags & CURTAINREQ_ON_SELF;
		bool req_on_exec = on_exec && req->flags & CURTAINREQ_ON_EXEC;
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
				if (req_on_self)
					ct->ct_sysfils[sf].on_self = req->level;
				if (req_on_exec)
					ct->ct_sysfils[sf].on_exec = req->level;
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
				    (union curtain_key){ .ioctl = *p++ });
				if (!item)
					goto fail;
				if (req_on_self)
					item->mode.on_self = req->level;
				if (req_on_exec)
					item->mode.on_exec = req->level;
			}
			break;
		}
		case CURTAINTYP_SOCKAF: {
			int *p = req->data;
			size_t c = req->size / sizeof *p;
			while (c--) {
				struct curtain_item *item;
				item = curtain_search(ct, req->type,
				    (union curtain_key){ .sockaf = *p++ });
				if (!item)
					goto fail;
				if (req_on_self)
					item->mode.on_self = req->level;
				if (req_on_exec)
					item->mode.on_exec = req->level;
			}
			break;
		}
		case CURTAINTYP_SOCKLVL: {
			int *p = req->data;
			size_t c = req->size / sizeof *p;
			while (c--) {
				struct curtain_item *item;
				item = curtain_search(ct, req->type,
				    (union curtain_key){ .socklvl = *p++ });
				if (!item)
					goto fail;
				if (req_on_self)
					item->mode.on_self = req->level;
				if (req_on_exec)
					item->mode.on_exec = req->level;
			}
			break;
		}
		case CURTAINTYP_SOCKOPT: {
			int (*p)[2] = req->data;
			size_t c = req->size / sizeof *p;
			while (c--) {
				struct curtain_item *item;
				item = curtain_search(ct, req->type,
				    (union curtain_key){ .sockopt = { (*p)[0], (*p)[1] } });
				p++;
				if (!item)
					goto fail;
				if (req_on_self)
					item->mode.on_self = req->level;
				if (req_on_exec)
					item->mode.on_exec = req->level;
			}
			break;
		}
		case CURTAINTYP_PRIV: {
			int *p = req->data;
			size_t c = req->size / sizeof *p;
			while (c--) {
				struct curtain_item *item;
				item = curtain_search(ct, req->type,
				    (union curtain_key){ .priv = *p++ });
				if (!item)
					goto fail;
				if (req_on_self)
					item->mode.on_self = req->level;
				if (req_on_exec)
					item->mode.on_exec = req->level;
			}
			break;
		}
		default:
			goto fail;
		}
	}

	for (size_t i = 0; i < nitems(sysfils_expand); i++) {
		if (on_self)
			ct->ct_sysfils[sysfils_expand[i][1]].on_self =
			    MIN(ct->ct_sysfils[sysfils_expand[i][0]].on_self,
			        ct->ct_sysfils[sysfils_expand[i][1]].on_self);
		if (on_exec)
			ct->ct_sysfils[sysfils_expand[i][1]].on_exec =
			    MIN(ct->ct_sysfils[sysfils_expand[i][0]].on_exec,
			        ct->ct_sysfils[sysfils_expand[i][1]].on_exec);
	}
	if (on_exec)
		ct->ct_sysfils[SYSFIL_PROT_EXEC_LOOSE].on_exec =
		    MIN(MIN(ct->ct_sysfils[SYSFIL_EXEC].on_self,
		            ct->ct_sysfils[SYSFIL_EXEC].on_exec),
		        ct->ct_sysfils[SYSFIL_PROT_EXEC_LOOSE].on_exec);

	if (flags & CURTAINCTL_ENFORCE) {
		SDT_PROBE1(curtain,, curtain_build, harden, ct);
		curtain_harden(ct);
	}

	SDT_PROBE1(curtain,, curtain_build, done, ct);
	return (ct);

fail:	SDT_PROBE0(curtain,, curtain_build, failed);
	curtain_free(ct);
	return (NULL);
}

#endif /* SYSFIL */


int
sysfil_require_vm_prot(struct thread *td, vm_prot_t prot, bool loose)
{
#ifdef SYSFIL
	if (prot & VM_PROT_EXECUTE)
		return (sysfil_require(td, loose && !(prot & VM_PROT_WRITE) ?
		    SYSFIL_PROT_EXEC_LOOSE : SYSFIL_PROT_EXEC));
#endif
	return (0);
}

int
sysfil_require_ioctl(struct thread *td, u_long com)
{
	int sf;
#ifdef SYSFIL
	if (curtain_check_cred(td->td_ucred, CURTAINTYP_IOCTL,
	    (union curtain_key){ .ioctl = com }) == 0)
		return (0);
#endif
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
	return (sysfil_require(td, sf));
}

int
sysfil_require_sockaf(struct thread *td, int af)
{
#ifdef SYSFIL
	if (curtain_check_cred(td->td_ucred, CURTAINTYP_SOCKAF,
	    (union curtain_key){ .sockaf = af }) == 0)
		return (0);
#endif
	return (sysfil_require(td, SYSFIL_ANY_SOCKAF));
}

int
sysfil_require_sockopt(struct thread *td, int level, int name)
{
#ifdef SYSFIL
	if (curtain_check_cred(td->td_ucred, CURTAINTYP_SOCKOPT,
	    (union curtain_key){ .sockopt = { level, name } }) == 0)
		return (0);
	if (curtain_check_cred(td->td_ucred, CURTAINTYP_SOCKLVL,
	    (union curtain_key){ .socklvl = level }) == 0)
		return (0);
#endif
	return (sysfil_require(td, SYSFIL_ANY_SOCKOPT));
}

int
sysfil_priv_check(struct ucred *cr, int priv)
{
#ifdef SYSFIL
	if (curtain_check_cred(cr, CURTAINTYP_PRIV,
	    (union curtain_key){ .priv = priv }) == 0)
		return (0);
	/*
	 * Mostly a subset of what's being allowed for jails (see
	 * prison_priv_check()) with some extra conditions based on sysfils.
	 * Some of those checks might be redundant with current syscall
	 * filterings, but this might be hard to tell and including them here
	 * anyway makes things a bit clearer.
	 */
	switch (priv) {
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
		if (sysfil_check_cred(cr, SYSFIL_ID) == 0)
			return (0);
		break;
	case PRIV_SEEOTHERGIDS:
	case PRIV_SEEOTHERUIDS:
		if (sysfil_check_cred(cr, SYSFIL_PS) == 0)
			return (0);
		break;
	case PRIV_PROC_LIMIT:
	case PRIV_PROC_SETRLIMIT:
		if (sysfil_check_cred(cr, SYSFIL_RLIMIT) == 0)
			return (0);
		break;
	case PRIV_JAIL_ATTACH:
	case PRIV_JAIL_SET:
	case PRIV_JAIL_REMOVE:
		if (sysfil_check_cred(cr, SYSFIL_JAIL) == 0)
			return (0);
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
		/* Allowing to restrict this could be useful? */
		return (0);
	case PRIV_VFS_SYSFLAGS:
		if (sysfil_check_cred(cr, SYSFIL_SYSFLAGS) == 0)
			return (0);
		break;
	case PRIV_VFS_READ_DIR:
		/* Let other policies handle this (like is done for jails). */
		return (0);
	case PRIV_VFS_CHOWN:
	case PRIV_VFS_SETGID:
	case PRIV_VFS_RETAINSUGID:
		if (sysfil_check_cred(cr, SYSFIL_CHOWN) == 0)
			return (0);
		break;
	case PRIV_VFS_CHROOT:
	case PRIV_VFS_FCHROOT:
		if (sysfil_check_cred(cr, SYSFIL_CHROOT) == 0)
			return (0);
		break;
	case PRIV_VM_MLOCK:
	case PRIV_VM_MUNLOCK:
		if (sysfil_check_cred(cr, SYSFIL_MLOCK) == 0)
			return (0);
		break;
	case PRIV_NETINET_RESERVEDPORT:
#if 0
	case PRIV_NETINET_REUSEPORT:
	case PRIV_NETINET_SETHDROPTS:
#endif
		return (0);
	case PRIV_NETINET_RAW:
		if (sysfil_check_cred(cr, SYSFIL_INET_RAW) == 0)
			return (0);
		break;
#if 0
	case PRIV_NETINET_GETCRED:
		return (0);
#endif
	case PRIV_ADJTIME:
	case PRIV_NTP_ADJTIME:
	case PRIV_CLOCK_SETTIME:
		if (sysfil_check_cred(cr, SYSFIL_SETTIME) == 0)
			return (0);
		break;
	case PRIV_VFS_GETFH:
	case PRIV_VFS_FHOPEN:
	case PRIV_VFS_FHSTAT:
	case PRIV_VFS_FHSTATFS:
	case PRIV_VFS_GENERATION:
		if (sysfil_check_cred(cr, SYSFIL_FH) == 0)
			return (0);
		break;
	}
	return (sysfil_check_cred(cr, SYSFIL_ANY_PRIV));
#else
	return (0);
#endif
}

#ifdef SYSFIL
static void
sysfil_log_violation(struct thread *td, int sf, int sig)
{
	struct proc *p = td->td_proc;
	struct ucred *cr = td->td_ucred;
	log(LOG_ERR, "pid %d (%s), jid %d, uid %d: violated sysfil #%d restrictions%s\n",
	    p->p_pid, p->p_comm, cr->cr_prison->pr_id, cr->cr_uid, sf,
	    sig == SIGKILL ? " and was killed" : sig != 0 ? " and was signaled" : "");
}
#endif

void
sysfil_violation(struct thread *td, int sf, int error)
{
#ifdef SYSFIL
	struct curtain *ct;
	enum curtain_level lvl;
	int sig;
	ct = td->td_ucred->cr_curtain;
	lvl = ct ? ct->ct_sysfils[sf].on_self : CURTAINLVL_DENY;
	sig = lvl >= CURTAINLVL_KILL ? SIGKILL :
	      lvl >= CURTAINLVL_TRAP ? SIGTRAP : 0;
	if (sysfil_violation_log_level >= 2 ? true :
	    sysfil_violation_log_level >= 1 ? sig != 0 :
	                                      false)
		sysfil_log_violation(td, sf, sig);
	if (sig != 0) {
		ksiginfo_t ksi;
		ksiginfo_init_trap(&ksi);
		ksi.ksi_signo = sig;
		ksi.ksi_code = SI_SYSFIL;
		ksi.ksi_sysfil = sf;
		ksi.ksi_errno = error;
		trapsignal(td, &ksi);
	}
#endif
}


#ifdef SYSFIL

static int
do_curtainctl(struct thread *td, int flags, size_t reqc, const struct curtainreq *reqv)
{
	struct proc *p = td->td_proc;
	struct ucred *cr, *old_cr;
	struct curtain *ct;
	const struct curtainreq *req;
	int error = 0;
#ifdef UNVEIL
	struct unveil_base *base = &p->p_unveils;
#endif
	bool on_self, on_exec;

	if (!sysfil_enabled)
		return (ENOSYS);

	on_self = flags & CURTAINCTL_ON_SELF;
	on_exec = flags & CURTAINCTL_ON_EXEC;

#ifdef UNVEIL
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

	do {
		cr = crget();
		PROC_LOCK(p);
		old_cr = crcopysafe(p, cr);
		if (cr->cr_curtain)
			curtain_limit(ct, cr->cr_curtain);
		else
			curtain_limit_sysfils(ct, &cr->cr_sysfilset);
		crhold(old_cr);
		PROC_UNLOCK(p);
		SDT_PROBE1(curtain,, do_curtainctl, limit, ct);
		if (cr->cr_curtain)
			curtain_free(cr->cr_curtain);
		curtain_compact(&ct);
		SDT_PROBE1(curtain,, do_curtainctl, compact, ct);
		cr->cr_curtain = ct;
		PROC_LOCK(p);
		if (old_cr == p->p_ucred) {
			crfree(old_cr);
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

	if (flags & CURTAINCTL_ON_SELF) {
		BIT_ZERO(SYSFILSET_BITS, &cr->cr_sysfilset);
		for (int sf = 0; sf <= SYSFIL_LAST; sf++)
			if (ct->ct_sysfils[sf].on_self == CURTAINLVL_PASS)
				BIT_SET(SYSFILSET_BITS, sf, &cr->cr_sysfilset);
		MPASS(SYSFILSET_IS_RESTRICTED(&cr->cr_sysfilset));
		MPASS(CRED_IN_RESTRICTED_MODE(cr));
	}

	if (!(flags & (CURTAINCTL_ENFORCE | CURTAINCTL_ENGAGE)))
		goto out1;

	proc_set_cred(p, cr);
	crfree(old_cr);
	if (on_self && !PROC_IN_RESTRICTED_MODE(p))
		panic("PROC_IN_RESTRICTED_MODE() bogus");
	PROC_UNLOCK(p);
	SDT_PROBE1(curtain,, do_curtainctl, assign, ct);

#ifdef UNVEIL
	for (req = reqv; req < &reqv[reqc]; req++) {
		bool req_on_self = on_self && req->flags & CURTAINREQ_ON_SELF;
		bool req_on_exec = on_exec && req->flags & CURTAINREQ_ON_EXEC;
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
		unveil_base_activate(base, UNVEIL_ON_SELF);
	if (on_exec)
		unveil_base_activate(base, UNVEIL_ON_EXEC);
	if (flags & CURTAINCTL_ENFORCE) {
		if (on_self)
			unveil_base_enforce(base, UNVEIL_ON_SELF);
		if (on_exec)
			unveil_base_enforce(base, UNVEIL_ON_EXEC);
	}
	unveil_lockdown_fd(td);
#endif
	goto out2;
out1:
	PROC_UNLOCK(p);
	crfree(cr);
out2:
#ifdef UNVEIL
	unveil_base_write_end(base);
#endif
	return (error);
}

#endif /* SYSFIL */

int
sys_curtainctl(struct thread *td, struct curtainctl_args *uap)
{
#ifdef SYSFIL
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
#else
	return (ENOSYS);
#endif /* SYSFIL */
}

#ifdef SYSFIL

void
curtain_cap_enter(struct thread *td)
{
	struct proc *p = td->td_proc;
	struct ucred *cr, *old_cr;
	struct curtain *ct;

	do {
		cr = crget();
		PROC_LOCK(p);
		old_cr = crcopysafe(p, cr);
		if (!cr->cr_curtain) {
			ct = NULL;
			break;
		}
		crhold(old_cr);
		PROC_UNLOCK(p);
		ct = curtain_dup(cr->cr_curtain);
		curtain_free(cr->cr_curtain);
		cr->cr_curtain = ct;
		PROC_LOCK(p);
		if (old_cr == p->p_ucred) {
			crfree(old_cr);
			break;
		}
		PROC_UNLOCK(p);
		crfree(old_cr);
		crfree(cr);
	} while (true);

	BIT_CLR(SYSFILSET_BITS, SYSFIL_UNCAPSICUM, &cr->cr_sysfilset);
	if (ct)
		mode_cap(&ct->ct_sysfils[SYSFIL_UNCAPSICUM], CURTAINLVL_DENY);
	MPASS(CRED_IN_CAPABILITY_MODE(cr));
	MPASS(CRED_IN_RESTRICTED_MODE(cr));

	proc_set_cred(p, cr);
	if (!PROC_IN_RESTRICTED_MODE(p))
		panic("PROC_IN_RESTRICTED_MODE() bogus");
	if (!PROC_IN_CAPABILITY_MODE(p))
		panic("PROC_IN_CAPABILITY_MODE() bogus");
	PROC_UNLOCK(p);
	crfree(old_cr);
}

static cap_rights_t __read_mostly cap_sysfil_rpath_rights;
static cap_rights_t __read_mostly cap_sysfil_wpath_rights;
static cap_rights_t __read_mostly cap_sysfil_cpath_rights;
static cap_rights_t __read_mostly cap_sysfil_exec_rights;
static cap_rights_t __read_mostly cap_sysfil_fattr_rights;
static cap_rights_t __read_mostly cap_sysfil_unix_rights;

void
sysfil_cred_rights(struct ucred *cr, cap_rights_t *rights)
{
	if (!CRED_IN_RESTRICTED_MODE(cr)) {
		CAP_ALL(rights);
		return;
	}
	CAP_NONE(rights);
	if (sysfil_match_cred(cr, SYSFIL_RPATH))
		cap_rights_merge(rights, &cap_sysfil_rpath_rights);
	if (sysfil_match_cred(cr, SYSFIL_WPATH))
		cap_rights_merge(rights, &cap_sysfil_wpath_rights);
	if (sysfil_match_cred(cr, SYSFIL_CPATH))
		cap_rights_merge(rights, &cap_sysfil_cpath_rights);
	if (sysfil_match_cred(cr, SYSFIL_EXEC))
		cap_rights_merge(rights, &cap_sysfil_exec_rights);
	if (sysfil_match_cred(cr, SYSFIL_FATTR))
		cap_rights_merge(rights, &cap_sysfil_fattr_rights);
	if (sysfil_match_cred(cr, SYSFIL_UNIX))
		cap_rights_merge(rights, &cap_sysfil_unix_rights);
}

static void
sysfil_sysinit(void *arg)
{
	/* Note: Some of those rights are further restricted by other sysfils. */
	cap_rights_init(&cap_sysfil_rpath_rights,
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
	cap_rights_init(&cap_sysfil_wpath_rights,
	    CAP_LOOKUP,
	    CAP_FLOCK,
	    CAP_WRITE,
	    CAP_SEEK,
	    CAP_FPATHCONF,
	    CAP_MMAP,
	    CAP_FSYNC,
	    CAP_FTRUNCATE);
	cap_rights_init(&cap_sysfil_cpath_rights,
	    CAP_LOOKUP,
	    CAP_CREATE,
	    CAP_FPATHCONF,
	    CAP_LINKAT_SOURCE,
	    CAP_LINKAT_TARGET,
	    CAP_MKDIRAT,
	    CAP_MKFIFOAT,
	    CAP_MKNODAT,
	    CAP_SYMLINKAT,
	    CAP_UNLINKAT,
	    CAP_RENAMEAT_SOURCE,
	    CAP_RENAMEAT_TARGET,
	    CAP_UNDELETEAT);
	cap_rights_init(&cap_sysfil_exec_rights,
	    CAP_LOOKUP,
	    CAP_FEXECVE,
	    CAP_EXECAT);
	cap_rights_init(&cap_sysfil_fattr_rights,
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
	cap_rights_init(&cap_sysfil_unix_rights,
	    CAP_LOOKUP,
	    CAP_BINDAT,
	    CAP_CONNECTAT);
}

SYSINIT(sysfil_sysinit, SI_SUB_COPYRIGHT, SI_ORDER_ANY, sysfil_sysinit, NULL);

#endif /* SYSFIL */
