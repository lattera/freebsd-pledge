#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/sysproto.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/ucred.h>
#include <sys/sysctl.h>
#include <sys/priv.h>
#include <sys/sdt.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/syscall.h>
#include <sys/conf.h>

#include <security/mac/mac_policy.h>
#include <sys/unveil.h>
#include <sys/curtain.h>

SDT_PROVIDER_DEFINE(curtain);
SDT_PROBE_DEFINE2(curtain,, curtain_fill, begin,
    "size_t", "const struct curtainreq *");
SDT_PROBE_DEFINE1(curtain,, curtain_fill, done, "struct curtain *");
SDT_PROBE_DEFINE0(curtain,, curtain_fill, failed);
SDT_PROBE_DEFINE1(curtain,, do_curtainctl, mask, "struct curtain *");
SDT_PROBE_DEFINE1(curtain,, do_curtainctl, compact, "struct curtain *");
SDT_PROBE_DEFINE1(curtain,, do_curtainctl, harden, "struct curtain *");
SDT_PROBE_DEFINE1(curtain,, do_curtainctl, assign, "struct curtain *");

typedef union curtain_key ctkey;

#define	CRED_SLOT(cr) CURTAIN_SLOT_CT((cr)->cr_label)
#define	CRED_SLOT_BR(cr) CURTAIN_SLOT_BR((cr)->cr_label)

bool
curtain_cred_visible(const struct ucred *subject, const struct ucred *target,
    enum barrier_type type)
{
	return (barrier_visible(CRED_SLOT_BR(subject), CRED_SLOT_BR(target), type));
}

struct curtain *
curtain_from_cred(struct ucred *cr)
{
	return (CRED_SLOT(cr));
}


struct get_sysctl_serial_ctx {
	uint64_t *serial;
	int *name;
	unsigned namelen;
	int error;
};

static void
get_sysctl_serial_cb(void *ptr)
{
	struct get_sysctl_serial_ctx *ctx = ptr;
	struct sysctl_oid *oidp;
	ctx->error = sysctl_find_oid(ctx->name, ctx->namelen, &oidp, NULL, NULL);
	if (!ctx->error)
		*ctx->serial = oidp->oid_serial;
}

static int
get_sysctl_serial(int *name, unsigned name_len, uint64_t *serial)
{
	struct get_sysctl_serial_ctx ctx = { serial, name, name_len };
	sysctl_call_with_rlock(get_sysctl_serial_cb, &ctx);
	return (ctx.error);
}


static bool __read_mostly curtainctl_enabled = true;
unsigned __read_mostly curtain_log_level = CURTAINLVL_TRAP;

SYSCTL_NODE(_security, OID_AUTO, curtain,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "Curtain");

#ifdef CURTAIN_STATS

SYSCTL_NODE(_security_curtain, OID_AUTO, stats,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0, "");

#endif

SYSCTL_BOOL(_security_curtain, OID_AUTO, enabled,
    CTLFLAG_RW, &curtainctl_enabled, 0,
    "Allow curtainctl(2) usage");

SYSCTL_UINT(_security_curtain, OID_AUTO, log_level,
    CTLFLAG_RW, &curtain_log_level, 0,
    "");

static int
sysctl_curtain_curtained(SYSCTL_HANDLER_ARGS)
{
	struct curtain *ct;
	int ret;
	ret = ((ct = CRED_SLOT(req->td->td_ucred)) ? ct->ct_cached.is_restricted_on_self : 0);
	return (SYSCTL_OUT(req, &ret, sizeof(ret)));
}

SYSCTL_PROC(_security_curtain, OID_AUTO, curtained,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_RESTRICT | CTLFLAG_MPSAFE, NULL, 0,
    sysctl_curtain_curtained, "I", "");

static int
sysctl_curtain_curtained_exec(SYSCTL_HANDLER_ARGS)
{
	struct curtain *ct;
	int ret;
	ret = ((ct = CRED_SLOT(req->td->td_ucred)) ? ct->ct_cached.is_restricted_on_exec : 0);
	return (SYSCTL_OUT(req, &ret, sizeof(ret)));
}

SYSCTL_PROC(_security_curtain, OID_AUTO, curtained_exec,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_RESTRICT | CTLFLAG_MPSAFE, NULL, 0,
    sysctl_curtain_curtained_exec, "I", "");


/* Some abilities shouldn't be disabled via curtainctl(2). */
static const int abilities_always[] = { CURTAINABL_UNCAPSICUM };
/* Some abilities don't make much sense without some others. */
static const int abilities_expand[][2] = {
	{ CURTAINABL_VFS_READ,		CURTAINABL_VFS_MISC		},
	{ CURTAINABL_VFS_WRITE,		CURTAINABL_VFS_MISC		},
	{ CURTAINABL_VFS_CREATE,	CURTAINABL_VFS_MISC		},
	{ CURTAINABL_VFS_DELETE,	CURTAINABL_VFS_MISC		},
	{ CURTAINABL_FATTR,		CURTAINABL_VFS_MISC		},
	{ CURTAINABL_PROT_EXEC,		CURTAINABL_PROT_EXEC_LOOSE	},
	{ CURTAINABL_VFS_SOCK,		CURTAINABL_VFS_BIND		},
	{ CURTAINABL_VFS_SOCK,		CURTAINABL_VFS_CONNECT		},
	{ CURTAINABL_VFS_BIND,		CURTAINABL_SOCK			},
	{ CURTAINABL_VFS_CONNECT,	CURTAINABL_SOCK			},
	{ CURTAINABL_NET,		CURTAINABL_NET_CLIENT		},
	{ CURTAINABL_NET,		CURTAINABL_NET_SERVER		},
	{ CURTAINABL_NET_CLIENT,	CURTAINABL_SOCK			},
	{ CURTAINABL_NET_SERVER,	CURTAINABL_SOCK			},
	{ CURTAINABL_CPUSET,		CURTAINABL_SCHED		},
};

static void
curtain_fill_expand(struct curtain *ct)
{
	bool propagate;

	for (size_t i = 0; i < nitems(abilities_always); i++) {
		ct->ct_abilities[abilities_always[i]].on_self = CURTAINACT_ALLOW;
		ct->ct_abilities[abilities_always[i]].on_exec = CURTAINACT_ALLOW;
	}

	do {
		propagate = false;
		for (size_t i = 0; i < nitems(abilities_expand); i++) {
			enum curtain_ability from = abilities_expand[i][0], to = abilities_expand[i][1];
			if (ct->ct_abilities[to].on_self > ct->ct_abilities[from].on_self) {
				ct->ct_abilities[to].on_self = ct->ct_abilities[from].on_self;
				propagate = true;
			}
			if (ct->ct_abilities[to].on_exec > ct->ct_abilities[from].on_exec) {
				ct->ct_abilities[to].on_exec = ct->ct_abilities[from].on_exec;
				propagate = true;
			}
		}
	} while (propagate);

	ct->ct_abilities[CURTAINABL_PROT_EXEC_LOOSE].on_exec =
	    MIN(MIN(ct->ct_abilities[CURTAINABL_EXEC].on_self,
	            ct->ct_abilities[CURTAINABL_EXEC].on_exec),
		ct->ct_abilities[CURTAINABL_PROT_EXEC_LOOSE].on_exec);
}

static void
curtain_fill_restrict(struct curtain *ct, struct ucred *cr)
{
	if (curtain_is_restricted_on_self(ct))
		if (ct->ct_abilities[CURTAINABL_DEFAULT].on_self < CURTAINACT_DENY)
			ct->ct_abilities[CURTAINABL_DEFAULT].on_self = CURTAINACT_DENY;
	if (curtain_is_restricted_on_exec(ct)) {
		if (ct->ct_abilities[CURTAINABL_DEFAULT].on_exec < CURTAINACT_DENY)
			ct->ct_abilities[CURTAINABL_DEFAULT].on_exec = CURTAINACT_DENY;
		if (ct->ct_abilities[CURTAINABL_EXEC_RSUGID].on_exec < CURTAINACT_DENY &&
		    priv_check_cred(cr, PRIV_VFS_CHROOT) != 0)
			ct->ct_abilities[CURTAINABL_EXEC_RSUGID].on_exec = CURTAINACT_DENY;
	}
}

static const enum curtain_action lvl2act[CURTAINLVL_COUNT] = {
	[CURTAINLVL_PASS] = CURTAINACT_ALLOW,
	[CURTAINLVL_GATE] = CURTAINACT_ALLOW,
	[CURTAINLVL_WALL] = CURTAINACT_ALLOW,
	[CURTAINLVL_DENY] = CURTAINACT_DENY,
	[CURTAINLVL_TRAP] = CURTAINACT_TRAP,
	[CURTAINLVL_KILL] = CURTAINACT_KILL,
};

static void
curtain_fill_barrier_mode(struct barrier_mode *mode, enum curtainreq_level lvl, barrier_bits barriers)
{
	if (lvl >= CURTAINLVL_GATE)
		mode->protect |= barriers;
	else
		mode->protect &= ~barriers;
	if (lvl >= CURTAINLVL_WALL)
		mode->isolate |= barriers;
	else
		mode->isolate &= ~barriers;
}

static inline void
fill_mode(struct curtain_mode *mode, const struct curtainreq *req)
{
	enum curtain_action act;
	act = lvl2act[req->level];
	if (req->flags & CURTAINREQ_ON_SELF)
		mode->on_self = act;
	if (req->flags & CURTAINREQ_ON_EXEC)
		mode->on_exec = act;
	mode->on_self_max = mode->on_exec_max = CURTAINACT_ALLOW;
}

static void
curtain_fill_ability(struct curtain *ct, const struct curtainreq *req,
    enum curtain_ability abl)
{
	struct barrier *br;
	fill_mode(&ct->ct_abilities[abl], req);
	br = CURTAIN_BARRIER(ct);
	if (req->flags & CURTAINREQ_ON_SELF)
		curtain_fill_barrier_mode(&br->br_mode,
		    req->level, curtain_abilities_barriers[abl]);
	if (req->flags & CURTAINREQ_ON_EXEC)
		curtain_fill_barrier_mode(&ct->ct_barrier_mode_on_exec,
		    req->level, curtain_abilities_barriers[abl]);
}

static struct curtain_item *
curtain_fill_item(struct curtain *ct, const struct curtainreq *req, union curtain_key key)
{
	struct curtain_item *item;
	item = curtain_spread(ct, req->type, key);
	if (item)
		fill_mode(&item->mode, req);
	return (item);
}

static int
curtain_fill(struct curtain *ct, size_t reqc, const struct curtainreq *reqv)
{
	struct barrier *br;
	const struct curtainreq *req;
	enum curtainreq_level def_on_self, def_on_exec;
	int error;
	unsigned short group_counts[CURTAINTYP_LAST + 1] = { 0 },
	               group_jumps[CURTAINTYP_LAST + 1],
	               group_fills[CURTAINTYP_LAST + 1],
	               group_entries[reqc], /* CURTAINCTL_MAX_REQS */
	               group_index;

	SDT_PROBE2(curtain,, curtain_fill, begin, reqc, reqv);

	/* Validate and group requests by type. */
	for (req = reqv; req < &reqv[reqc]; req++) {
		if (!(req->level >= 0 && req->level < CURTAINLVL_COUNT) ||
		    !(req->type >= CURTAINTYP_DEFAULT && req->type <= CURTAINTYP_LAST)) {
			error = EINVAL;
			goto fail;
		}
		group_counts[req->type]++;
	}
	group_jumps[0] = group_fills[0] = 0;
	for (int i = 0; i < CURTAINTYP_LAST; i++)
		group_jumps[i + 1] = group_fills[i + 1] = group_counts[i] + group_jumps[i];
	for (size_t reqi = 0; reqi < reqc; reqi++)
		group_entries[group_fills[reqv[reqi].type]++] = reqi;
#ifdef INVARIANTS
	for (int i = 0; i <= CURTAINTYP_LAST; i++)
		MPASS(group_fills[i] == group_jumps[i] + group_counts[i]);
#endif

	/*
	 * Requests for items of a certain type must be processed before
	 * requests for items of types that can inherit from them.
	 */

#define	GROUP_FOREACH(t, req) \
	for (group_index = group_jumps[t]; \
	    group_index < group_fills[t] && (req = &reqv[group_entries[group_index]]); \
	    group_index++)

	def_on_self = def_on_exec = CURTAINLVL_KILL;
	GROUP_FOREACH(CURTAINTYP_DEFAULT, req) {
		MPASS(req->type == CURTAINTYP_DEFAULT);
		if (req->flags & CURTAINREQ_ON_SELF)
			def_on_self = req->level;
		if (req->flags & CURTAINREQ_ON_EXEC)
			def_on_exec = req->level;
	}
	for (enum curtain_ability abl = 0; abl <= CURTAINABL_LAST; abl++) {
		ct->ct_abilities[abl].on_self = lvl2act[def_on_self];
		ct->ct_abilities[abl].on_exec = lvl2act[def_on_exec];
	}
	br = CURTAIN_BARRIER(ct);
	curtain_fill_barrier_mode(&br->br_mode, def_on_self, BARRIERS_ALL);
	curtain_fill_barrier_mode(&ct->ct_barrier_mode_on_exec, def_on_exec, BARRIERS_ALL);

	GROUP_FOREACH(CURTAINTYP_ABILITY, req) {
		MPASS(req->type == CURTAINTYP_ABILITY);
		enum curtain_ability *ablp = req->data;
		size_t ablc = req->size / sizeof *ablp;
		while (ablc--) {
			enum curtain_ability abl = *ablp++;
			if (!CURTAINABL_USER_VALID(abl)) {
				error = EINVAL;
				goto fail;
			}
			curtain_fill_ability(ct, req, abl);
		}
	}

	GROUP_FOREACH(CURTAINTYP_IOCTL, req) {
		MPASS(req->type == CURTAINTYP_IOCTL);
		unsigned long *p = req->data;
		size_t c = req->size / sizeof *p;
		while (c--)
			curtain_fill_item(ct, req, (ctkey){ .ioctl = *p++ });
	}

	GROUP_FOREACH(CURTAINTYP_SOCKAF, req) {
		MPASS(req->type == CURTAINTYP_SOCKAF);
		int *p = req->data;
		size_t c = req->size / sizeof *p;
		while (c--)
			curtain_fill_item(ct, req, (ctkey){ .sockaf = *p++ });
	}

	GROUP_FOREACH(CURTAINTYP_SOCKLVL, req) {
		MPASS(req->type == CURTAINTYP_SOCKLVL);
		int *p = req->data;
		size_t c = req->size / sizeof *p;
		while (c--)
			curtain_fill_item(ct, req, (ctkey){ .socklvl = *p++ });
	}

	GROUP_FOREACH(CURTAINTYP_SOCKOPT, req) {
		MPASS(req->type == CURTAINTYP_SOCKOPT);
		int (*p)[2] = req->data;
		size_t c = req->size / sizeof *p;
		while (c--) {
			curtain_fill_item(ct, req,
			    (ctkey){ .sockopt = { (*p)[0], (*p)[1] } });
			p++;
		}
	}

	GROUP_FOREACH(CURTAINTYP_PRIV, req) {
		MPASS(req->type == CURTAINTYP_PRIV);
		int *p = req->data;
		size_t c = req->size / sizeof *p;
		while (c--)
			curtain_fill_item(ct, req, (ctkey){ .priv = *p++ });
	}

	GROUP_FOREACH(CURTAINTYP_SYSCTL, req) {
		MPASS(req->type == CURTAINTYP_SYSCTL);
		int *p = req->data;
		size_t c = req->size / sizeof *p;
		while (c--) {
			uint64_t serial;
			size_t l;
			l = *p++;
			if (l > c) {
				error = EINVAL;
				goto fail;
			}
			error = get_sysctl_serial(p, l, &serial);
			p += l;
			c -= l;
			if (error) {
				if (error != ENOENT)
					goto fail;
				continue;
			}
			curtain_fill_item(ct, req,
			    (ctkey){ .sysctl = { .serial = serial } });
		}
	}

	GROUP_FOREACH(CURTAINTYP_FIBNUM, req) {
		MPASS(req->type == CURTAINTYP_FIBNUM);
		int *p = req->data;
		size_t c = req->size / sizeof *p;
		while (c--)
			curtain_fill_item(ct, req, (ctkey){ .fibnum = *p++ });
	}

	GROUP_FOREACH(CURTAINTYP_UNVEIL, req) {
		MPASS(req->type == CURTAINTYP_UNVEIL);
		struct curtainent_unveil *entp = req->data;
		size_t entc = req->size / sizeof *entp;
		while (entc--) {
			if (req->flags & CURTAINREQ_ON_SELF) {
				error = unveil_stash_update(&ct->ct_ustash,
				    entp->index, UNVEIL_ON_SELF, entp->uperms);
				if (error)
					goto fail;
			}
			if (req->flags & CURTAINREQ_ON_EXEC) {
				error = unveil_stash_update(&ct->ct_ustash,
				    entp->index, UNVEIL_ON_EXEC, entp->uperms);
				if (error)
					goto fail;
			}
			entp++;
		}
	}

#undef	GROUP_FOREACH

	if (ct->ct_overflowed || ct->ct_nitems > CURTAINCTL_MAX_ITEMS) {
		error = E2BIG;
		goto fail;
	}

	curtain_fill_expand(ct);

	SDT_PROBE1(curtain,, curtain_fill, done, ct);
	curtain_invariants_sync(ct);
	return (0);

fail:	SDT_PROBE0(curtain,, curtain_fill, failed);
	return (error);
}


static int
do_curtainctl(struct thread *td, int flags, size_t reqc, const struct curtainreq *reqv)
{
	struct proc *p = td->td_proc;
	struct ucred *cr, *old_cr;
	struct curtain *ct, *old_ct;
	struct unveil_base *ubase;
	bool on_self, on_exec;
	int error = 0;

	if (!curtainctl_enabled)
		return (ENOSYS);

	ct = curtain_make(CURTAINCTL_MAX_ITEMS);

	ubase = unveil_proc_get_base(p, true);
	unveil_base_write_begin(ubase);
	unveil_stash_begin(&ct->ct_ustash, ubase);

	error = curtain_fill(ct, reqc, reqv);
	if (error) {
		curtain_free(ct);
		goto out2;
	}

	/*
	 * Were restrictions requested by the user?  This may be different from
	 * how the curtain actually ends up.
	 */
	on_self = curtain_is_restricted_on_self(ct);
	on_exec = curtain_is_restricted_on_exec(ct);

	/*
	 * Mask the requested curtain against the curtain (or sysfilset) of the
	 * process' current ucred, compact it and associate it with a new ucred
	 * while dealing with the current ucred potentially changing in-between
	 * process unlocks.
	 */
	do {
		struct curtain *new_ct;
		cr = crget();
		PROC_LOCK(p);
		old_cr = crcopysafe(p, cr);
		crhold(old_cr);
		PROC_UNLOCK(p);
		if (CRED_SLOT(cr))
			curtain_mask(ct, CRED_SLOT(cr));
		else
			curtain_mask_sysfils(ct, cr->cr_sysfilset);
		SDT_PROBE1(curtain,, do_curtainctl, mask, ct);
		new_ct = curtain_dup_compact(ct);
		if (CRED_SLOT(cr))
			curtain_free(CRED_SLOT(cr));
		mac_label_set(cr->cr_label, curtain_slot, (uintptr_t)new_ct);
		SDT_PROBE1(curtain,, do_curtainctl, compact, new_ct);
		PROC_LOCK(p);
		if (old_cr == p->p_ucred) {
			crfree(old_cr);
			old_ct = ct;
			ct = new_ct;
			break;
		}
		PROC_UNLOCK(p);
		crfree(old_cr);
		crfree(cr);
	} while (true);
	if (ct->ct_overflowed) { /* masking can overflow */
		error = E2BIG;
		goto out1;
	}
	curtain_fill_restrict(ct, old_cr);
	curtain_cache_update(ct);
	curtain_cred_sysfil_update(cr, ct);

	if (on_self)
		unveil_stash_inherit(&ct->ct_ustash, UNVEIL_ON_SELF);
	else
		unveil_stash_unrestrict(&ct->ct_ustash, UNVEIL_ON_SELF);
	if (on_exec)
		unveil_stash_inherit(&ct->ct_ustash, UNVEIL_ON_EXEC);
	else
		unveil_stash_unrestrict(&ct->ct_ustash, UNVEIL_ON_EXEC);

	if (flags & CURTAINCTL_ENFORCE) {
		SDT_PROBE1(curtain,, do_curtainctl, harden, ct);
		curtain_harden(ct);
		if (on_self)
			unveil_stash_freeze(&ct->ct_ustash, UNVEIL_ON_SELF);
		if (on_exec)
			unveil_stash_freeze(&ct->ct_ustash, UNVEIL_ON_EXEC);
	}

	if (!(flags & (CURTAINCTL_ENFORCE | CURTAINCTL_ENGAGE)))
		goto out1;

	/* Install new ucred and curtain. */
	unveil_stash_commit(&ct->ct_ustash, ubase);
	if (CRED_SLOT(old_cr))
		barrier_link(CURTAIN_BARRIER(ct), CURTAIN_BARRIER(CRED_SLOT(old_cr)));
	proc_set_cred(p, cr);
	if (CRED_IN_RESTRICTED_MODE(cr) != PROC_IN_RESTRICTED_MODE(p))
		panic("PROC_IN_RESTRICTED_MODE() bogus");
	PROC_UNLOCK(p);
	crfree(old_cr);
	curtain_free(old_ct);
	SDT_PROBE1(curtain,, do_curtainctl, assign, ct);

	goto out2;
out1:
	PROC_UNLOCK(p);
	crfree(cr);
	curtain_free(old_ct);
out2:
	unveil_base_write_end(ubase);
	return (error);
}

int
sys_curtainctl(struct thread *td, struct curtainctl_args *uap)
{
	size_t reqc, reqi, avail;
	struct curtainreq *reqv;
	int flags, error;
	flags = uap->flags;
	if ((flags & CURTAINCTL_VER_MASK) != CURTAINCTL_THIS_VERSION)
		return (EINVAL);
	reqc = uap->reqc;
	if (reqc > CURTAINCTL_MAX_REQS)
		return (E2BIG);
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
			error = E2BIG;
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


static struct syscall_helper_data curtain_syscalls[] = {
	SYSCALL_INIT_HELPER(curtainctl),
	SYSCALL_INIT_LAST,
};

static void
sys_curtain_sysinit(void *arg)
{
	int error;
	error = syscall_helper_register(curtain_syscalls,
	    SY_THR_STATIC_KLD | SY_HLP_PRESERVE_SYFLAGS);
	if (error)
		printf("%s: syscall_helper_register error %d\n", __FUNCTION__, error);
}

static void
sys_curtain_sysuninit(void *arg __unused)
{
	syscall_helper_unregister(curtain_syscalls);
}

SYSINIT(curtain_sysinit, SI_SUB_MAC_POLICY, SI_ORDER_MIDDLE, sys_curtain_sysinit, NULL);
SYSUNINIT(curtain_sysuninit, SI_SUB_MAC_POLICY, SI_ORDER_MIDDLE, sys_curtain_sysuninit, NULL);

