#include "opt_ddb.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/ucred.h>
#include <sys/sysctl.h>
#include <sys/priv.h>
#include <sys/sdt.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/syscall.h>
#include <sys/conf.h>
#include <sys/filedesc.h>
#include <sys/file.h>
#include <sys/fnv_hash.h>
#ifdef DDB
#include <sys/vnode.h>
#include <ddb/ddb.h>
#endif

#include <security/mac_curtain/curtain_int.h>
#include <security/mac/mac_policy.h>
#include <sys/unveil.h>

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
curtain_cred_visible(const struct ucred *subject, const struct ucred *target, barrier_bits bar)
{
	return (barrier_visible(CRED_SLOT_BR(subject), CRED_SLOT_BR(target), bar));
}

struct curtain *
curtain_from_cred(struct ucred *cr)
{
	return (CRED_SLOT(cr));
}


static bool __read_mostly curtainctl_enabled = true;
static curtain_index curtain_max_items_per_curtain = CURTAINCTL_MAX_ITEMS;
unsigned __read_mostly curtain_log_level = CURTAIN_TRAP;
unsigned __read_mostly curtain_sysctls_log_level = CURTAIN_TRAP;

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

SYSCTL_UINT(_security_curtain, OID_AUTO, sysctls_log_level,
    CTLFLAG_RW, &curtain_sysctls_log_level, 0,
    "");

static int
sysctl_curtain_max_items(SYSCTL_HANDLER_ARGS)
{
	int error, val;
	val = curtain_max_items_per_curtain;
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (!error && req->newptr) {
		if (val >= 0 && val <= (curtain_index)-1) {
			curtain_max_items_per_curtain = val;
		} else
			error = EINVAL;
	}
	return (error);
}

SYSCTL_PROC(_security_curtain, OID_AUTO, max_items_per_curtain,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_RESTRICT | CTLFLAG_MPSAFE, NULL, 0,
    sysctl_curtain_max_items, "I", "");

static int
sysctl_curtain_curtained(SYSCTL_HANDLER_ARGS)
{
	struct curtain *ct;
	int ret;
	ret = ((ct = CRED_SLOT(req->td->td_ucred)) ? ct->ct_cached.restrictive : 0);
	return (SYSCTL_OUT(req, &ret, sizeof(ret)));
}

SYSCTL_PROC(_security_curtain, OID_AUTO, curtained,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_RESTRICT | CTLFLAG_MPSAFE, NULL, 0,
    sysctl_curtain_curtained, "I", "");

static int
sysctl_curtain_curtained_exec(SYSCTL_HANDLER_ARGS)
{
	struct curtain *ct, *ct1;
	int ret;
	if ((ct = CRED_SLOT(req->td->td_ucred))) {
		ct1 = ct->ct_on_exec ? ct->ct_on_exec : ct;
		ret = ct1->ct_cached.restrictive;
	} else
		ret = 0;
	return (SYSCTL_OUT(req, &ret, sizeof(ret)));
}

SYSCTL_PROC(_security_curtain, OID_AUTO, curtained_exec,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_RESTRICT | CTLFLAG_MPSAFE, NULL, 0,
    sysctl_curtain_curtained_exec, "I", "");

#ifdef DDB

static void db_print_curtain(struct curtain *);

static int
sysctl_curtain_show(SYSCTL_HANDLER_ARGS)
{
	struct proc *p;
	struct curtain *ct;
	int val, error;
	if (!req->newptr)
		return (EINVAL);
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error)
		return (error);
	error = pget(val, PGET_CANDEBUG | PGET_NOTWEXIT, &p);
	if (error)
		return (error);
	if ((ct = CRED_SLOT(p->p_ucred)))
		ct = curtain_hold(ct);
	PROC_UNLOCK(p);
	if (ct) {
		db_print_curtain(ct);
		curtain_free(ct);
	}
	return (0);
}

SYSCTL_PROC(_debug, OID_AUTO, show_curtain,
    CTLTYPE_INT | CTLFLAG_WR | CTLFLAG_MPSAFE, NULL, 0,
    sysctl_curtain_show, "I", "");

#endif


/* Some abilities don't make much sense without some others. */
static const enum curtain_ability abilities_expand[][2] = {
	{ CURTAINABL_VFS_READ,		CURTAINABL_VFS_MISC		},
	{ CURTAINABL_VFS_WRITE,		CURTAINABL_VFS_MISC		},
	{ CURTAINABL_VFS_CREATE,	CURTAINABL_VFS_MISC		},
	{ CURTAINABL_VFS_DELETE,	CURTAINABL_VFS_MISC		},
	{ CURTAINABL_FATTR,		CURTAINABL_VFS_MISC		},
	{ CURTAINABL_PROT_EXEC,		CURTAINABL_PROT_EXEC_LOOSER	},
	{ CURTAINABL_PROT_EXEC_LOOSER,	CURTAINABL_PROT_EXEC_LOOSE	},
	{ CURTAINABL_MOUNT_NONUSER,	CURTAINABL_MOUNT		},
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
	do {
		propagate = false;
		for (size_t i = 0; i < nitems(abilities_expand); i++) {
			enum curtain_ability from = abilities_expand[i][0], to = abilities_expand[i][1];
			if (ct->ct_abilities[to].soft > ct->ct_abilities[from].soft) {
				ct->ct_abilities[to].soft = ct->ct_abilities[from].soft;
				propagate = true;
			}
		}
	} while (propagate);

	if (ct->ct_on_exec)
		curtain_fill_expand(ct->ct_on_exec);
}

static void
curtain_fill_restrict_exec(struct curtain *ct, struct ucred *cr)
{
	if (curtain_restrictive(ct) &&
	    ct->ct_abilities[CURTAINABL_EXEC_RSUGID].soft < CURTAIN_DENY &&
	    priv_check_cred(cr, PRIV_VFS_CHROOT) != 0)
		ct->ct_abilities[CURTAINABL_EXEC_RSUGID].soft = CURTAIN_DENY;
	if (ct->ct_on_exec)
		curtain_fill_restrict_exec(ct->ct_on_exec, cr);
}

static const enum curtain_action lvl2act[CURTAINLVL_COUNT] = {
	[CURTAINLVL_PASS] = CURTAIN_ALLOW,
	[CURTAINLVL_GATE] = CURTAIN_ALLOW,
	[CURTAINLVL_WALL] = CURTAIN_ALLOW,
	[CURTAINLVL_DENY] = CURTAIN_DENY,
	[CURTAINLVL_TRAP] = CURTAIN_TRAP,
	[CURTAINLVL_KILL] = CURTAIN_KILL,
};

static const barrier_bits abl2bar[CURTAINABL_COUNT][2] = {
	                         /* CURTAINLVL_GATE, CURTAINLVL_WALL */
	[CURTAINABL_DEFAULT]	= { BARRIER_DEVICE, BARRIER_NONE },
	[CURTAINABL_PROC]	= { BARRIER_PROC_SIGNAL, BARRIER_NONE },
	[CURTAINABL_PS]		= { BARRIER_PROC_STATUS, BARRIER_NONE },
	[CURTAINABL_SCHED]	= { BARRIER_PROC_SCHED, BARRIER_NONE },
	[CURTAINABL_DEBUG]	= { BARRIER_PROC_DEBUG, BARRIER_NONE },
	[CURTAINABL_SOCK]	= { BARRIER_SOCK, BARRIER_NONE },
	[CURTAINABL_POSIXIPC]	= { BARRIER_POSIXIPC, BARRIER_POSIXIPC_RENAME },
	[CURTAINABL_SYSVIPC]	= { BARRIER_SYSVIPC, BARRIER_NONE },
};

static void
curtain_fill_barrier_mode(struct barrier_mode *mode,
    enum curtainreq_level lvl, enum curtain_ability abl)
{
	mode->soft |= lvl >= CURTAINLVL_GATE ?  abl2bar[abl][0] : BARRIER_NONE;
	mode->soft &= lvl <  CURTAINLVL_GATE ? ~abl2bar[abl][0] : BARRIER_ALL;
	mode->soft |= lvl >= CURTAINLVL_WALL ?  abl2bar[abl][1] : BARRIER_NONE;
	mode->soft &= lvl <  CURTAINLVL_WALL ? ~abl2bar[abl][1] : BARRIER_ALL;
}

static void
curtain_fill_ability(struct curtain *ct, enum curtainreq_level lvl,
    enum curtain_ability abl)
{
	ct->ct_abilities[abl].soft = lvl2act[lvl];
	curtain_fill_barrier_mode(&CURTAIN_BARRIER(ct)->br_mode, lvl, abl);
}

static struct curtain_item *
curtain_fill_item(struct curtain *ct, enum curtain_type type, union curtain_key key,
    enum curtainreq_level lvl)
{
	struct curtain_item *item;
	item = curtain_search(ct, type, key, NULL);
	if (item) {
		item->mode.soft = lvl2act[lvl];
		item->mode.hard = CURTAIN_ALLOW;
	}
	return (item);
}

MALLOC_DECLARE(M_CURTAIN_UNVEIL);

static int
curtain_fill_unveil(struct curtain *ct, struct curtainent_unveil **ent_ret, char *end)
{
	struct curtainent_unveil *ent;
	struct file *fp;
	struct vnode *vp;
	struct curtain_item *item;
	char *name_end;
	size_t name_size, space;
	bool inserted, has_name;
	int error;

	ent = *ent_ret;

	name_end = memchr(ent->name, '\0', end - ent->name);
	if (!name_end)
		return (EINVAL);
	name_size = name_end - ent->name + 1;
	has_name = name_size > 1;

	error = getvnode_path(curthread, ent->dir_fd, &cap_no_rights, &fp);
	if (error)
		return (error);
	vp = fp->f_vnode;
	if (vp->v_type != VDIR) {
		fdrop(fp, curthread);
		return (ENOTDIR);
	}

	item = NULL;
	inserted = false;

	if (!has_name) {
		struct curtain_unveil uv = {
			.vp = vp,
			.hash = vp->v_nchash,
		};
		item = curtain_lookup(ct, CURTAIN_UNVEIL, (ctkey){ .unveil = &uv });
	}

	if (!item) {
		struct curtain_unveil *uv;
		uv = malloc(sizeof *uv + name_size, M_CURTAIN_UNVEIL, M_WAITOK);
		*uv = (struct curtain_unveil){
			.vp = vp,
			.hash = vp->v_nchash,
		};
		if (has_name) {
			uv->name_len = name_size - 1;
			memcpy(uv->name, ent->name, name_size);
			uv->hash = fnv_32_buf(uv->name, uv->name_len, uv->hash);
		}
		item = curtain_search(ct, CURTAIN_UNVEIL, (ctkey){ .unveil = uv }, &inserted);
		if (item && inserted) {
			item->mode.hard = item->mode.soft = CURTAIN_ALLOW;
			vref(uv->vp);
		} else
			free(uv, M_CURTAIN_UNVEIL);
	}

	if (item) {
		item->key.unveil->soft_uperms = uperms_expand(ent->uperms);
		item->key.unveil->hard_uperms = UPERM_ALL;
	}
	fdrop(fp, curthread);

	space = __align_up(name_size, __alignof(struct curtainent_unveil));
	if (space < name_size)
		return (EINVAL);
	if (end - ent->name < space)
		return (EINVAL);
	*ent_ret = (void *)(ent->name + space);

	return (0);
}

static int
curtain_fill_req(struct curtain *ct, const struct curtainreq *req)
{
	switch (req->type) {
	case CURTAINTYP_DEFAULT:
		/* handled earlier */
		break;
	case CURTAINTYP_ABILITY: {
		enum curtain_ability *ablp = req->data;
		size_t ablc = req->size / sizeof *ablp;
		while (ablc--) {
			enum curtain_ability abl = *ablp++;
			if (!CURTAINABL_USER_VALID(abl))
				return (EINVAL);
			curtain_fill_ability(ct, req->level, abl);
		}
		break;
	}
	case CURTAINTYP_IOCTL: {
		unsigned long *p = req->data;
		size_t c = req->size / sizeof *p;
		while (c--)
			curtain_fill_item(ct, CURTAIN_IOCTL,
			    (ctkey){ .ioctl = *p++ }, req->level);
		break;
	}
	case CURTAINTYP_SOCKAF: {
		int *p = req->data;
		size_t c = req->size / sizeof *p;
		while (c--)
			curtain_fill_item(ct, CURTAIN_SOCKAF,
			    (ctkey){ .sockaf = *p++ }, req->level);
		break;
	}
	case CURTAINTYP_SOCKLVL: {
		int *p = req->data;
		size_t c = req->size / sizeof *p;
		while (c--)
			curtain_fill_item(ct, CURTAIN_SOCKLVL,
			    (ctkey){ .socklvl = *p++ }, req->level);
		break;
	}

	case CURTAINTYP_GETSOCKOPT:
	case CURTAINTYP_SETSOCKOPT:
	case CURTAINTYP_SOCKOPT: {
		enum curtain_type type = req->type == CURTAINTYP_GETSOCKOPT ? CURTAIN_GETSOCKOPT :
		                         req->type == CURTAINTYP_SETSOCKOPT ? CURTAIN_SETSOCKOPT :
		                                                              CURTAIN_SOCKOPT;
		int (*p)[2] = req->data;
		size_t c = req->size / sizeof *p;
		while (c--) {
			curtain_fill_item(ct, type,
			    (ctkey){ .sockopt = { (*p)[0], (*p)[1] } }, req->level);
			p++;
		}
		break;
	}

	case CURTAINTYP_PRIV: {
		int *p = req->data;
		size_t c = req->size / sizeof *p;
		while (c--)
			curtain_fill_item(ct, CURTAIN_PRIV,
			    (ctkey){ .priv = *p++ }, req->level);
		break;
	}

	case CURTAINTYP_SYSCTL: {
		int *p = req->data;
		size_t c = req->size / sizeof *p;
		while (c--) {
			struct sysctl_shadow *sdw;
			size_t l;
			int error;
			l = *p++;
			if (l == 0 || l > c)
				return (EINVAL);
			error = sysctl_shadow_find(p, l, &sdw, NULL, NULL);
			if (!error)
				curtain_fill_item(ct, CURTAIN_SYSCTL,
				    (ctkey){ .sysctl = sdw }, req->level);
			else if (error != ENOENT)
				return (error);
			p += l;
			c -= l;
		}
		break;
	}

	case CURTAINTYP_FIBNUM: {
		int *p = req->data;
		size_t c = req->size / sizeof *p;
		while (c--)
			curtain_fill_item(ct, CURTAIN_FIBNUM,
			    (ctkey){ .fibnum = *p++ }, req->level);
		break;
	}

	case CURTAINTYP_UNVEIL: {
		struct curtainent_unveil *entp = (void *)req->data;
		char *endp = (char *)req->data + req->size;
		int error;
		while ((char *)entp < endp) {
			if (endp - (char *)entp < sizeof *entp)
				return (EINVAL);
			error = curtain_fill_unveil(ct, &entp, endp);
			if (error)
				return (error);
		}
		break;
	}
	default:
		return (EINVAL);
	}
	return (0);
}

static int
curtain_fill(struct curtain *ct, struct ucred *cr,
    int flags_filter, size_t reqc, const struct curtainreq *reqv)
{
	const struct curtainreq *req;
	enum curtainreq_level def;
	int error;

	SDT_PROBE2(curtain,, curtain_fill, begin, reqc, reqv);

	def = CURTAINLVL_KILL;
	for (req = reqv; req < &reqv[reqc]; req++)
		if (req->flags & flags_filter) {
			if (!(req->level >= 0 && req->level < CURTAINLVL_COUNT) ||
			    !(req->type >= CURTAINTYP_DEFAULT && req->type <= CURTAINTYP_LAST)) {
				error = EINVAL;
				goto fail;
			}
			if (req->type == CURTAINTYP_DEFAULT)
				def = req->level;
		}

	for (enum curtain_ability abl = 0; abl <= CURTAINABL_LAST; abl++) {
		ct->ct_abilities[abl].soft = lvl2act[def];
		curtain_fill_barrier_mode(&CURTAIN_BARRIER(ct)->br_mode, def, abl);
	}

	for (req = reqv; req < &reqv[reqc]; req++)
		if (req->flags & flags_filter) {
			error = curtain_fill_req(ct, req);
			if (error)
				goto fail;
		}

	if (ct->ct_overflowed || ct->ct_nitems > curtain_max_items_per_curtain) {
		error = E2BIG;
		goto fail;
	}

	error = curtain_fixup_unveils_parents(ct, cr);
	if (error)
		goto fail;

	SDT_PROBE1(curtain,, curtain_fill, done, ct);
	curtain_invariants_sync(ct);
	return (0);

fail:	SDT_PROBE0(curtain,, curtain_fill, failed);
	return (error);
}


static int
update_ucred_curtain(struct ucred *cr, struct curtain *ct, bool harden)
{
	struct curtain *old_ct;
	int error;

	/*
	 * NOTE: If multiple attempts are needed, the curtain may be masked
	 * multiple times.  This is fine since masking can only drop
	 * permissions.  This avoids having to do an extra copy.
	 */
	if ((old_ct = CRED_SLOT(cr)))
		curtain_mask(ct, old_ct);
	else
		curtain_mask_sysfils(ct, cr->cr_sysfilset);

	ct = curtain_dup(ct); /* compaction */
	if (old_ct)
		/* old_ct can still be used since there's still a reference to
		   it in the old ucred referenced by the caller. */
		curtain_free(old_ct);
	/* Must assign new curtain to (tentative) new ucred before we return so
	   that it can be cleaned up on failure. */
	mac_label_set(cr->cr_label, curtain_slot, (uintptr_t)ct);

	if (ct->ct_overflowed) /* masking can overflow */
		return (E2BIG);

	error = curtain_finish(ct, cr);
	if (error)
		return (error);

	if (harden)
		curtain_harden(ct);

	/* Will be unlinked on failure when the new ucred is freed. */
	if (old_ct)
		barrier_link(CURTAIN_BARRIER(ct), CURTAIN_BARRIER(old_ct));
	if (ct->ct_on_exec)
		barrier_link(CURTAIN_BARRIER(ct->ct_on_exec), CURTAIN_BARRIER(ct));

	curtain_cred_update(ct, cr);
	return (0);
}

static int
do_curtainctl(struct thread *td, int flags, size_t reqc, const struct curtainreq *reqv)
{
	struct proc *p = td->td_proc;
	struct ucred *new_cr, *old_cr;
	struct curtain *ct;
	int error;

	if (!curtainctl_enabled)
		return (ENOSYS);

	ct = curtain_make(curtain_max_items_per_curtain);
	/*
	 * TODO: Could skip filling a second curtain when all requests have the
	 * same flags, but libcurtain doesn't generate requests like that yet.
	 */
	ct->ct_on_exec = curtain_make(curtain_max_items_per_curtain);

	error = curtain_fill(ct, td->td_ucred, CURTAINREQ_ON_SELF, reqc, reqv);
	if (error) {
		curtain_free(ct);
		return (error);
	}
	error = curtain_fill(ct->ct_on_exec, td->td_ucred, CURTAINREQ_ON_EXEC, reqc, reqv);
	if (error) {
		curtain_free(ct);
		return (error);
	}

	curtain_fill_expand(ct);
	curtain_fill_restrict_exec(ct->ct_on_exec ? ct->ct_on_exec : ct, td->td_ucred);

	/*
	 * Mask the requested curtain against the curtain (or sysfilset) of the
	 * process' current ucred, compact it and associate it with a new ucred
	 * while dealing with the current ucred potentially changing in-between
	 * process unlocks.
	 */
	do {
		new_cr = crget();
		PROC_LOCK(p);
		old_cr = crcopysafe(p, new_cr);
		crhold(old_cr);
		PROC_UNLOCK(p);
		error = update_ucred_curtain(new_cr, ct, !(flags & CURTAINCTL_SOFT));
		if (error) {
			crfree(old_cr);
			crfree(new_cr);
			curtain_free(ct);
			return (error);
		}
		PROC_LOCK(p);
		if (old_cr == p->p_ucred) {
			crfree(old_cr);
			curtain_free(ct);
			ct = NULL;
			break;
		}
		PROC_UNLOCK(p);
		crfree(old_cr);
		crfree(new_cr);
	} while (true);

	if (flags & CURTAINCTL_REPLACE) {
		proc_set_cred(p, new_cr);
		if (CRED_IN_RESTRICTED_MODE(new_cr) != PROC_IN_RESTRICTED_MODE(p))
			panic("PROC_IN_RESTRICTED_MODE() bogus");
		PROC_UNLOCK(p);
		crfree(old_cr);
		unveil_proc_get_cache(p, true);
	} else {
		PROC_UNLOCK(p);
		crfree(new_cr);
	}
	return (0);
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


#ifdef DDB

static void
db_print_curtain(struct curtain *ct)
{
#ifdef INVARIANTS
	if (ct->ct_magic != CURTAIN_MAGIC) {
		db_printf("%p: invalid ct_magic!\n", ct);
		return;
	}
#endif
	db_printf("curtain at %p ct_ref: %d\n", ct, ct->ct_ref);
	db_printf("ct_on_exec: %p\n", ct->ct_on_exec);
	db_printf("ct_nslots: %u ct_nitems: %u ct_modulo: %u ct_cellar: %u\n",
	    ct->ct_nslots, ct->ct_nitems, ct->ct_modulo, ct->ct_cellar);
	db_printf("ct_overflowed: %d\n", ct->ct_overflowed);
	db_printf("ct_cached:\n");
	db_printf("\tvalid: %d restrictive: %d sysfilset: %#016jx\n",
	    ct->ct_cached.valid, ct->ct_cached.restrictive, ct->ct_cached.sysfilset);
	db_printf("ct_abilities:\n");
	for (enum curtain_ability abl = 0; abl <= CURTAINABL_LAST; abl++)
		db_printf("\tability: %3d soft: %d hard: %d\n", abl,
		    ct->ct_abilities[abl].soft, ct->ct_abilities[abl].hard);
	db_printf("ct_slots:\n");
	for (struct curtain_item *item = ct->ct_slots; item < &ct->ct_slots[ct->ct_nslots]; item++)
		if (item->type != 0) {
			union curtain_key key = item->key;
			db_printf("\tslot: %3zu chain: %3zu type: %2d soft: %d hard: %d",
			    (size_t)(item - ct->ct_slots), (size_t)item->chain,
			    item->type, item->mode.soft, item->mode.hard);
			switch (item->type) {
			case CURTAIN_IOCTL:
				db_printf(" ioctl: %#jx\n", (uintmax_t)key.ioctl);
				break;
			case CURTAIN_SOCKAF:
				db_printf(" sockaf: %d\n", key.sockaf);
				break;
			case CURTAIN_SOCKLVL:
				db_printf(" socklvl: %d\n", key.socklvl);
				break;
			case CURTAIN_GETSOCKOPT:
			case CURTAIN_SETSOCKOPT:
			case CURTAIN_SOCKOPT:
				db_printf(" %ssockopt: %d:%d\n",
				    item->type == CURTAIN_GETSOCKOPT ? "get" :
				    item->type == CURTAIN_SETSOCKOPT ? "set" : "",
				    key.sockopt.level, key.sockopt.optname);
				break;
			case CURTAIN_PRIV:
				db_printf(" priv: %d\n", key.priv);
				break;
			case CURTAIN_SYSCTL:
				db_printf(" sysctl: %p\n", key.sysctl);
				break;
			case CURTAIN_FIBNUM:
				db_printf(" fibnum: %d\n", key.fibnum);
				break;
			case CURTAIN_UNVEIL:
				db_printf(" unveil: %p parent: %p\n",
				    key.unveil, key.unveil->parent);
				db_printf("\t\tvp: %p", key.unveil->vp);
				if (key.unveil->name_len != 0)
					db_printf(" name: \"%s\"", key.unveil->name);
				db_printf(" hash: 0x%08x\n", key.unveil->hash);
				db_printf("\t\tsoft-uperms: 0x%08x hard-uperms: 0x%08x\n",
				    key.unveil->soft_uperms, key.unveil->hard_uperms);
				if (key.unveil->vp) {
					int error;
					char *fullpath, *freepath;
					freepath = fullpath = NULL;
					error = vn_fullpath(key.unveil->vp, &fullpath, &freepath);
					if (error)
						db_printf("\t\tpath error: %d\n", error);
					else if (key.unveil->name_len)
						db_printf("\t\tpath: %s/%s\n",
						    fullpath, key.unveil->name);
					else
						db_printf("\t\tpath: %s\n", fullpath);
					if (freepath)
						free(freepath, M_TEMP);
				}
				break;
			default:
				db_printf("\n");
				break;
			}
		}
	if (ct->ct_on_exec)
		db_print_curtain(ct->ct_on_exec);
}

DB_SHOW_COMMAND(curtain, db_show_curtain)
{
	if (!have_addr) {
		db_printf("usage: show curtain <addr>\n");
		return;
	}
	db_print_curtain((void *)addr);
}

DB_SHOW_ALL_COMMAND(curtains, db_show_all_curtains)
{
	struct proc *p;
	FOREACH_PROC_IN_SYSTEM(p) {
		struct curtain *ct;
		if (p->p_state == PRS_NEW)
			continue;
		if (p->p_ucred && (ct = CRED_SLOT(p->p_ucred))) {
			db_printf("proc at %p pid %d\n", p, p->p_pid);
			db_print_curtain(ct);
			db_printf("\n");
		}
	}
}

#endif


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

