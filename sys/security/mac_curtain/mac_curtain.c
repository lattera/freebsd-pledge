#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/ucred.h>
#include <sys/syslog.h>
#include <sys/sysctl.h>
#include <sys/priv.h>
#include <sys/jail.h>
#include <sys/mman.h>
#include <sys/counter.h>
#include <sys/sdt.h>
#include <sys/rwlock.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/syscall.h>
#include <sys/sysfil.h>
#include <sys/sbuf.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/mount.h>

#include <security/mac_curtain/curtain_int.h>
#include <security/mac/mac_policy.h>

#include <sys/imgact.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockopt.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/filio.h>
#include <sys/tty.h>

SDT_PROBE_DEFINE3(curtain,, cred_key_check, check,
    "struct ucred *", "enum curtain_type", "union curtain_key *");
SDT_PROBE_DEFINE5(curtain,, cred_key_check, failed,
    "struct ucred *", "enum curtain_type", "union curtain_key *",
    "enum curtain_action", "bool");
SDT_PROBE_DEFINE3(curtain,, cred_sysfil_check, failed,
    "struct ucred *", "sysfilset_t", "enum curtain_action");

#ifdef CURTAIN_STATS

#define STATNODE_COUNTER(name, varname, descr)				\
	static COUNTER_U64_DEFINE_EARLY(varname);			\
	SYSCTL_COUNTER_U64(_security_curtain_stats, OID_AUTO, name,	\
	    CTLFLAG_RD, &varname, descr);

STATNODE_COUNTER(check_denies, curtain_stats_check_denies, "");
STATNODE_COUNTER(check_traps, curtain_stats_check_traps, "");
STATNODE_COUNTER(check_kills, curtain_stats_check_kills, "");

#endif

typedef union curtain_key ctkey;

#define	CTH_IS_CT(l) CURTAIN_CTH_IS_CT(l)
#define	SLOT_CTH(l) CURTAIN_SLOT_CTH(l)
#define	SLOT_CT(l) CURTAIN_SLOT_CT(l)
#define	SLOT_BR(l) CURTAIN_SLOT_BR(l)
#define	CRED_SLOT(cr) CURTAIN_SLOT_CT((cr)->cr_label)
#define	CRED_SLOT_BR(cr) CURTAIN_SLOT_BR((cr)->cr_label)
#define	SLOT_SET(l, val) mac_label_set((l), curtain_slot, (uintptr_t)(val))

int __read_mostly curtain_slot;

static const char act2str[][6] = {
	[CURTAIN_ALLOW] = "allow",
	[CURTAIN_DENY] = "deny",
	[CURTAIN_TRAP] = "trap",
	[CURTAIN_KILL] = "kill",
};

static const int act2err[] = {
	[CURTAIN_ALLOW] = 0,
	[CURTAIN_DENY] = SYSFIL_FAILED_ERRNO,
	[CURTAIN_TRAP] = ESYSFILTRAP,
	[CURTAIN_KILL] = ESYSFILKILL,
};

#define	CURTAIN_LOG(td, cat, fmt, ...) do { \
	log(LOG_ERR, "curtain %s: pid %d (%s), jid %d, uid %d: " fmt "\n", \
	    cat, (td)->td_proc->p_pid, (td)->td_proc->p_comm, \
	    (td)->td_ucred->cr_prison->pr_id, (td)->td_ucred->cr_uid, \
	    __VA_ARGS__); \
} while (0)

#define	CURTAIN_LOG_ACTION(td, act, fmt, ...) do { \
	if ((act) >= curtain_log_level) \
		CURTAIN_LOG(td, act2str[act], fmt, __VA_ARGS__); \
} while (0)

#define	CURTAIN_CRED_LOG(cr, cat, fmt, ...) do { \
	if ((cr) == curthread->td_ucred) /* XXX */ \
		CURTAIN_LOG(curthread, (cat), fmt, __VA_ARGS__); \
} while (0)

#define	CURTAIN_CRED_LOG_ACTION(cr, act, fmt, ...) do { \
	if ((cr) == curthread->td_ucred) /* XXX */ \
		CURTAIN_LOG_ACTION(curthread, (act), fmt, __VA_ARGS__); \
} while (0)

static void
cred_action_failed(const struct ucred *cr, enum curtain_action act, bool noise)
{
#ifdef CURTAIN_STATS
	if (!noise)
		switch (act) {
		case CURTAIN_ALLOW:
			break;
		case CURTAIN_DENY:
			counter_u64_add(curtain_stats_check_denies, 1);
			break;
		case CURTAIN_TRAP:
			counter_u64_add(curtain_stats_check_traps, 1);
			break;
		case CURTAIN_KILL:
			counter_u64_add(curtain_stats_check_kills, 1);
			break;
		}
#endif
}

static inline enum curtain_action
cred_key_action(const struct ucred *cr, enum curtain_type type, union curtain_key key)
{
	const struct curtain *ct;
	if ((ct = CRED_SLOT(cr)))
		return (curtain_resolve(ct, type, key).soft);
	else
		return (CURTAIN_ALLOW);
}

static inline enum curtain_action
cred_ability_action(const struct ucred *cr, enum curtain_ability abl)
{
	return (cred_key_action(cr, CURTAIN_ABILITY, (ctkey){ .ability = abl }));
}

static void
cred_key_failed(const struct ucred *cr, enum curtain_type type, union curtain_key key,
    enum curtain_action act)
{
	bool noise = false;
	switch (type) {
	case CURTAIN_UNVEIL:
	case CURTAIN_SYSCTL:
		noise = true;
		break;
	case CURTAIN_ABILITY:
		CURTAIN_CRED_LOG_ACTION(cr, act, "ability %d", key.ability);
		break;
	case CURTAIN_IOCTL:
		CURTAIN_CRED_LOG_ACTION(cr, act, "ioctl %#jx", (uintmax_t)key.ioctl);
		break;
	case CURTAIN_SOCKAF:
		CURTAIN_CRED_LOG_ACTION(cr, act, "sockaf %d", key.sockaf);
		break;
	case CURTAIN_SOCKLVL:
		CURTAIN_CRED_LOG_ACTION(cr, act, "socklvl %d", key.socklvl);
		break;
	case CURTAIN_GETSOCKOPT:
	case CURTAIN_SETSOCKOPT:
	case CURTAIN_SOCKOPT:
		CURTAIN_CRED_LOG_ACTION(cr, act, "%ssockopt %d:%d",
		    type == CURTAIN_GETSOCKOPT ? "get" :
		    type == CURTAIN_SETSOCKOPT ? "set" : "",
		    key.sockopt.level, key.sockopt.optname);
		break;
	case CURTAIN_PRIV:
		/*
		 * Some priv_check()/priv_check_cred() callers just compare the
		 * error value against 0 without returning it.  Some privileges
		 * are checked in this way so often that it shouldn't be logged.
		 */
		switch (key.priv) {
		case PRIV_VFS_GENERATION:
		case PRIV_VFS_EXCEEDQUOTA:
		case PRIV_VFS_SYSFLAGS:
		case PRIV_NETINET_REUSEPORT:
			noise = true;
			break;
		default:
			CURTAIN_CRED_LOG_ACTION(cr, act, "priv %d", key.priv);
			break;
		}
		break;
	case CURTAIN_FIBNUM:
		CURTAIN_CRED_LOG_ACTION(cr, act, "fibnum %d", key.fibnum);
		break;
	}
	SDT_PROBE5(curtain,, cred_key_check, failed, cr, type, &key, act, noise);
	cred_action_failed(cr, act, noise);
}

static inline int
cred_key_check(const struct ucred *cr, enum curtain_type type, union curtain_key key)
{
	enum curtain_action act;
	SDT_PROBE3(curtain,, cred_key_check, check, cr, type, &key);
	act = cred_key_action(cr, type, key);
	if (__predict_true(act == CURTAIN_ALLOW))
		return (0);
	cred_key_failed(cr, type, key, act);
	return (act2err[act]);
}

static inline int
cred_ability_check(const struct ucred *cr, enum curtain_ability abl)
{
	return (cred_key_check(cr, CURTAIN_ABILITY, (ctkey){ .ability = abl }));
}


static void
curtain_cred_init_label(struct label *label)
{
	if (label)
		SLOT_SET(label, NULL);
}

static void
curtain_cred_copy_label(struct label *src, struct label *dst)
{
	if (dst) {
		struct curtain_head *cth;
		if ((cth = SLOT_CTH(dst))) {
			if (CTH_IS_CT(cth))
				curtain_free((struct curtain *)cth);
			else
				barrier_free((struct barrier *)cth);
		}
		if (src && (cth = SLOT_CTH(src))) {
			if (CTH_IS_CT(cth))
				SLOT_SET(dst, curtain_hold((struct curtain *)cth));
			else
				SLOT_SET(dst, barrier_hold((struct barrier *)cth));
		} else
			SLOT_SET(dst, NULL);
	}
}

static void
curtain_cred_destroy_label(struct label *label)
{
	if (label) {
		struct curtain_head *cth;
		if ((cth = SLOT_CTH(label))) {
			if (CTH_IS_CT(cth))
				curtain_free((struct curtain *)cth);
			else
				barrier_free((struct barrier *)cth);
		}
		SLOT_SET(label, NULL);
	}
}

static int
curtain_cred_externalize_label(struct label *label, char *element_name,
    struct sbuf *sb, int *claimed)
{
	struct curtain *ct;
	struct barrier *br;
	if (!(ct = SLOT_CT(label)) || strcmp("curtain", element_name) != 0)
		return (0);
	(*claimed)++;
	br = CURTAIN_BARRIER(ct);
	sbuf_printf(sb, "%ju", (uintmax_t)br->br_serial);
	return (sbuf_error(sb) ? EINVAL : 0);
}


static void
curtain_init_label_barrier(struct label *label)
{
	if (label)
		SLOT_SET(label, NULL);
}

static void
curtain_copy_label_barrier(struct label *src, struct label *dst)
{
	if (dst) {
		struct barrier *br;
		if ((br = SLOT_BR(dst)))
			barrier_free(br);
		if (src && (br = SLOT_BR(src)))
			SLOT_SET(dst, barrier_hold(br));
		else
			SLOT_SET(dst, NULL);
	}
}

static void
curtain_destroy_label_barrier(struct label *label)
{
	if (label) {
		struct barrier *br;
		if ((br = SLOT_BR(label)))
			barrier_free(br);
		SLOT_SET(label, NULL);
	}
}

static int
curtain_cred_check_visible(struct ucred *cr1, struct ucred *cr2)
{
	/*
	 * XXX This currently allows too much:
	 *
	 * - Listing active local domain sockets (sysctl blocked by default).
	 * - Certain procctl(2) operations (partially limited with sysfils).
	 * - Some TCP/syncache state inspection (sysctl blocked by default).
	 * - Others?
	 */
	if (!barrier_visible(CRED_SLOT_BR(cr1), CRED_SLOT_BR(cr2), BARRIER_PROC_STATUS))
		return (ESRCH);
	return (0);
}

static void
curtain_cred_trim(struct ucred *cr)
{
	struct curtain *ct;
	struct barrier *br;
	if (!(ct = CRED_SLOT(cr)))
		return;
	br = barrier_hold(CURTAIN_BARRIER(ct));
	SLOT_SET(cr->cr_label, &br->br_head);
	curtain_free(ct);
}


static int
curtain_proc_check_signal(struct ucred *cr, struct proc *p, int signum)
{
	int error;
	if ((error = cred_ability_check(cr, CURTAINABL_PROC)))
		return (error);
	if (!barrier_visible(CRED_SLOT_BR(cr), CRED_SLOT_BR(p->p_ucred), BARRIER_PROC_SIGNAL))
		return (ESRCH);
	return (0);
}

static int
curtain_proc_check_sched(struct ucred *cr, struct proc *p)
{
	int error;
	if ((error = cred_ability_check(cr, CURTAINABL_SCHED)))
		return (error);
	if (!barrier_visible(CRED_SLOT_BR(cr), CRED_SLOT_BR(p->p_ucred), BARRIER_PROC_SCHED))
		return (ESRCH);
	return (0);
}

static int
curtain_proc_check_debug(struct ucred *cr, struct proc *p)
{
	int error;
	if ((error = cred_ability_check(cr, CURTAINABL_DEBUG)))
		return (error);
	if (!barrier_visible(CRED_SLOT_BR(cr), CRED_SLOT_BR(p->p_ucred), BARRIER_PROC_DEBUG))
		return (ESRCH);
	return (0);
}


static int
curtain_socket_check_create(struct ucred *cr, int domain, int type, int protocol)
{
	int error;
	if ((error = cred_ability_check(cr, CURTAINABL_SOCK)))
		return (error);
	return (cred_key_check(cr, CURTAIN_SOCKAF, (ctkey){ .sockaf = domain }));
}

static int
curtain_socket_check_bind(struct ucred *cr, struct socket *so, struct label *solabel,
    struct sockaddr *sa)
{
	int sockaf, error;
	sockaf = sa->sa_family == AF_UNSPEC ? so->so_proto->pr_domain->dom_family : sa->sa_family;
	if (sockaf != AF_LOCAL && (error = cred_ability_check(cr, CURTAINABL_NET_SERVER)))
		return (error);
	return (cred_key_check(cr, CURTAIN_SOCKAF, (ctkey){ .sockaf = sockaf }));
}

static int
curtain_socket_check_connect(struct ucred *cr, struct socket *so, struct label *solabel,
    struct sockaddr *sa)
{
	int sockaf, error;
	sockaf = sa->sa_family;
	if (sockaf != AF_LOCAL && (error = cred_ability_check(cr, CURTAINABL_NET_CLIENT)))
		return (error);
	return (cred_key_check(cr, CURTAIN_SOCKAF, (ctkey){ .sockaf = sockaf }));
}

static int
curtain_socket_check_sockopt(struct ucred *cr, struct socket *so, struct label *solabel,
    struct sockopt *sopt)
{
	return (cred_key_check(cr,
	    sopt->sopt_dir == SOPT_GET ? CURTAIN_GETSOCKOPT : CURTAIN_SETSOCKOPT,
	    (ctkey){ .sockopt = { sopt->sopt_level, sopt->sopt_name } }));
}

static int
curtain_socket_check_visible(struct ucred *cr, struct socket *so, struct label *solabel)
{
	int error;
	if ((error = cred_ability_check(cr, CURTAINABL_SOCK)))
		return (error);
	error = 0;
	SOCK_LOCK(so);
	if (!barrier_visible(CRED_SLOT_BR(cr), SLOT_BR(solabel), BARRIER_SOCK))
		error = ENOENT;
	SOCK_UNLOCK(so);
	return (error);
}


static int
curtain_inpcb_check_visible(struct ucred *cr, struct inpcb *inp, struct label *inplabel)
{
	int error;
	if ((error = cred_ability_check(cr, CURTAINABL_SOCK)))
		return (error);
	if (!barrier_visible(CRED_SLOT_BR(cr), SLOT_BR(inplabel), BARRIER_SOCK))
		return (ENOENT);
	return (0);
}


static int
curtain_net_check_fibnum(struct ucred *cr, int fibnum)
{
	return (cred_key_check(cr, CURTAIN_FIBNUM, (ctkey){ .fibnum = fibnum }));
}


static inline int
check_uperms(unveil_perms uhave, unveil_perms uneed)
{
	if (uperms_contains(uhave, uneed))
		return (0);
	return (uhave & UPERM_EXPOSE ? EACCES : ENOENT);
}

static unveil_perms
get_vp_uperms(struct ucred *cr, struct vnode *vp)
{
	struct unveil_tracker *track;
	struct unveil_tracker_entry *entry;
	if (CRED_IN_VFS_VEILED_MODE(cr)) {
		if ((track = unveil_track_get(cr, false)) &&
		    (entry = unveil_track_find(track, vp)))
			return (entry->uperms);
		return (UPERM_NONE);
	}
	return (UPERM_ALL);
}

/* To be used for file creation when the target might not already exist. */
static unveil_perms
get_vp_pending_uperms(struct ucred *cr, struct vnode *dvp, struct vnode *vp)
{
	struct unveil_tracker *track;
	struct unveil_tracker_entry *entry;
	if (CRED_IN_VFS_VEILED_MODE(cr)) {
		if ((track = unveil_track_get(cr, false))) {
			if (vp && (entry = unveil_track_find(track, vp)))
				return (entry->uperms);
			if ((entry = unveil_track_find(track, dvp)))
				return (entry->pending_uperms);
		}
		return (UPERM_NONE);
	}
	return (UPERM_ALL);
}

static int
check_fmode(struct ucred *cr, mode_t mode)
{
	if (mode & (S_ISUID|S_ISGID))
		return (cred_ability_check(cr, CURTAINABL_FSUGID));
	return (0);
}

static int
check_accmode(struct ucred *cr, unveil_perms uperms, enum vtype type, accmode_t accmode)
{
	int error;
	switch (type) {
	case VSOCK:
		if ((error = check_uperms(uperms, UPERM_CONNECT)))
			return (error);
		break;
	case VDIR:
		if (accmode & VREAD &&
		    (error = check_uperms(uperms, UPERM_LIST)))
			return (error);
		if (accmode & VWRITE &&
		    (error = check_uperms(uperms,
		    accmode & VAPPEND ? UPERM_APPEND : UPERM_WRITE)))
			return (error);
		if (accmode & VEXEC && (error = check_uperms(uperms, UPERM_SEARCH)))
			return (error);
		break;
	case VREG:
		if (!(uperms & UPERM_TMPDIR_CHILD)) {
	default:	if (accmode & VREAD &&
			    (error = check_uperms(uperms, UPERM_READ)))
				return (error);
			if (accmode & VWRITE &&
			    (error = check_uperms(uperms,
			    accmode & VAPPEND ? UPERM_APPEND : UPERM_WRITE)))
				return (error);
		}
		if (accmode & VEXEC &&
		    (error = check_uperms(uperms, UPERM_EXECUTE)))
			return (error);
		break;
	}
	return (0);
}

static int
curtain_vnode_check_access(struct ucred *cr,
    struct vnode *vp, struct label *vplabel, accmode_t accmode)
{
	return (check_accmode(cr, get_vp_uperms(cr, vp), vp->v_type, accmode));
}

static int
curtain_vnode_check_open(struct ucred *cr,
    struct vnode *vp, struct label *vplabel, accmode_t accmode)
{
	int error;

	if ((error = check_accmode(cr, get_vp_uperms(cr, vp), vp->v_type, accmode)))
		return (error);

	if (vp->v_type == VSOCK) {
		if ((error = cred_ability_check(cr, CURTAINABL_VFS_CONNECT)))
			return (error);
	} else {
		if (vp->v_type == VFIFO) {
			if ((error = cred_ability_check(cr, CURTAINABL_VFS_FIFO)))
				return (error);
		}
		if (accmode & VREAD && (error = cred_ability_check(cr, CURTAINABL_VFS_READ)))
			return (error);
		if (accmode & VWRITE && (error = cred_ability_check(cr, CURTAINABL_VFS_WRITE)))
			return (error);
		if (accmode & VEXEC &&
		    (error = cred_ability_check(cr, vp->v_type == VDIR ?
		    CURTAINABL_VFS_READ : CURTAINABL_EXEC)))
			return (error);
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
	uperms = get_vp_uperms(cr, vp);
	if (!(uperms & UPERM_TMPDIR_CHILD && vp->v_type == VREG) &&
	    (error = check_uperms(uperms, UPERM_READ)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_VFS_READ)))
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
	uperms = get_vp_uperms(cr, vp);
	if (!(uperms & UPERM_TMPDIR_CHILD && vp->v_type == VREG) &&
	    (error = check_uperms(uperms, UPERM_WRITE)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_VFS_WRITE)))
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

	if (vap->va_mode != (mode_t)VNOVAL &&
	    (error = check_fmode(cr, vap->va_mode)))
		return (error);

	uperms = get_vp_pending_uperms(cr, dvp, NULL);

	if (vap->va_type == VSOCK) {
		if ((error = check_uperms(uperms, UPERM_BIND)))
			return (error);
	} else {
		if (!(uperms & UPERM_TMPDIR_CHILD && vap->va_type == VREG) &&
		    (error = check_uperms(uperms, UPERM_CREATE)))
			return (error);
	}

	if (vap->va_type == VSOCK) {
		if ((error = cred_ability_check(cr, CURTAINABL_VFS_BIND)))
			return (error);
	} else {
		if (vap->va_type == VFIFO) {
			if ((error = cred_ability_check(cr, CURTAINABL_VFS_FIFO)))
				return (error);
		}
		if ((error = cred_ability_check(cr, CURTAINABL_VFS_CREATE)))
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
	if ((error = check_uperms(get_vp_uperms(cr, from_vp),
	    UPERM_READ | UPERM_WRITE | UPERM_SETATTR | UPERM_CREATE | UPERM_DELETE)))
		return (error);
	if ((error = check_uperms(get_vp_pending_uperms(cr, to_dvp, NULL), UPERM_CREATE)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_VFS_CREATE)))
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

	uperms = get_vp_uperms(cr, vp);

	if (vp->v_type == VSOCK) {
		if ((error = check_uperms(uperms, UPERM_BIND)))
			return (error);
	} else {
		if (!(uperms & UPERM_TMPDIR_CHILD && vp->v_type == VREG) &&
		    (error = check_uperms(uperms, UPERM_DELETE)))
			return (error);
	}

	if (vp->v_type == VSOCK) {
		if ((error = cred_ability_check(cr, CURTAINABL_VFS_BIND)))
			return (error);
	} else {
		if ((error = cred_ability_check(cr, CURTAINABL_VFS_DELETE)))
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
	if ((error = check_uperms(get_vp_uperms(cr, vp), UPERM_DELETE | UPERM_READ)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_VFS_DELETE)))
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
	if (vp && (error = check_uperms(get_vp_uperms(cr, vp), UPERM_DELETE)))
		return (error);
	if ((error = check_uperms(get_vp_pending_uperms(cr, dvp, vp), UPERM_CREATE)))
		return (error);
	if (vp && (error = cred_ability_check(cr, CURTAINABL_VFS_DELETE)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_VFS_CREATE)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_chdir(struct ucred *cr, struct vnode *dvp, struct label *dvplabel)
{
	int error;
	if ((error = check_uperms(get_vp_uperms(cr, dvp), UPERM_SEARCH)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_VFS_READ)))
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
	uperms = get_vp_uperms(cr, vp);
	if (!(uperms & UPERM_TMPDIR_CHILD && vp->v_type == VREG) &&
	    (error = check_uperms(uperms, UPERM_STATUS)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_VFS_READ)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_lookup(struct ucred *cr,
    struct vnode *dvp, struct label *dvplabel, struct componentname *cnp)
{
	int error;
	if ((error = check_uperms(get_vp_uperms(cr, dvp), UPERM_TRAVERSE)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_VFS_MISC)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_readlink(struct ucred *cr, struct vnode *vp, struct label *vplabel)
{
	int error;
	if ((error = check_uperms(get_vp_uperms(cr, vp), UPERM_TRAVERSE)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_VFS_MISC)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_setflags(struct ucred *cr,
    struct vnode *vp, struct label *vplabel, u_long flags)
{
	int error;
	if ((error = check_uperms(get_vp_uperms(cr, vp), UPERM_SETATTR)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_FATTR)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_CHFLAGS)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_setmode(struct ucred *cr,
    struct vnode *vp, struct label *vplabel, mode_t mode)
{
	unveil_perms uperms;
	int error;
	uperms = get_vp_uperms(cr, vp);
	if ((error = check_fmode(cr, mode)))
		return (error);
	if ((error = check_uperms(uperms, UPERM_SETATTR)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_FATTR)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_setowner(struct ucred *cr,
    struct vnode *vp, struct label *vplabel, uid_t uid, gid_t gid)
{
	int error;
	if ((error = check_uperms(get_vp_uperms(cr, vp), UPERM_SETATTR)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_FATTR)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_setutimes(struct ucred *cr,
    struct vnode *vp, struct label *vplabel,
    struct timespec atime, struct timespec mtime)
{
	int error;
	if ((error = check_uperms(get_vp_uperms(cr, vp), UPERM_SETATTR)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_FATTR)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_listextattr(struct ucred *cr,
    struct vnode *vp, struct label *vplabel, int attrnamespace)
{
	int error;
	if ((error = check_uperms(get_vp_uperms(cr, vp), UPERM_READ)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_EXTATTR)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_VFS_READ)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_getextattr(struct ucred *cr,
    struct vnode *vp, struct label *vplabel, int attrnamespace, const char *name)
{
	int error;
	if ((error = check_uperms(get_vp_uperms(cr, vp), UPERM_READ)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_EXTATTR)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_VFS_READ)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_setextattr(struct ucred *cr,
    struct vnode *vp, struct label *vplabel, int attrnamespace, const char *name)
{
	int error;
	if ((error = check_uperms(get_vp_uperms(cr, vp), UPERM_SETATTR)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_EXTATTR)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_FATTR)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_deleteextattr(struct ucred *cr,
    struct vnode *vp, struct label *vplabel, int attrnamespace, const char *name)
{
	int error;
	if ((error = check_uperms(get_vp_uperms(cr, vp), UPERM_SETATTR)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_EXTATTR)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_FATTR)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_getacl(struct ucred *cr,
    struct vnode *vp, struct label *vplabel, acl_type_t type)
{
	int error;
	if ((error = check_uperms(get_vp_uperms(cr, vp), UPERM_STATUS)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_ACL)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_VFS_READ)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_setacl(struct ucred *cr,
    struct vnode *vp, struct label *vplabel, acl_type_t type, struct acl *acl)
{
	int error;
	if ((error = check_uperms(get_vp_uperms(cr, vp), UPERM_SETATTR)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_ACL)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_FATTR)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_deleteacl(struct ucred *cr,
    struct vnode *vp, struct label *vplabel, acl_type_t type)
{
	int error;
	if ((error = check_uperms(get_vp_uperms(cr, vp), UPERM_SETATTR)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_ACL)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_FATTR)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_relabel(struct ucred *cr,
    struct vnode *vp, struct label *vplabel, struct label *newlabel)
{
	int error;
	if ((error = check_uperms(get_vp_uperms(cr, vp), UPERM_SETATTR)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_MAC)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_FATTR)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_revoke(struct ucred *cr, struct vnode *vp, struct label *vplabel)
{
	int error;
	if ((error = check_uperms(get_vp_uperms(cr, vp), UPERM_SETATTR)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_TTY)))
		return (error);
	return (0);
}

static int
curtain_vnode_check_exec(struct ucred *cr,
    struct vnode *vp, struct label *vplabel,
    struct image_params *imgp, struct label *execlabel)
{
	int error;
	if ((error = check_uperms(get_vp_uperms(cr, vp), UPERM_SHELL)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_EXEC)))
		return (error);
	return (0);
}


static int
curtain_mount_check_stat(struct ucred *cr,
    struct mount *mp, struct label *mplabel)
{
	unveil_perms uperms;
	int error;
	if (CRED_IN_VFS_VEILED_MODE(cr) &&
	    cred_ability_action(cr, CURTAINABL_MOUNT_SEE_ALL) != CURTAIN_ALLOW) {
		struct curtain *ct;
		if (mtx_owned(&mountlist_mtx)) { /* getfsstat(2)? */
			if ((ct = CRED_SLOT(cr)))
				uperms = curtain_lookup_mount(ct, mp);
			else
				uperms = UPERM_NONE;
		} else {
			struct unveil_tracker *track;
			struct unveil_tracker_entry *entry;
			if ((track = unveil_track_get(cr, false)) &&
			    (entry = unveil_track_find_mount(track, mp)))
				uperms = entry->uperms;
			else
				uperms = UPERM_NONE;
		}
	} else
		uperms = UPERM_ALL;
	if ((error = check_uperms(uperms, UPERM_STATUS)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_VFS_MISC)))
		return (error);
	return (0);
}


static void curtain_posixshm_create(struct ucred *cr,
    struct shmfd *shmfd, struct label *shmlabel)
{
	curtain_copy_label_barrier(cr->cr_label, shmlabel);
}

static int
curtain_posixshm_check_open(struct ucred *cr,
    struct shmfd *shmfd, struct label *shmlabel,
    accmode_t accmode)
{
	if (!barrier_visible(CRED_SLOT_BR(cr), SLOT_BR(shmlabel), BARRIER_POSIXIPC))
		return (ENOENT);
	return (0);
}

static int
curtain_posixshm_check_unlink(struct ucred *cr,
    struct shmfd *shmfd, struct label *shmlabel)
{
	if (!barrier_visible(CRED_SLOT_BR(cr), SLOT_BR(shmlabel), BARRIER_POSIXIPC))
		return (ENOENT);
	return (0);
}

static int
curtain_posixshm_check_setmode(struct ucred *cr,
    struct shmfd *shmfd, struct label *shmlabel,
    mode_t mode)
{
	int error;
	if ((error = check_fmode(cr, mode)))
		return (error);
	return (cred_ability_check(cr, CURTAINABL_FATTR));
}

static int
curtain_posixshm_check_setowner(struct ucred *cr,
    struct shmfd *shmfd, struct label *shmlabel,
    uid_t uid, gid_t gid)
{
	return (cred_ability_check(cr, CURTAINABL_FATTR));
}

static void curtain_posixsem_create(struct ucred *cr,
    struct ksem *sem, struct label *semlabel)
{
	curtain_copy_label_barrier(cr->cr_label, semlabel);
}

static int
curtain_posixsem_check_open_unlink(struct ucred *cr,
    struct ksem *sem, struct label *semlabel)
{
	if (!barrier_visible(CRED_SLOT_BR(cr), SLOT_BR(semlabel), BARRIER_POSIXIPC))
		return (ENOENT);
	return (0);
}

static int
curtain_posixsem_check_setmode(struct ucred *cr,
    struct ksem *ks, struct label *shmlabel,
    mode_t mode)
{
	int error;
	if ((error = check_fmode(cr, mode)))
		return (error);
	return (cred_ability_check(cr, CURTAINABL_FATTR));
}

static int
curtain_posixsem_check_setowner(struct ucred *cr,
    struct ksem *ks, struct label *shmlabel,
    uid_t uid, gid_t gid)
{
	return (cred_ability_check(cr, CURTAINABL_FATTR));
}


static void
curtain_sysvshm_create(struct ucred *cr,
    struct shmid_kernel *shm, struct label *shmlabel)
{
	curtain_copy_label_barrier(cr->cr_label, shmlabel);
}

static int
curtain_sysvshm_check_something(struct ucred *cr,
    struct shmid_kernel *shm, struct label *shmlabel, int something)
{
	if (!barrier_visible(CRED_SLOT_BR(cr), SLOT_BR(shmlabel), BARRIER_SYSVIPC))
		return (ENOENT);
	return (0);
}


static void
curtain_sysvsem_create(struct ucred *cr,
    struct semid_kernel *sem, struct label *semlabel)
{
	curtain_copy_label_barrier(cr->cr_label, semlabel);
}

static int
curtain_sysvsem_check_semctl(struct ucred *cr,
    struct semid_kernel *sem, struct label *semlabel,
    int cmd)
{
	if (!barrier_visible(CRED_SLOT_BR(cr), SLOT_BR(semlabel), BARRIER_SYSVIPC))
		return (ENOENT);
	return (0);
}

static int
curtain_sysvsem_check_semget(struct ucred *cr,
    struct semid_kernel *sem, struct label *semlabel)
{
	if (!barrier_visible(CRED_SLOT_BR(cr), SLOT_BR(semlabel), BARRIER_SYSVIPC))
		return (ENOENT);
	return (0);
}

static int
curtain_sysvsem_check_semop(struct ucred *cr,
    struct semid_kernel *sem, struct label *semlabel,
    size_t accesstype)
{
	if (!barrier_visible(CRED_SLOT_BR(cr), SLOT_BR(semlabel), BARRIER_SYSVIPC))
		return (ENOENT);
	return (0);
}


static void
curtain_sysvmsq_create(struct ucred *cr,
    struct msqid_kernel *msq, struct label *msqlabel)
{
	curtain_copy_label_barrier(cr->cr_label, msqlabel);
}

static int
curtain_sysvmsq_check_1(struct ucred *cr,
    struct msqid_kernel *msq, struct label *msqlabel)
{
	if (!barrier_visible(CRED_SLOT_BR(cr), SLOT_BR(msqlabel), BARRIER_SYSVIPC))
		return (ENOENT);
	return (0);
}

static int
curtain_sysvmsq_check_2(struct ucred *cr,
    struct msqid_kernel *msq, struct label *msqlabel, int something)
{
	if (!barrier_visible(CRED_SLOT_BR(cr), SLOT_BR(msqlabel), BARRIER_SYSVIPC))
		return (ENOENT);
	return (0);
}


static int
curtain_generic_ipc_name_prefix(struct ucred *cr, char **prefix, char *end)
{
	struct barrier *br;
	size_t n, m;
	m = end - *prefix;
	br = barrier_cross(CRED_SLOT_BR(cr), BARRIER_POSIXIPC_RENAME);
	if (br) {
		ssize_t r;
		r = snprintf(*prefix, m,
		    "/curtain/%ju", (uintmax_t)br->br_serial);
		n = r > 0 ? r : 0;
	} else
		n = 0;
	if (n >= m)
		return (ENAMETOOLONG);
	*prefix += n;
	return (0);
}

static bool
dangerous_device_ioctl(struct ucred *cr, struct file *fp, u_long com)
{
	const char *reason;
	if (!(fp->f_vnode && fp->f_vnode->v_type == VCHR))
		reason = "on non-device";
	else if (!fp->f_vnode->v_rdev)
		reason = "on bogus device vnode";
	else if (!fp->f_vnode->v_rdev->si_cred)
		reason = "on device without ucred";
	else if (!curtain_cred_visible(cr, fp->f_vnode->v_rdev->si_cred, BARRIER_DEVICE))
		reason = "across barrier";
	else
		return (false);
	CURTAIN_CRED_LOG(cr, "warning",
	    "dangerous ioctl %#jx attempted %s", (uintmax_t)com, reason);
	return (true);
}

static int
curtain_generic_check_ioctl(struct ucred *cr, struct file *fp, u_long com, void *data)
{
	enum curtain_ability abl;
	int error;
	bool dangerous;
	dangerous = false;
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
		return (0);
	case TIOCGETA:
		/* needed for isatty(3) */
		abl = CURTAINABL_STDIO;
		break;
	case FIOSETOWN:
		/* also checked in setown() */
		abl = CURTAINABL_PROC;
		break;
	case TIOCSTI:
		if (CRED_IN_RESTRICTED_MODE(cr))
			dangerous = dangerous_device_ioctl(cr, fp, com);
		/* FALLTHROUGH */
	default:
		abl = CURTAINABL_ANY_IOCTL;
		break;
	}
	if (abl != CURTAINABL_ANY_IOCTL &&
	    cred_ability_action(cr, abl) == CURTAIN_ALLOW)
		return (0);
	error = cred_key_check(cr, CURTAIN_IOCTL, (ctkey){ .ioctl = com });
	return (error ? error : dangerous ? EPERM : 0);
}

static int
curtain_generic_check_vm_prot(struct ucred *cr, struct file *fp, vm_prot_t prot)
{
	if (prot & VM_PROT_EXECUTE) {
		enum curtain_ability abl;
		if (!(prot & VM_PROT_WRITE) && fp && fp->f_vnode) {
			if (check_uperms(get_vp_uperms(cr, fp->f_vnode), UPERM_EXECUTE) == 0)
				abl = CURTAINABL_PROT_EXEC_LOOSE;
			else
				abl = CURTAINABL_PROT_EXEC_LOOSER;
		} else
			abl = CURTAINABL_PROT_EXEC;
		return (cred_ability_check(cr, abl));
	}
	return (0);
}


static char *
sysctl_name_str(const struct sysctl_oid *oidp, char *p, size_t n)
{
	char *q = &p[n];
	if (!(q > p))
		return (NULL);
	*--q = '\0';
	while (oidp) {
		size_t l = strlen(oidp->oid_name);
		if (l > q - p)
			break;
		memcpy((q -= l), oidp->oid_name, l);
		if ((oidp = SYSCTL_PARENT(oidp))) {
			if (!(q > p))
				break;
			*--q = '.';
		}
	}
	return (q);
}

static int
curtain_system_check_sysctl(struct ucred *cr,
    struct sysctl_oid *oidp, void *arg1, int arg2,
    struct sysctl_req *req)
{
	enum curtain_action act;
	struct sysctl_oid *p;
	if (oidp->oid_kind & (CTLFLAG_RESTRICT|CTLFLAG_CAPRW))
		return (0);
	if (!CRED_SLOT(cr))
		return (0);
	for (p = oidp; p && !p->oid_shadow; p = SYSCTL_PARENT(p));
	if (p)
		act = cred_key_action(cr, CURTAIN_SYSCTL,
		    (ctkey){ .sysctl = p->oid_shadow });
	else
		act = cred_ability_action(cr, curtain_type_fallback(CURTAIN_SYSCTL));
	if (__predict_true(act == CURTAIN_ALLOW))
		return (0);
	if (act >= curtain_sysctls_log_level) {
		char buf[256], *name;
		if ((name = sysctl_name_str(oidp, buf, sizeof buf)))
			CURTAIN_CRED_LOG_ACTION(cr, act, "sysctl %s", name);
	}
	return (act2err[act]);
}


static int
curtain_priv_check(struct ucred *cr, int priv)
{
	enum curtain_ability abl;
	switch (priv) {
	case PRIV_AUDIT_CONTROL:
	case PRIV_AUDIT_FAILSTOP:
	case PRIV_AUDIT_GETAUDIT:
	case PRIV_AUDIT_SETAUDIT:
	case PRIV_AUDIT_SUBMIT:
		abl = CURTAINABL_AUDIT;
		break;
	case PRIV_SCHED_SETPRIORITY:
		abl = CURTAINABL_SCHED;
		break;
	default:
		abl = CURTAINABL_ANY_PRIV;
		break;
	/*
	 * Mostly a subset of what's being allowed for jails (see
	 * prison_priv_check()) with some extra conditions based on sysfils.
	 */
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
		abl = CURTAINABL_ANY_CRED;
		break;
	case PRIV_SEEOTHERGIDS:
	case PRIV_SEEOTHERUIDS:
		abl = CURTAINABL_PS;
		break;
	case PRIV_DEBUG_DIFFCRED:
	case PRIV_DEBUG_SUGID:
	case PRIV_DEBUG_UNPRIV:
		abl = CURTAINABL_DEBUG;
		break;
	case PRIV_PROC_LIMIT:
	case PRIV_PROC_SETRLIMIT:
		abl = CURTAINABL_RLIMIT;
		break;
	case PRIV_JAIL_ATTACH:
	case PRIV_JAIL_SET:
	case PRIV_JAIL_REMOVE:
		abl = CURTAINABL_JAIL;
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
		abl = CURTAINABL_VFS_MISC;
		break;
	case PRIV_VFS_SYSFLAGS:
#if 0
	case PRIV_VFS_EXTATTR_SYSTEM:
#endif
		abl = CURTAINABL_SYSFLAGS;
		break;
	case PRIV_VFS_MOUNT:
	case PRIV_VFS_UNMOUNT:
	case PRIV_VFS_MOUNT_OWNER:
		abl = CURTAINABL_MOUNT;
		break;
	case PRIV_VFS_MOUNT_NONUSER:
		abl = CURTAINABL_MOUNT_NONUSER;
		break;

	case PRIV_VFS_READ_DIR:
		/* Let other policies handle this (like is done for jails). */
		abl = CURTAINABL_VFS_MISC;
		break;
	case PRIV_VFS_CHOWN:
	case PRIV_VFS_SETGID:
	case PRIV_VFS_RETAINSUGID:
		abl = CURTAINABL_CHOWN;
		break;
	case PRIV_VFS_CHROOT:
	case PRIV_VFS_FCHROOT:
		abl = CURTAINABL_CHROOT;
		break;
	case PRIV_VFS_MKNOD_DEV:
		abl = CURTAINABL_MAKEDEV;
		break;
	case PRIV_VM_MLOCK:
	case PRIV_VM_MUNLOCK:
		abl = CURTAINABL_MLOCK;
		break;
	case PRIV_NETINET_RESERVEDPORT:
	case PRIV_NETINET_REUSEPORT:
#if 0
	case PRIV_NETINET_SETHDROPTS:
	case PRIV_NETINET_RAW:
	case PRIV_NETINET_GETCRED:
#endif
		abl = CURTAINABL_SOCK;
		break;
	case PRIV_ADJTIME:
	case PRIV_NTP_ADJTIME:
	case PRIV_CLOCK_SETTIME:
		abl = CURTAINABL_SETTIME;
		break;
	case PRIV_VFS_GETFH:
	case PRIV_VFS_FHOPEN:
	case PRIV_VFS_FHSTAT:
	case PRIV_VFS_FHSTATFS:
	case PRIV_VFS_GENERATION:
		abl = CURTAINABL_FH;
		break;
	}
	if (abl != CURTAINABL_ANY_PRIV &&
	    cred_ability_action(cr, abl) == CURTAIN_ALLOW)
		return (0);
	return (cred_key_check(cr, CURTAIN_PRIV, (ctkey){ .priv = priv }));
}


static int
curtain_sysfil_check(struct ucred *cr, sysfilset_t sfs)
{
	sysfilset_t orig_sfs = sfs;
	struct curtain *ct;
	enum curtain_action act;
	if (!(ct = CRED_SLOT(cr)))
		return (sysfil_probe_cred(cr, sfs));
	act = CURTAIN_ALLOW;
	sfs &= ~curtain_preserve_sysfils;
	while (sfs) {
		unsigned i = ffsll(sfs) - 1;
		act = MAX(act, ct->ct_cached.sysfilacts[i]);
		sfs ^= SYSFIL_INDEX(i);
	}
	sfs = orig_sfs;
	if (act == CURTAIN_ALLOW)
		return (0);
	CURTAIN_CRED_LOG_ACTION(cr, act, "sysfil %#jx", (uintmax_t)sfs);
	SDT_PROBE3(curtain,, cred_sysfil_check, failed, cr, sfs, act);
	cred_action_failed(cr, act, false);
	return (act2err[act]);
}


static int
curtain_proc_check_exec_sugid(struct ucred *cr, struct proc *p)
{
	const struct curtain *ct, *ct1;
	enum curtain_action act;
	if ((ct = CRED_SLOT(cr))) {
		MPASS(ct->ct_cached.valid);
		ct1 = ct->ct_on_exec ? ct->ct_on_exec : ct;
		if (curtain_cred_restricted(ct1, cr))
			act = ct1->ct_abilities[CURTAINABL_EXEC_RSUGID].soft;
		else
			act = CURTAIN_ALLOW;
	} else if (CRED_IN_RESTRICTED_MODE(cr))
		act = CURTAIN_DENY;
	else
		act = CURTAIN_ALLOW;
	return (act2err[act]);
}

static int
curtain_proc_exec_check(struct image_params *imgp)
{
	struct ucred *cr = imgp->proc->p_ucred;
	struct vnode *vp = imgp->vp;
	int error;
	if ((error = check_uperms(get_vp_uperms(cr, vp),
	    imgp->interpreted == IMGACT_SHELL ? UPERM_SHELL : UPERM_EXECUTE)))
		return (error);
	if ((error = cred_ability_check(cr, CURTAINABL_EXEC)))
		return (error);
	return (0);
}

static bool
curtain_proc_exec_will_alter(struct proc *p, struct ucred *cr)
{
	struct curtain *ct;
	if (!(ct = CRED_SLOT(cr)))
		return (false); /* NOTE: the ucred's sysfilset will be kept as-is */
	return (ct->ct_on_exec);
}

static void
curtain_proc_exec_alter(struct proc *p, struct ucred *cr)
{
	struct curtain *ct;
	if (!(ct = CRED_SLOT(cr)) || !ct->ct_on_exec)
		return;

	if (!curtain_cred_restricted(ct->ct_on_exec, cr)) {
		/* Can drop the curtain and unveils altogether. */
		curtain_free(ct);
		SLOT_SET(cr->cr_label, NULL);
		sysfil_cred_init(cr);
		MPASS(!CRED_IN_RESTRICTED_MODE(cr));
		unveil_proc_drop_cache(p);
		return;
	}

	ct = curtain_hold(ct->ct_on_exec);
	curtain_free(CRED_SLOT(cr));
	curtain_cred_update(ct, cr);
	SLOT_SET(cr->cr_label, ct);
	MPASS(CRED_IN_RESTRICTED_MODE(cr));
}


static struct mac_policy_ops curtain_policy_ops = {
	.mpo_cred_init_label = curtain_cred_init_label,
	.mpo_cred_copy_label = curtain_cred_copy_label,
	.mpo_cred_destroy_label = curtain_cred_destroy_label,
	.mpo_cred_externalize_label = curtain_cred_externalize_label,
	.mpo_cred_check_visible = curtain_cred_check_visible,
	.mpo_cred_trim = curtain_cred_trim,

	.mpo_proc_check_signal = curtain_proc_check_signal,
	.mpo_proc_check_sched = curtain_proc_check_sched,
	.mpo_proc_check_debug = curtain_proc_check_debug,

	.mpo_socket_check_create = curtain_socket_check_create,
	.mpo_socket_check_bind = curtain_socket_check_bind,
	.mpo_socket_check_connect = curtain_socket_check_connect,
	.mpo_socket_check_setsockopt = curtain_socket_check_sockopt,
	.mpo_socket_check_getsockopt = curtain_socket_check_sockopt,
	.mpo_socket_check_visible = curtain_socket_check_visible,
	.mpo_inpcb_check_visible = curtain_inpcb_check_visible,

	.mpo_net_check_fibnum = curtain_net_check_fibnum,

	.mpo_vnode_check_access = curtain_vnode_check_access,
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

	.mpo_mount_check_stat = curtain_mount_check_stat,

	.mpo_vnode_walk_roll = unveil_vnode_walk_roll,
	.mpo_vnode_walk_annotate_file = unveil_vnode_walk_annotate_file,
	.mpo_vnode_walk_start_file = unveil_vnode_walk_start_file,
	.mpo_vnode_walk_start = unveil_vnode_walk_start,
	.mpo_vnode_walk_component = unveil_vnode_walk_component,
	.mpo_vnode_walk_backtrack = unveil_vnode_walk_backtrack,
	.mpo_vnode_walk_replace = unveil_vnode_walk_replace,
	.mpo_vnode_walk_created = unveil_vnode_walk_created,
	.mpo_vnode_walk_fixup_errno = unveil_vnode_walk_fixup_errno,
	.mpo_vnode_walk_dirent_visible = unveil_vnode_walk_dirent_visible,

	.mpo_posixshm_init_label = curtain_init_label_barrier,
	.mpo_posixshm_destroy_label = curtain_destroy_label_barrier,
	.mpo_posixshm_create = curtain_posixshm_create,
	.mpo_posixshm_check_open = curtain_posixshm_check_open,
	.mpo_posixshm_check_unlink = curtain_posixshm_check_unlink,
	.mpo_posixshm_check_setmode = curtain_posixshm_check_setmode,
	.mpo_posixshm_check_setowner = curtain_posixshm_check_setowner,

	.mpo_posixsem_init_label = curtain_init_label_barrier,
	.mpo_posixsem_destroy_label = curtain_destroy_label_barrier,
	.mpo_posixsem_create = curtain_posixsem_create,
	.mpo_posixsem_check_open = curtain_posixsem_check_open_unlink,
	.mpo_posixsem_check_unlink = curtain_posixsem_check_open_unlink,
	.mpo_posixsem_check_setmode = curtain_posixsem_check_setmode,
	.mpo_posixsem_check_setowner = curtain_posixsem_check_setowner,

	.mpo_sysvshm_init_label = curtain_init_label_barrier,
	.mpo_sysvshm_cleanup = curtain_destroy_label_barrier,
	.mpo_sysvshm_destroy_label = curtain_destroy_label_barrier,
	.mpo_sysvshm_create = curtain_sysvshm_create,
	.mpo_sysvshm_check_shmat = curtain_sysvshm_check_something,
	.mpo_sysvshm_check_shmctl = curtain_sysvshm_check_something,
	.mpo_sysvshm_check_shmget = curtain_sysvshm_check_something,

	.mpo_sysvsem_init_label = curtain_init_label_barrier,
	.mpo_sysvsem_cleanup = curtain_destroy_label_barrier,
	.mpo_sysvsem_destroy_label = curtain_destroy_label_barrier,
	.mpo_sysvsem_create = curtain_sysvsem_create,
	.mpo_sysvsem_check_semctl = curtain_sysvsem_check_semctl,
	.mpo_sysvsem_check_semget = curtain_sysvsem_check_semget,
	.mpo_sysvsem_check_semop = curtain_sysvsem_check_semop,

	.mpo_sysvmsq_init_label = curtain_init_label_barrier,
	.mpo_sysvmsq_cleanup = curtain_destroy_label_barrier,
	.mpo_sysvmsq_destroy_label = curtain_destroy_label_barrier,
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

	.mpo_proc_check_exec_sugid = curtain_proc_check_exec_sugid,
	.mpo_proc_exec_check = curtain_proc_exec_check,
	.mpo_proc_exec_will_alter = curtain_proc_exec_will_alter,
	.mpo_proc_exec_alter = curtain_proc_exec_alter,
};

MAC_POLICY_SET(&curtain_policy_ops, mac_curtain, "MAC/curtain", 0, &curtain_slot);
