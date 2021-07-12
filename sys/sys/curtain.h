#ifndef _SYS_CURTAIN_H_
#define	_SYS_CURTAIN_H_

enum curtain_type {
	CURTAINTYP_DEFAULT = 1,
	CURTAINTYP_SYSFIL = 2,
	CURTAINTYP_UNVEIL = 3,
	CURTAINTYP_IOCTL = 4,
	CURTAINTYP_SOCKAF = 5,
	CURTAINTYP_SOCKLVL = 6,
	CURTAINTYP_SOCKOPT = 7,
	CURTAINTYP_PRIV = 8,
	CURTAINTYP_SYSCTL = 9,
};

enum curtain_level {
	CURTAINLVL_PASS = 0,
	CURTAINLVL_DENY = 1,
	CURTAINLVL_TRAP = 2,
	CURTAINLVL_KILL = 3,
};

struct curtainreq {
	enum curtain_type type : 8;
	enum curtain_level level : 8;
	int flags;
	size_t size;
	void *data;
};

#define	CURTAINCTL_MAX_REQS	1024
#define	CURTAINCTL_MAX_SIZE	(16 << 10)
#define	CURTAINCTL_MAX_ITEMS	1024

int curtainctl(int flags, size_t reqc, struct curtainreq *reqv);

#define	CURTAINCTL_VERSION_MASK	(0xff << 24)
#define	CURTAINCTL_VERSION	(4 << 24)

#define	CURTAINCTL_ENGAGE	(1 <<  0 | CURTAINCTL_VERSION)
#define	CURTAINCTL_REQUIRE	(1 <<  1 | CURTAINCTL_VERSION)
#define	CURTAINCTL_ENFORCE	(1 <<  2 | CURTAINCTL_VERSION)

#define	CURTAINREQ_ON_SELF	(1 << 16)
#define	CURTAINREQ_ON_EXEC	(1 << 17)

#ifdef _KERNEL

#include <sys/types.h>
#include <sys/sysfil.h>
#include <sys/ucred.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/mman.h>

struct curtain_mode {
	uint8_t on_self     : 2;
	uint8_t on_self_max : 2;
	uint8_t on_exec     : 2;
	uint8_t on_exec_max : 2;
};

typedef uint16_t curtain_index;

struct curtain_item {
	uint8_t type;
	struct curtain_mode mode;
	curtain_index chain;
	union curtain_key {
		/*
		 * Using __packed to reduce the alignment requirements on
		 * specific members to save 4 bytes per item on 64-bits archs.
		 */
		unsigned long __packed ioctl;
		int sockaf;
		int socklvl;
		struct {
			int level, optname;
		} sockopt;
		int priv;
		struct {
			uint64_t serial;
		} __packed sysctl;
	} key;
};

CTASSERT(sizeof(struct curtain_item) <= 12);

struct curtain {
	volatile int ct_ref;
	curtain_index ct_nslots;
	curtain_index ct_nitems;
	curtain_index ct_modulo;
	curtain_index ct_cellar;
	bool ct_overflowed;
	struct curtain_mode ct_sysfils[SYSFIL_COUNT];
	struct curtain_item ct_slots[];
};

void	curtain_hold(struct curtain *);
void	curtain_free(struct curtain *);

bool	curtain_cred_need_exec_switch(const struct ucred *);
bool	curtain_cred_exec_restricted(const struct ucred *);
void	curtain_cred_exec_switch(struct ucred *);
void	curtain_cap_enter(struct thread *);

bool	curtain_device_unveil_bypass(struct thread *, struct cdev *);
void	curtain_sysctl_req_amend(struct sysctl_req *, const struct sysctl_oid *);


#define	SYSFIL_FAILED_ERRNO	EPERM

static inline int
sysfil_match_cred(const struct ucred *cr, int sf) {
#ifdef SYSFIL
	return (BIT_ISSET(SYSFILSET_BITS, sf, &cr->cr_sysfilset));
#else
	return (1);
#endif
}

static inline int
sysfil_check_cred(const struct ucred *cr, int sf)
{
	if (__predict_false(!SYSFIL_VALID(sf)))
		return (EINVAL);
	if (__predict_false(!sysfil_match_cred(cr, sf)))
		return (SYSFIL_FAILED_ERRNO);
	return (0);
}

static inline int
sysfil_check(const struct thread *td, int sf)
{
	return (sysfil_check_cred(td->td_ucred, sf));
}

void sysfil_violation(struct thread *, int sf, int error);

/*
 * Note: sysfil_require() may acquire the PROC_LOCK to send a violation signal.
 * Thus it must not be called with the PROC_LOCK (or any other incompatible
 * lock) currently being held.
 */
static inline int
sysfil_require(struct thread *td, int sf)
{
	int error;
	PROC_LOCK_ASSERT(td->td_proc, MA_NOTOWNED);
	error = sysfil_check(td, sf);
	if (__predict_false(error))
		sysfil_violation(td, sf, error);
	return (error);
}

static inline int
sysfil_failed(struct thread *td, int sf)
{
	sysfil_violation(td, sf, SYSFIL_FAILED_ERRNO);
	return (SYSFIL_FAILED_ERRNO);
}

static inline void
sysfil_cred_init(struct ucred *cr)
{
#ifdef SYSFIL
	BIT_FILL(SYSFILSET_BITS, &cr->cr_sysfilset);
	cr->cr_curtain = NULL;
#endif
}

void sysfil_cred_rights(struct ucred *, cap_rights_t *);

int sysfil_require_vm_prot(struct thread *, vm_prot_t prot, bool loose);
int sysfil_require_ioctl(struct thread *, u_long com);
int sysfil_require_sockaf(struct thread *, int af);
int sysfil_require_sockopt(struct thread *, int level, int name);
int sysfil_require_sysctl_req(struct sysctl_req *);

int sysfil_priv_check(struct ucred *, int priv);

#endif

#endif

