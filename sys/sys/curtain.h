#ifndef _SYS_CURTAIN_H_
#define	_SYS_CURTAIN_H_

#include <sys/curtain_ability.h>
#include <sys/_unveil.h>

enum curtainreq_type {
	CURTAINTYP_DEFAULT = 1,
	CURTAINTYP_ABILITY = 2,
	CURTAINTYP_OLD_UNVEIL = 3,
	CURTAINTYP_IOCTL = 4,
	CURTAINTYP_SOCKAF = 5,
	CURTAINTYP_SOCKLVL = 6,
	CURTAINTYP_SOCKOPT = 7,
	CURTAINTYP_PRIV = 8,
	CURTAINTYP_SYSCTL = 9,
	CURTAINTYP_FIBNUM = 10,
	CURTAINTYP_UNVEIL = 11,
#define	CURTAINTYP_LAST 11 /* UPDATE ME!!! */
};

enum curtainreq_level {
	CURTAINLVL_PASS = 0,
	CURTAINLVL_GATE = 1,
	CURTAINLVL_WALL = 2,
	CURTAINLVL_DENY = 3,
	CURTAINLVL_TRAP = 4,
	CURTAINLVL_KILL = 5,
#define	CURTAINLVL_COUNT 6
#define	CURTAINLVL_LEAST CURTAINLVL_KILL
};

struct curtainreq {
	enum curtainreq_type type : 8;
	enum curtainreq_level level : 8;
	int flags;
	size_t size;
	void *data;
};

#define	CURTAINCTL_MAX_REQS	1024
#define	CURTAINCTL_MAX_SIZE	(16 << 10)
#define	CURTAINCTL_MAX_ITEMS	1024

int curtainctl(int flags, size_t reqc, struct curtainreq *reqv);

#define	CURTAINCTL_VER_SHIFT	(24)
#define	CURTAINCTL_VER_MASK	(0xff << CURTAINCTL_VER_SHIFT)
#define	CURTAINCTL_VERSION(v)	(((v) << CURTAINCTL_VER_SHIFT) & CURTAINCTL_VER_MASK)
#define	CURTAINCTL_THIS_VERSION	CURTAINCTL_VERSION(7)

#define	CURTAINCTL_ENGAGE	(1 <<  0)
#define	CURTAINCTL_ENFORCE	(1 <<  1)

#define	CURTAINREQ_ON_SELF	(1 << 16)
#define	CURTAINREQ_ON_EXEC	(1 << 17)
#define	CURTAINREQ_ON_BOTH	(CURTAINREQ_ON_SELF | CURTAINREQ_ON_EXEC)

static const enum curtain_ability curtain_type_fallback[CURTAINTYP_LAST + 1] = {
	[CURTAINTYP_IOCTL] = CURTAINABL_ANY_IOCTL,
	[CURTAINTYP_SOCKAF] = CURTAINABL_ANY_SOCKAF,
	[CURTAINTYP_SOCKLVL] = CURTAINABL_ANY_SOCKOPT,
	[CURTAINTYP_SOCKOPT] = CURTAINABL_ANY_SOCKOPT,
	[CURTAINTYP_PRIV] = CURTAINABL_ANY_PRIV,
	[CURTAINTYP_SYSCTL] = CURTAINABL_ANY_SYSCTL,
	[CURTAINTYP_FIBNUM] = CURTAINABL_ANY_FIBNUM,
};
#ifdef _KERNEL
CTASSERT(CURTAINABL_DEFAULT == 0);
#endif

struct curtainent_unveil {
	int dir_fd;
	unveil_perms uperms;
	char name[];
};

#ifdef _KERNEL

#include <sys/types.h>
#include <sys/sysfil.h>
#include <sys/ucred.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/unveil.h>

enum curtain_action {
	CURTAINACT_ALLOW = 0,
	CURTAINACT_DENY = 1,
	CURTAINACT_TRAP = 2,
	CURTAINACT_KILL = 3,
#define	CURTAINACT_COUNT 4
};

struct curtain_mode {
	/* enum curtain_action */
	uint8_t soft : 2;
	uint8_t hard : 2;
};

typedef uint16_t curtain_index;

CTASSERT(CURTAINCTL_MAX_ITEMS <= (curtain_index)-1);

struct curtain_unveil {
	struct curtain_unveil *parent;
	struct vnode *vp;
	uint32_t hash;
	unveil_perms soft_uperms, hard_uperms;
	uint8_t name_len;
	uint8_t depth;
	bool hidden_children : 1;
	bool name_ext : 1;
	char name[];
};

CTASSERT(NAME_MAX <= UINT8_MAX);
CTASSERT(sizeof(struct curtain_unveil) <= 32);

struct curtain_item {
	uint8_t type;
	struct curtain_mode mode;
	curtain_index chain;
	union curtain_key {
		/*
		 * Using __packed to reduce the alignment requirements on
		 * specific members to save 4 bytes per item on 64-bits archs.
		 */
		enum curtain_ability ability;
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
		int fibnum;
		struct curtain_unveil __packed *unveil;
	} key;
};

CTASSERT(sizeof(struct curtain_item) <= 12);

struct curtain_head {
	struct barrier *cth_barrier;
};

enum barrier_type {
	BARRIER_PROC_STATUS,
	BARRIER_PROC_SIGNAL,
	BARRIER_PROC_SCHED,
	BARRIER_PROC_DEBUG,
	BARRIER_SOCK,
	BARRIER_POSIXIPC,
	BARRIER_SYSVIPC,
	BARRIER_DEVICE,
#define	BARRIER_COUNT 8 /* UPDATE ME!!! */
};

typedef uint8_t barrier_bits;
#define	BARRIERS_ALL	((1 << BARRIER_COUNT) - 1)

struct barrier_mode {
	barrier_bits isolate : BARRIER_COUNT;
	barrier_bits protect : BARRIER_COUNT;
};

#define	CURTAIN_BARRIER(ct) ((ct)->ct_head.cth_barrier)

struct barrier {
	struct curtain_head br_head; /* cth_barrier will point to itself */
	struct barrier *br_parent;
	LIST_HEAD(, barrier) br_children;
	LIST_ENTRY(barrier) br_sibling;
	unsigned br_nchildren;
	volatile int br_ref;
	uint64_t br_serial;
	struct barrier_mode br_mode;
};

struct curtain {
	struct curtain_head ct_head;
#ifdef INVARIANTS
#define	CURTAIN_MAGIC 0x4355525441494e00ULL
	unsigned long long ct_magic;
#endif
	struct curtain *ct_on_exec;
	volatile int ct_ref;
	curtain_index ct_nslots;
	curtain_index ct_nitems;
	curtain_index ct_modulo;
	curtain_index ct_cellar;
	bool ct_overflowed;
	bool ct_finalized;
	struct {
		bool is_restricted;
		uint8_t sysfilacts[SYSFILSET_BITS];
	} ct_cached;
	struct curtain_mode ct_abilities[CURTAINABL_COUNT];
	struct curtain_item ct_slots[];
};

#define CURTAIN_STATS
#define CURTAIN_STATS_LOOKUP

SDT_PROVIDER_DECLARE(curtain);

SYSCTL_DECL(_security_curtain);
SYSCTL_DECL(_security_curtain_unveil);
#ifdef CURTAIN_STATS
SYSCTL_DECL(_security_curtain_stats);
#endif

extern unsigned __read_mostly curtain_log_level;

extern const sysfilset_t curtain_abilities_sysfils[CURTAINABL_COUNT];
extern const barrier_bits curtain_abilities_barriers[CURTAINABL_COUNT];

extern int __read_mostly curtain_slot;
#define	CURTAIN_CTH_IS_CT(cth) ((cth) != &(cth)->cth_barrier->br_head)
#define	CURTAIN_SLOT_CTH(l) ((l) ? (struct curtain_head *)mac_label_get((l), curtain_slot) : NULL)
#define	CURTAIN_SLOT_CT_UNCHECKED(l) ((struct curtain *)CURTAIN_SLOT_CTH(l))
#define	CURTAIN_SLOT_CT(l) ({ \
	struct curtain_head *__cth; \
	struct curtain *__ct; \
	__cth = CURTAIN_SLOT_CTH(l); \
	__ct = __cth && CURTAIN_CTH_IS_CT(__cth) ? (struct curtain *)__cth : NULL; \
	MPASS(!__ct || __ct->ct_magic == CURTAIN_MAGIC); \
	__ct; \
})
#define	CURTAIN_SLOT_BR(l) ({ \
	struct curtain_head *__cth = CURTAIN_SLOT_CTH(l); \
	__cth ? __cth->cth_barrier : NULL; \
})

struct barrier *barrier_hold(struct barrier *);
struct barrier *barrier_dup(const struct barrier *);
void	barrier_bump(struct barrier *);
void	barrier_link(struct barrier *child, struct barrier *parent);
void	barrier_free(struct barrier *);
struct barrier *barrier_cross(struct barrier *, struct barrier_mode);
bool	barrier_visible(struct barrier *subject, const struct barrier *target,
	    enum barrier_type);

void	curtain_invariants(const struct curtain *);
void	curtain_invariants_sync(const struct curtain *);
struct curtain *curtain_make(size_t nitems);
struct curtain *curtain_hold(struct curtain *);
void	curtain_free(struct curtain *);
struct curtain *curtain_dup(const struct curtain *);
struct curtain *curtain_dup_compact(const struct curtain *);
uint64_t curtain_serial(const struct curtain *);
struct curtain_item *curtain_lookup(const struct curtain *, enum curtainreq_type, union curtain_key);
struct curtain_item *curtain_search(struct curtain *, enum curtainreq_type, union curtain_key,
	    bool *inserted);
struct curtain_mode curtain_resolve(const struct curtain *,
	    enum curtainreq_type, union curtain_key );
bool	curtain_need_exec_switch(const struct curtain *);
bool	curtain_restricted(const struct curtain *);
bool	curtain_equivalent(const struct curtain *, const struct curtain *);
void	curtain_cache_update(struct curtain *);
void	curtain_cred_sysfil_update(struct ucred *, const struct curtain *);
void	curtain_exec_switch(struct curtain *);
void	curtain_harden(struct curtain *);
void	curtain_mask_sysfils(struct curtain *, sysfilset_t);
struct curtain_item *curtain_extend(struct curtain *, enum curtainreq_type, union curtain_key);
void	curtain_mask(struct curtain *dst, const struct curtain *src);

bool	curtain_cred_visible(const struct ucred *subject, const struct ucred *target,
	    enum barrier_type);
struct curtain *curtain_from_cred(struct ucred *);

#endif

#endif

