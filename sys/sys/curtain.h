#ifndef _SYS_CURTAIN_H_
#define	_SYS_CURTAIN_H_

#include <sys/curtain_ability.h>

enum curtain_type {
	CURTAINTYP_DEFAULT = 1,
	CURTAINTYP_UNVEIL = 3,
	CURTAINTYP_IOCTL = 4,
	CURTAINTYP_SOCKAF = 5,
	CURTAINTYP_SOCKLVL = 6,
	CURTAINTYP_SOCKOPT = 7,
	CURTAINTYP_PRIV = 8,
	CURTAINTYP_SYSCTL = 9,
	CURTAINTYP_ABILITY = 10,
};

enum curtain_level {
	CURTAINLVL_PASS = 0,
	CURTAINLVL_GATE = 1,
	CURTAINLVL_WALL = 2,
	CURTAINLVL_DENY = 3,
	CURTAINLVL_TRAP = 4,
	CURTAINLVL_KILL = 5,
#define	CURTAINLVL_COUNT 6
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
#define	CURTAINCTL_VERSION	(6 << 24)

#define	CURTAINCTL_ENGAGE	(1 <<  0 | CURTAINCTL_VERSION)
#define	CURTAINCTL_REQUIRE	(1 <<  1 | CURTAINCTL_VERSION)
#define	CURTAINCTL_ENFORCE	(1 <<  2 | CURTAINCTL_VERSION)

#define	CURTAINREQ_ON_SELF	(1 << 16)
#define	CURTAINREQ_ON_EXEC	(1 << 17)
#define	CURTAINREQ_ON_BOTH	(CURTAINREQ_ON_SELF | CURTAINREQ_ON_EXEC)

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
	} key;
};

CTASSERT(sizeof(struct curtain_item) <= 12);

enum barrier_stop {
	BARRIER_PASS = 0,
	BARRIER_GATE = 1,
	BARRIER_WALL = 2,
};

enum barrier_type {
	BARRIER_PROC_STATUS,
	BARRIER_PROC_SIGNAL,
	BARRIER_PROC_SCHED,
	BARRIER_PROC_DEBUG,
	BARRIER_SOCKET,
	BARRIER_POSIXIPC,
	BARRIER_SYSVIPC,
	BARRIER_DEVICE,
#define	BARRIER_COUNT 8 /* UPDATE ME!!! */
};

struct barrier_mode {
	/* enum barrier_stop */
	uint8_t on_self : 2, on_exec : 2;
};

struct curtain_head {
	struct barrier *cth_barrier;
};

struct barrier {
	struct curtain_head br_head;
	struct barrier *br_parent;
	LIST_HEAD(, barrier) br_children;
	LIST_ENTRY(barrier) br_sibling;
	unsigned br_nchildren;
	volatile int br_ref;
	uint64_t br_serial;
	struct barrier_mode br_barriers[BARRIER_COUNT];
};

struct curtain {
	struct curtain_head ct_head;
#ifdef INVARIANTS
	unsigned ct_magic;
#endif
	volatile int ct_ref;
	curtain_index ct_nslots;
	curtain_index ct_nitems;
	curtain_index ct_modulo;
	curtain_index ct_cellar;
	bool ct_overflowed;
	bool ct_finalized;
	struct {
		bool need_exec_switch;
		bool is_restricted_on_self;
		bool is_restricted_on_exec;
	} ct_cached;
#ifdef UNVEIL_SUPPORT
	struct unveil_stash ct_ustash;
#endif
	struct curtain_mode ct_abilities[CURTAINABL_COUNT];
	struct curtain_item ct_slots[];
};

bool	curtain_cred_visible(const struct ucred *subject, const struct ucred *target,
	    enum barrier_type);
struct curtain *curtain_from_cred(struct ucred *);

#endif

#endif

