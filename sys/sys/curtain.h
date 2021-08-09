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
#define	CURTAINCTL_VERSION	(5 << 24)

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
	struct curtain *ct_parent;
	LIST_HEAD(, curtain) ct_children;
	LIST_ENTRY(curtain) ct_sibling;
	size_t ct_nchildren;
	volatile int ct_ref;
	curtain_index ct_nslots;
	curtain_index ct_nitems;
	curtain_index ct_modulo;
	curtain_index ct_cellar;
	bool ct_overflowed;
	bool ct_cache_valid;
	struct {
		bool need_exec_switch;
		bool is_restricted_on_self;
		bool is_restricted_on_exec;
	} ct_cached;
	bool ct_barrier, ct_barrier_on_exec;
	struct curtain_mode ct_sysfils[SYSFIL_COUNT];
	struct curtain_item ct_slots[];
};

bool	curtain_cred_visible(const struct ucred *subject, const struct ucred *target,
	    bool strict);

#endif

#endif

