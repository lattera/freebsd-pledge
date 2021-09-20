#ifndef _SYS_CURTAIN_H_
#define	_SYS_CURTAIN_H_

enum curtain_ability {
#ifdef _KERNEL
	CURTAINABL_UNCAPSICUM = 0, /* XXX */
	CURTAINABL_DEFAULT = 1, /* XXX */
	CURTAINABL_ALWAYS = 2, /* XXX */
#endif
	CURTAINABL_STDIO = 3,
	CURTAINABL_VFS_MISC = 4,
	CURTAINABL_VFS_READ = 5,
	CURTAINABL_VFS_WRITE = 6,
	CURTAINABL_VFS_CREATE = 7,
	CURTAINABL_VFS_DELETE = 8,
	CURTAINABL_FATTR = 9,
	CURTAINABL_FLOCK = 10,
	CURTAINABL_TTY = 11,
	CURTAINABL_NET = 12,
	CURTAINABL_PROC = 13,
	CURTAINABL_THREAD = 14,
	CURTAINABL_EXEC = 15,
	CURTAINABL_CURTAIN = 16,
	CURTAINABL_RLIMIT = 17,
	CURTAINABL_SETTIME = 18,
	CURTAINABL_ID = 19,
	CURTAINABL_CHOWN = 20,
	CURTAINABL_MLOCK = 21,
	CURTAINABL_AIO = 22,
	CURTAINABL_EXTATTR = 23,
	CURTAINABL_ACL = 24,
	CURTAINABL_CPUSET = 25,
	CURTAINABL_SYSVIPC = 26,
	CURTAINABL_POSIXIPC = 27,
	CURTAINABL_POSIXRT = 28,
	CURTAINABL_MAC = 29,
	CURTAINABL_CHROOT = 30,
	CURTAINABL_JAIL = 31,
	CURTAINABL_SCHED = 32,
	CURTAINABL_MKFIFO = 33,
	CURTAINABL_PS = 34,
	CURTAINABL__UNUSED1 = 35,
	CURTAINABL_DEBUG = 36,
	CURTAINABL_UNIX = 37,
	CURTAINABL_MAKEDEV = 38,
	CURTAINABL_ANY_SYSCTL = 39,
	CURTAINABL_CHMOD_SPECIAL = 40,
	CURTAINABL_SYSFLAGS = 41,
	CURTAINABL_ANY_SOCKAF = 42,
	CURTAINABL_ANY_PRIV = 43,
	CURTAINABL_SENDFILE = 44,
	CURTAINABL_MOUNT = 45,
	CURTAINABL_QUOTA = 46,
	CURTAINABL_FH = 47,
	CURTAINABL_RECVFD = 48,
	CURTAINABL_SENDFD = 49,
	CURTAINABL_PROT_EXEC = 50,
	CURTAINABL_RSUGID_EXEC = 51,
	CURTAINABL_ANY_IOCTL = 52,
	CURTAINABL_ANY_SOCKOPT = 53,
	CURTAINABL__UNUSED2 = 54,
	CURTAINABL__UNUSED3 = 55,
	CURTAINABL_REAP = 56,
	CURTAINABL_FFCLOCK = 57,
	CURTAINABL_AUDIT = 58,
	CURTAINABL_RFORK = 59,
	CURTAINABL__UNUSED6 = 60,
	CURTAINABL__UNUSED7 = 61,
	CURTAINABL_PROT_EXEC_LOOSE = 62,
#define	CURTAINABL_LAST 62 /* UPDATE ME!!! */
#define	CURTAINABL_COUNT (CURTAINABL_LAST + 1)
};

#define	CURTAINABL_VALID(i)		((i) >= 0 && (i) <= CURTAINABL_LAST)
#define	CURTAINABL_USER_VALID(i)	(CURTAINABL_VALID(i) && (i) >= CURTAINABL_STDIO)

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

enum curtain_barrier {
	CURTAINBAR_PASS = 0,
	CURTAINBAR_GATE = 1,
	CURTAINBAR_WALL = 2,
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
	/* enum curtain_barrier */
	uint8_t on_self : 2, on_exec : 2;
};

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
	bool ct_finalized;
	struct {
		bool need_exec_switch;
		bool is_restricted_on_self;
		bool is_restricted_on_exec;
	} ct_cached;
	uint64_t ct_serial;
	struct barrier_mode ct_barriers[BARRIER_COUNT];
	struct curtain_mode ct_abilities[CURTAINABL_COUNT];
	struct curtain_item ct_slots[];
};

bool	curtain_cred_visible(const struct ucred *subject, const struct ucred *target,
	    enum barrier_type);

#endif

#endif

