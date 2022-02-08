#ifndef _SYS_CURTAINCTL_H_
#define	_SYS_CURTAINCTL_H_

#include <sys/curtain_ability.h>
#include <sys/_unveil.h>

enum curtainreq_type {
	CURTAINTYP_DEFAULT = 1,
	CURTAINTYP_ABILITY = 2,
	CURTAINTYP_OLD_UNVEIL = 3,
	CURTAINTYP_UNVEIL = 11,
	CURTAINTYP_IOCTL = 4,
	CURTAINTYP_SYSCTL = 9,
	CURTAINTYP_PRIV = 8,
	CURTAINTYP_SOCKAF = 5,
	CURTAINTYP_SOCKLVL = 6,
	CURTAINTYP_SOCKOPT = 7,
	CURTAINTYP_GETSOCKOPT = 12,
	CURTAINTYP_SETSOCKOPT = 13,
	CURTAINTYP_FIBNUM = 10,
#define	CURTAINTYP_LAST 13 /* UPDATE ME!!! */
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
#define	CURTAINCTL_THIS_VERSION	CURTAINCTL_VERSION(8)

#define	CURTAINCTL_REPLACE	(1 <<  0)
#define	CURTAINCTL_SOFT		(1 <<  8)

#define	CURTAINREQ_ON_SELF	(1 << 16)
#define	CURTAINREQ_ON_EXEC	(1 << 17)
#define	CURTAINREQ_ON_BOTH	(CURTAINREQ_ON_SELF | CURTAINREQ_ON_EXEC)

struct curtainent_unveil {
	int dir_fd;
	unveil_perms uperms;
	char name[];
};

#endif

