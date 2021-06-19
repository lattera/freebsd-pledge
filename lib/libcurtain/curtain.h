#ifndef __LIBCURTAIN_H__
#define __LIBCURTAIN_H__

#include <sys/sysfil.h>
#include <sys/unveil.h>

struct curtain_slot;

enum curtain_on { CURTAIN_ON_SELF, CURTAIN_ON_EXEC };
enum { CURTAIN_ON_COUNT = 2 };

enum curtain_state {
	CURTAIN_NEUTRAL = -1,
	CURTAIN_DISABLED = 0,
	CURTAIN_RESERVED = 1,
	CURTAIN_ENABLED = 2,
};

enum {
	CURTAIN_UNVEIL_INHERIT = 1 << 0,
	CURTAIN_UNVEIL_INSPECT = 1 << 1,

	CURTAIN_LEVEL_SHIFT = 24,
	CURTAIN_LEVEL_MASK = 0x3 << CURTAIN_LEVEL_SHIFT,
	CURTAIN_PASS = 0 << CURTAIN_LEVEL_SHIFT,
	CURTAIN_DENY = 1 << CURTAIN_LEVEL_SHIFT,
	CURTAIN_TRAP = 2 << CURTAIN_LEVEL_SHIFT,
	CURTAIN_KILL = 3 << CURTAIN_LEVEL_SHIFT,
};

struct curtain_slot *curtain_slot(void);
struct curtain_slot *curtain_slot_on(enum curtain_on);
struct curtain_slot *curtain_slot_neutral(void);
void curtain_enable(struct curtain_slot *, enum curtain_on);
void curtain_disable(struct curtain_slot *, enum curtain_on);
void curtain_state(struct curtain_slot *, enum curtain_on, enum curtain_state);

int curtain_apply(void);
int curtain_enforce(void);

int curtain_default(struct curtain_slot *slot, unsigned flags);
int curtain_sysfil(struct curtain_slot *, int sysfil, int flags);
int curtain_ioctl(struct curtain_slot *, unsigned long ioctl, int flags);
int curtain_ioctls(struct curtain_slot *, const unsigned long *ioctls, int flags);
int curtain_sockaf(struct curtain_slot *, int af, int flags);
int curtain_socklvl(struct curtain_slot *, int level, int flags);
int curtain_sockopt(struct curtain_slot *, int level, int optname, int flags);
int curtain_sockopts(struct curtain_slot *, const int (*sockopts)[2], int flags);
int curtain_unveil(struct curtain_slot *,
    const char *path, unsigned flags, unveil_perms uperms);
int curtain_unveils_limit(struct curtain_slot *, unveil_perms uperms);

extern const unsigned long curtain_ioctls_tty_basic[];

#endif
