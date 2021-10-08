#ifndef __LIBCURTAIN_H__
#define __LIBCURTAIN_H__

#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/curtain_ability.h>
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

#define CURTAIN_LEVEL_SHIFT	(24)
#define CURTAIN_LEVEL_MASK	(0x7 << CURTAIN_LEVEL_SHIFT)
#define CURTAIN_ALLOW		(0 << CURTAIN_LEVEL_SHIFT)
#define CURTAIN_PASS		(1 << CURTAIN_LEVEL_SHIFT)
#define CURTAIN_GATE		(2 << CURTAIN_LEVEL_SHIFT)
#define CURTAIN_WALL		(3 << CURTAIN_LEVEL_SHIFT)
#define CURTAIN_DENY		(4 << CURTAIN_LEVEL_SHIFT)
#define CURTAIN_TRAP		(5 << CURTAIN_LEVEL_SHIFT)
#define CURTAIN_KILL		(6 << CURTAIN_LEVEL_SHIFT)
#define CURTAIN_INHERIT		(1 << 16)
#define CURTAIN_UNVEIL_INHERIT	(CURTAIN_INHERIT)
#define CURTAIN_UNVEIL_INSPECT	(1 << 1)
#define CURTAIN_UNVEIL_NOFOLLOW	(1 << 2)

struct curtain_slot *curtain_slot(void);
struct curtain_slot *curtain_slot_on(enum curtain_on);
struct curtain_slot *curtain_slot_neutral(void);
void curtain_enable(struct curtain_slot *, enum curtain_on);
void curtain_disable(struct curtain_slot *, enum curtain_on);
void curtain_state(struct curtain_slot *, enum curtain_on, enum curtain_state);
int curtain_engage(void);
int curtain_enforce(void);
void curtain_reinit(void);

int curtain_default(struct curtain_slot *slot, unsigned flags);
int curtain_ability(struct curtain_slot *, enum curtain_ability ability, int flags);
int curtain_ioctl(struct curtain_slot *, unsigned long ioctl, int flags);
int curtain_ioctls(struct curtain_slot *, const unsigned long *ioctls, int flags);
int curtain_sockaf(struct curtain_slot *, int af, int flags);
int curtain_socklvl(struct curtain_slot *, int level, int flags);
int curtain_sockopt(struct curtain_slot *, int level, int optname, int flags);
int curtain_sockopts(struct curtain_slot *, const int (*sockopts)[2], int flags);
int curtain_priv(struct curtain_slot *, int priv, int flags);
int curtain_sysctl(struct curtain_slot *, const char *sysctl, int flags);
int curtain_unveil(struct curtain_slot *,
    const char *path, unsigned flags, unveil_perms uperms);
int curtain_unveils_limit(struct curtain_slot *, unveil_perms uperms);
int curtain_unveils_reset_all(void);


extern const unsigned long curtain_ioctls_tty_basic[];
extern const unsigned long curtain_ioctls_tty_pts[];
extern const unsigned long curtain_ioctls_net_basic[];
extern const unsigned long curtain_ioctls_net_route[];
extern const unsigned long curtain_ioctls_oss[];
extern const unsigned long curtain_ioctls_cryptodev[];
extern const unsigned long curtain_ioctls_bpf_all[];


struct curtain_config;

enum curtain_config_flags {
	CURTAIN_CONFIG_ON_EXEC_ONLY = 1 << 0,
};

int curtain_parse_unveil_perms(unveil_perms *, const char *);

struct curtain_config *curtain_config_new(unsigned flags);
void curtain_config_free(struct curtain_config *);

int curtain_config_verbosity(struct curtain_config *, int);
int curtain_config_unsafety(struct curtain_config *, int);

struct curtain_config_tag *curtain_config_tag_push_mem(struct curtain_config *, const char *buf, size_t len);

static inline struct curtain_config_tag *
curtain_config_tag_push(struct curtain_config *cfg, const char *name)
{
	return (curtain_config_tag_push_mem(cfg, name, strlen(name)));
}

struct curtain_config_tag *curtain_config_tag_block_mem(struct curtain_config *, const char *buf, size_t len);

static inline struct curtain_config_tag *
curtain_config_tag_block(struct curtain_config *cfg, const char *name)
{
	return (curtain_config_tag_block_mem(cfg, name, strlen(name)));
}

void curtain_config_load(struct curtain_config *);
void curtain_config_tags_from_env(struct curtain_config *);
void curtain_config_tags_clear(struct curtain_config *);

int curtain_config_directive(struct curtain_config *, struct curtain_slot *,
    const char *directive);

int curtain_config_setup_x11(struct curtain_config *, bool trusted);
int curtain_config_setup_wayland(struct curtain_config *);
int curtain_config_setup_tmpdir(struct curtain_config *, bool separate);

#endif
