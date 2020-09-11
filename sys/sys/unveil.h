#ifndef	_SYS_UNVEIL_H_
#define	_SYS_UNVEIL_H_

#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/vnode.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/_unveil.h>
#ifdef _KERNEL
#include <sys/systm.h>
#include <sys/limits.h>
#endif

enum {
	UNVEIL_PERM_NONE = 0,
	UNVEIL_PERM_INSPECT = 1 << 0,
	UNVEIL_PERM_RPATH = 1 << 1,
	UNVEIL_PERM_WPATH = 1 << 2,
	UNVEIL_PERM_CPATH = 1 << 3,
	UNVEIL_PERM_XPATH = 1 << 4,
	/* NOTE: last bit used internally */
	UNVEIL_PERM_ALL = (1 << (8 - 1)) - 1,
	UNVEIL_PERM_NONINHERITED_MASK = UNVEIL_PERM_INSPECT,
#ifdef _KERNEL
	UNVEIL_PERM_FINAL = 1 << 7,
	/* NOTE: the internal last bit is included in the "full" mask */
	UNVEIL_PERM_FULL_MASK = (1 << 8) - 1,
#endif
};

enum {
	UNVEIL_FLAG_SWEEP = 1 << 0,
	UNVEIL_FLAG_FREEZE = 1 << 1,
	UNVEIL_FLAG_LIMIT = 1 << 2,
	UNVEIL_FLAG_ACTIVATE = 1 << 3,
	UNVEIL_FLAG_NOFOLLOW = 1 << 8,
	UNVEIL_FLAG_NOINHERIT = 1 << 9,
	UNVEIL_FLAG_INTERMEDIATE = 1 << 10,
	UNVEIL_FLAG_INSPECTABLE = 1 << 11,
	UNVEIL_FLAG_NONDIRBYNAME = 1 << 12,
	UNVEIL_FLAG_ROLE_SHIFT = 16,
	UNVEIL_FLAG_ROLE_WIDTH = 8,
	UNVEIL_FLAG_FOR_CURR = 1 << 16,
	UNVEIL_FLAG_FOR_EXEC = 1 << 17,
	UNVEIL_FLAG_FOR_ALL_ROLES =
	    ((1 << UNVEIL_FLAG_ROLE_WIDTH) - 1) << UNVEIL_FLAG_ROLE_SHIFT,
	UNVEIL_FLAG_SLOT_SHIFT = 24,
	UNVEIL_FLAG_SLOT_WIDTH = 8,
	UNVEIL_FLAG_FOR_SLOT0 = 1 << 24,
	UNVEIL_FLAG_FOR_SLOT1 = 1 << 25,
	UNVEIL_FLAG_FOR_ALL_SLOTS =
	    ((1 << UNVEIL_FLAG_SLOT_WIDTH) - 1) << UNVEIL_FLAG_SLOT_SHIFT,
	UNVEIL_FLAG_FOR_ALL =
	    UNVEIL_FLAG_FOR_ALL_ROLES | UNVEIL_FLAG_FOR_ALL_SLOTS,
};

int unveilctl(int atfd, const char *path, int flags, int perms);

#ifdef _KERNEL

#ifdef UNVEIL
MALLOC_DECLARE(M_UNVEIL);
#endif

enum unveil_role {
	UNVEIL_ROLE_CURR,
	UNVEIL_ROLE_EXEC,
};

enum {
	UNVEIL_ROLE_COUNT = 2,
	UNVEIL_SLOT_COUNT = 2,
};

struct unveil_node {
	struct unveil_node *cover;
	RB_ENTRY(unveil_node) entry;
	/*
	 * If name is NULL, the node is not name-based and vp is a directly
	 * unveiled vnode.  Otherwise, vp is the vnode of a parent directory
	 * under which the name is unveiled.
	 */
	struct vnode *vp;
	unveil_perms_t frozen_perms[UNVEIL_ROLE_COUNT];
	unveil_perms_t wanted_perms[UNVEIL_ROLE_COUNT][UNVEIL_SLOT_COUNT];
	u_char name_len;
	char *name;
};

CTASSERT(NAME_MAX <= UCHAR_MAX);

unveil_perms_t unveil_node_soft_perms(struct unveil_node *, enum unveil_role);
unveil_perms_t unveil_node_effective_perms(struct unveil_node *, struct vnode *vp);

void unveil_init(struct unveil_base *);
void unveil_merge(struct unveil_base *dst, struct unveil_base *src);
void unveil_clear(struct unveil_base *);
void unveil_free(struct unveil_base *);

struct unveil_node *unveil_lookup(struct unveil_base *,
    struct vnode *, const char *name, size_t name_len);
struct unveil_node *unveil_insert(struct unveil_base *,
    struct vnode *, const char *name, size_t name_len, struct unveil_node *cover);

struct unveil_namei_data;

int unveil_traverse_save(struct unveil_base *,
    struct unveil_namei_data *, struct unveil_node **cover,
    struct vnode *dvp, const char *name, size_t name_len, struct vnode *vp, bool last);
int unveil_traverse(struct unveil_base *,
    struct unveil_namei_data *, struct unveil_node **cover,
    struct vnode *dvp, const char *name, size_t name_len, struct vnode *vp, bool last);
void unveil_traverse_dotdot(struct unveil_base *,
    struct unveil_namei_data *, struct unveil_node **cover,
    struct vnode *dvp);

void unveil_fd_init(struct filedesc *);
void unveil_fd_merge(struct filedesc *dst, struct filedesc *src);
void unveil_fd_free(struct filedesc *);

void unveil_proc_exec_switch(struct thread *);

int unveil_find_cover(struct thread *, struct vnode *, struct unveil_node **);

#endif /* _KERNEL */

#endif
