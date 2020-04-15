#ifndef	_SYS_UNVEIL_H_
#define	_SYS_UNVEIL_H_

#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/vnode.h>
#include <sys/refcount.h>
#include <sys/_unveil.h>

enum {
	UNVEIL_PERM_NONE  = 0,
	UNVEIL_PERM_RPATH = 1 << 0,
	UNVEIL_PERM_WPATH = 1 << 1,
	UNVEIL_PERM_CPATH = 1 << 2,
	UNVEIL_PERM_EXEC  = 1 << 3,
	UNVEIL_PERM_ALL   = (1 << 4) - 1
};

enum {
	UNVEIL_FLAG_FOR_ALL = 1 << 0,
	UNVEIL_FLAG_FREEZE = 1 << 1,
	UNVEIL_FLAG_RESTRICT = 1 << 2,
	UNVEIL_FLAG_REGULAR = 1 << 3,
	UNVEIL_FLAG_SPECIAL = 1 << 4,
};

int unveilctl(int atfd, const char *path, int flags, int perms);

#ifdef _KERNEL

#ifdef PLEDGE
MALLOC_DECLARE(M_UNVEIL);
#endif

struct unveil_node {
	struct unveil_node *cover;
	RB_ENTRY(unveil_node) entry;
	struct vnode *vp;
	unveil_perms_t regular_perms;
	unveil_perms_t special_perms;
	bool frozen;
};

static inline unveil_perms_t
unveil_node_perms(const struct unveil_node *node)
{
	return (node->regular_perms | node->special_perms);
}

void unveil_init(struct unveil_base *);
void unveil_merge(struct unveil_base *dst, struct unveil_base *src);
void unveil_destroy(struct unveil_base *);

struct unveil_node *unveil_lookup(struct unveil_base *, struct vnode *);

struct unveil_node *unveil_insert(struct unveil_base *,
    struct unveil_node *, struct vnode *);

#endif /* _KERNEL */

#endif
