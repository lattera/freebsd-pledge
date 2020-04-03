#ifndef	_SYS_UNVEIL_H_
#define	_SYS_UNVEIL_H_

#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/vnode.h>
#include <sys/refcount.h>
#include <sys/_unveil.h>

#ifdef PLEDGE
MALLOC_DECLARE(M_UNVEIL);
#endif

enum {
	UNVEIL_PERM_RPATH = 1 << 0,
	UNVEIL_PERM_WPATH = 1 << 1,
	UNVEIL_PERM_CPATH = 1 << 2,
	UNVEIL_PERM_EXEC  = 1 << 3,
};

struct unveil_node {
	struct unveil_node *cover;
	RB_ENTRY(unveil_node) entry;
	struct vnode *vp;
	unveil_perms_t perms;
};

static inline void
unveil_init(struct unveil_base *base)
{
	*base = (struct unveil_base){
		.dir_root = RB_INITIALIZER(&base->dir_root),
	};
}

void unveil_merge(struct unveil_base *dst, struct unveil_base *src);
void unveil_destroy(struct unveil_base *);

struct unveil_node *unveil_lookup(struct unveil_base *, struct vnode *);

struct unveil_node *unveil_insert(struct unveil_base *,
    struct unveil_node *, struct vnode *);

#endif
