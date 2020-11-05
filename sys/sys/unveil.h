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
	UNVEIL_PERM_ALL = -1,
	UNVEIL_PERM_NONINHERITED_MASK = UNVEIL_PERM_INSPECT,
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

static bool
unveil_is_active(struct thread *td)
{
	return (td->td_proc->p_fd->fd_unveil.active);
}

int unveil_traverse_begin(struct thread *, struct unveil_traversal *,
    struct vnode *);
int unveil_traverse(struct thread *, struct unveil_traversal *,
    struct vnode *dvp, const char *name, size_t name_len, struct vnode *vp);
void unveil_traverse_dotdot(struct thread *, struct unveil_traversal *,
    struct vnode *);
unveil_perms_t unveil_traverse_effective_perms(struct thread *, struct unveil_traversal *);

void unveil_fd_init(struct filedesc *);
void unveil_fd_merge(struct filedesc *dst, struct filedesc *src);
void unveil_fd_free(struct filedesc *);

void unveil_proc_exec_switch(struct thread *);

#endif /* _KERNEL */

#endif
