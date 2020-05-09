#ifndef	_SYS_UNVEIL_H_
#define	_SYS_UNVEIL_H_

#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/vnode.h>
#include <sys/refcount.h>
#include <sys/_unveil.h>

enum {
	UNVEIL_PERM_NONE  = 0,
	UNVEIL_PERM_ERROR = 1 << 0,
	UNVEIL_PERM_RPATH = 1 << 1,
	UNVEIL_PERM_WPATH = 1 << 2,
	UNVEIL_PERM_CPATH = 1 << 3,
	UNVEIL_PERM_EXEC  = 1 << 4,
	UNVEIL_PERM_ALL = (unveil_perms_t)-1
};

enum {
	UNVEIL_FLAG_ACTIVATE = 1 << 0,
	UNVEIL_FLAG_FINISH = 1 << 1,
	UNVEIL_FLAG_FOR_ALL = 1 << 2,
	UNVEIL_FLAG_FROM_EXEC = 1 << 3,
	UNVEIL_FLAG_HARDEN = 1 << 4,
	UNVEIL_FLAG_MASK = 1 << 5,
	UNVEIL_FLAG_NOFOLLOW = 1 << 6,
};

int unveilctl(int atfd, const char *path, int flags, int perms, int execperms);

#ifdef _KERNEL

#ifdef UNVEIL
MALLOC_DECLARE(M_UNVEIL);
#endif

struct unveil_node {
	struct unveil_node *cover;
	RB_ENTRY(unveil_node) entry;
	struct vnode *vp;
	unveil_perms_t hard_perms;
	unveil_perms_t soft_perms;
	unveil_perms_t exec_perms;
	bool from_exec;
};

void unveil_init(struct unveil_base *);
void unveil_merge(struct unveil_base *dst, struct unveil_base *src);
void unveil_clear(struct unveil_base *);
void unveil_free(struct unveil_base *);

struct unveil_node *unveil_lookup(struct unveil_base *, struct vnode *);
struct unveil_node *unveil_insert(struct unveil_base *, struct vnode *);

void unveil_fd_init(struct filedesc *);
void unveil_fd_merge(struct filedesc *dst, struct filedesc *src);
void unveil_fd_free(struct filedesc *);

void unveil_proc_exec_switch(struct thread *);

struct nameidata;
void unveil_namei_start(struct nameidata *, struct thread *);
void unveil_lookup_update(struct nameidata *, struct vnode *);
void unveil_lookup_update_dotdot(struct nameidata *, struct vnode *);
int unveil_lookup_check(struct nameidata *);

#endif /* _KERNEL */

#endif
