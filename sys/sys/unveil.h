#ifndef	_SYS_UNVEIL_H_
#define	_SYS_UNVEIL_H_

#include <sys/types.h>
#include <sys/vnode.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/_unveil.h>
#ifdef _KERNEL
#include <sys/systm.h>
#include <sys/limits.h>
#include <sys/capsicum.h>
#include <sys/proc.h>
#include <sys/namei.h>
#include <sys/curtain.h>
#endif

#define	UPERM_NONE		(0)
#define	UPERM_EXPOSE		(1 <<  0)
#define	UPERM_TRAVERSE		(1 <<  1)
#define	UPERM_SEARCH		(1 <<  2)
#define	UPERM_STATUS		(1 <<  3)
#define	UPERM_INSPECT		(UPERM_EXPOSE | UPERM_SEARCH | UPERM_STATUS)
#define	UPERM_BROWSE		(1 <<  8)
#define	UPERM_READ		(1 <<  9)
#define	UPERM_WRITE		(1 << 10)
#define	UPERM_CREATE		(1 << 11)
#define	UPERM_DELETE		(1 << 12)
#define	UPERM_EXECUTE		(1 << 13)
#define	UPERM_SETATTR		(1 << 14)
#define	UPERM_BIND		(1 << 16)
#define	UPERM_CONNECT		(1 << 17)
#define	UPERM_UNIX		(UPERM_BIND | UPERM_CONNECT)
#define	UPERM_TMPDIR		(1 << 23)
#define	UPERM_TMPDIR_CHILD	(1 << 24)
#define	UPERM_DEVFS		(1 << 25)
#define	UPERM_ALL		(-1)

static const unveil_perms uperms_inheritable =
    UPERM_BROWSE | UPERM_READ | UPERM_WRITE | UPERM_CREATE | UPERM_DELETE |
    UPERM_EXECUTE | UPERM_SETATTR | UPERM_BIND | UPERM_CONNECT |
    UPERM_DEVFS;

static const unveil_perms uperms_searchable = uperms_inheritable | UPERM_TMPDIR;
static const unveil_perms uperms_exposable = uperms_searchable & ~UPERM_DEVFS;

static inline unveil_perms
uperms_expand(unveil_perms uperms)
{
	if (uperms & uperms_searchable)
		uperms |= UPERM_SEARCH;
	if (uperms & uperms_exposable)
		uperms |= UPERM_EXPOSE;
	if (uperms & (UPERM_BROWSE | UPERM_READ))
		uperms |= UPERM_STATUS | UPERM_BROWSE;
	if (uperms & UPERM_SEARCH)
		uperms |= UPERM_TRAVERSE;
	if (uperms & UPERM_READ && uperms & UPERM_WRITE &&
	    uperms & UPERM_CREATE && uperms & UPERM_DELETE)
		uperms |= UPERM_TMPDIR;
	return (uperms);
}

static inline unveil_perms
uperms_inherit(unveil_perms uperms)
{
	return (uperms_expand(uperms & uperms_inheritable));
}


struct unveilreg {
	int atfd;
	int atflags;
	const char *path;
	/* return trail entries array for unveiled path */
	size_t tec;
	unveil_index (*tev)[2];
};

#define	UNVEILREG_MAX_TE	1024

int unveilreg(int flags, struct unveilreg *);

#define	UNVEILREG_VERSION_MASK	(0xff << 24)
#define	UNVEILREG_VERSION	(2 << 24)

#define	UNVEILREG_REGISTER	(1 <<  0 | UNVEILREG_VERSION)
#define	UNVEILREG_NONDIRBYNAME	(1 <<  9 | UNVEILREG_VERSION)

struct curtainent_unveil {
	uint16_t _reserved;
	unveil_index index;
	unveil_perms uperms;
};


#ifdef _KERNEL

enum unveil_on {
	UNVEIL_ON_SELF,
	UNVEIL_ON_EXEC,
};

static inline bool
unveil_active(struct thread *td)
{
#ifdef UNVEIL_SUPPORT
	return (sysfil_probe(td, SYSFIL_DEFAULT) != 0 &&
	    td->td_proc->p_unveils != NULL);
#else
	return (false);
#endif
}

struct unveil_base *unveil_proc_get_base(struct proc *, bool create);
void unveil_proc_drop_base(struct proc *);
void unveil_proc_exec_switch(struct proc *);
bool unveil_proc_need_exec_switch(struct proc *);

void unveil_base_init(struct unveil_base *);
void unveil_base_copy(struct unveil_base *dst, struct unveil_base *src);
void unveil_base_clear(struct unveil_base *);
void unveil_base_reset(struct unveil_base *);
void unveil_base_free(struct unveil_base *);

void unveil_base_write_begin(struct unveil_base *);
void unveil_base_write_end(struct unveil_base *);

void unveil_base_enable(struct unveil_base *, enum unveil_on);
void unveil_base_disable(struct unveil_base *, enum unveil_on);
void unveil_base_freeze(struct unveil_base *, enum unveil_on);
int unveil_index_set(struct unveil_base *, enum unveil_on, unsigned index, unveil_perms);
int unveil_index_check(struct unveil_base *, unsigned index);

void unveil_lockdown_fd(struct thread *);

#ifdef UNVEIL_SUPPORT

struct unveil_traversal;

struct unveil_ops {
	void (*traverse_begin)(struct thread *, struct unveil_traversal *,
	    bool bypass, bool reuse);
	int (*traverse_start)(struct thread *, struct unveil_traversal *,
	    struct vnode *);
	void (*traverse_component)(struct thread *, struct unveil_traversal *,
	    struct vnode *dvp, struct componentname *cnp, struct vnode *vp);
	void (*traverse_backtrack)(struct thread *, struct unveil_traversal *,
	    struct vnode *dvp);
	void (*traverse_replace)(struct thread *, struct unveil_traversal *,
	    struct vnode *from_vp, struct vnode *to_vp);
	unveil_perms (*traverse_uperms)(struct thread *, struct unveil_traversal *,
	    struct vnode *vp);
	void (*traverse_end)(struct thread *, struct unveil_traversal *);
	unveil_perms (*tracker_find)(struct thread *, struct vnode *);
	void (*tracker_substitute)(struct thread *,
	    struct vnode *old_vp, struct vnode *new_vp);
	void (*tracker_push_file)(struct thread *, struct file *);
	void (*tracker_save_file)(struct thread *, struct file *, struct vnode *);
	void (*tracker_clear)(struct thread *);
};

struct unveil_traversal {
	struct unveil_tree *tree;
	struct unveil_save *save;
	struct unveil_node *cover;
	unveil_perms actual_uperms;
	unveil_perms wanted_uperms;
	unsigned fill;
	bool bypass;
	bool uncharted;
	bool wanted_valid;
};

#endif

#endif /* _KERNEL */

#endif
