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
#include <sys/capsicum.h>
#include <sys/proc.h>
#endif

#define	UPERM_NONE		(0)
#define	UPERM_EXPOSE		(1 <<  0)
#define	UPERM_FOLLOW		(1 <<  1)
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
#define	UPERM_ALL		(-1)

static const unveil_perms uperms_inheritable =
    UPERM_BROWSE | UPERM_READ | UPERM_WRITE | UPERM_CREATE | UPERM_DELETE |
    UPERM_EXECUTE | UPERM_SETATTR | UPERM_BIND | UPERM_CONNECT;

static inline unveil_perms
uperms_expand(unveil_perms uperms)
{
	if (uperms & (uperms_inheritable | UPERM_TMPDIR))
		uperms |= UPERM_EXPOSE | UPERM_SEARCH;
	if (uperms & (UPERM_BROWSE | UPERM_READ))
		uperms |= UPERM_STATUS | UPERM_BROWSE;
	if (uperms & UPERM_STATUS)
		uperms |= UPERM_FOLLOW;
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
#define	UNVEILREG_INTERMEDIATE	(1 <<  8 | UNVEILREG_VERSION)
#define	UNVEILREG_NONDIRBYNAME	(1 <<  9 | UNVEILREG_VERSION)

struct curtainent_unveil {
	uint16_t _reserved;
	unveil_index index;
	unveil_perms uperms;
};


#ifdef _KERNEL

#ifdef UNVEIL
MALLOC_DECLARE(M_UNVEIL);
#endif

enum unveil_on {
	UNVEIL_ON_SELF,
	UNVEIL_ON_EXEC,
};

static inline bool
unveil_is_active(struct thread *td)
{
#ifdef UNVEIL
	return (td->td_proc->p_unveils.on[UNVEIL_ON_SELF].active);
#else
	return (false);
#endif
}

static inline bool
unveil_exec_is_active(struct thread *td)
{
#ifdef UNVEIL
	return (td->td_proc->p_unveils.on[UNVEIL_ON_EXEC].active);
#else
	return (false);
#endif
}


void unveil_proc_exec_switch(struct thread *);

void unveil_base_init(struct unveil_base *);
void unveil_base_copy(struct unveil_base *dst, struct unveil_base *src);
void unveil_base_clear(struct unveil_base *);
void unveil_base_reset(struct unveil_base *);
void unveil_base_free(struct unveil_base *);

void unveil_base_write_begin(struct unveil_base *);
void unveil_base_write_end(struct unveil_base *);

void unveil_base_activate(struct unveil_base *, enum unveil_on);
void unveil_base_enforce(struct unveil_base *, enum unveil_on);
int unveil_index_set(struct unveil_base *, enum unveil_on, unsigned index, unveil_perms);
int unveil_index_check(struct unveil_base *, unsigned index);

int unveil_traverse_begin(struct thread *, struct unveil_traversal *,
    struct vnode *);
int unveil_traverse(struct thread *, struct unveil_traversal *,
    struct vnode *dvp, const char *name, size_t name_len, struct vnode *vp,
    bool final);
void unveil_traverse_dotdot(struct thread *, struct unveil_traversal *,
    struct vnode *);
unveil_perms unveil_traverse_effective_uperms(struct thread *, struct unveil_traversal *);
void unveil_traverse_end(struct thread *, struct unveil_traversal *);

void unveil_uperms_rights(unveil_perms, cap_rights_t *);

#endif /* _KERNEL */

#endif
