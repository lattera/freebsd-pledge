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

enum {
	UPERM_NONE = 0,
	UPERM_LPATH = 1 << 0,
	UPERM_RPATH = 1 << 1,
	UPERM_WPATH = 1 << 2,
	UPERM_CPATH = 1 << 3,
	UPERM_XPATH = 1 << 4,
	UPERM_APATH = 1 << 5,
	UPERM_TMPPATH = 1 << 6,
	UPERM_SUBTMPPATH = 1 << 7,
	UPERM_FOLLOW = 1 << 8,
	UPERM_EXPOSE = 1 << 9,
	UPERM_SEARCH = 1 << 10,
	UPERM_STATUS = 1 << 11,
	UPERM_INSPECT = UPERM_EXPOSE | UPERM_SEARCH | UPERM_STATUS,
	UPERM_BIND = 1 << 12,
	UPERM_CONNECT = 1 << 13,
	UPERM_UNIX = UPERM_BIND | UPERM_CONNECT,
	UPERM_ALL = -1,
};

static inline unveil_perms
uperms_expand(unveil_perms uperms)
{
	if (uperms & (UPERM_LPATH | UPERM_RPATH | UPERM_WPATH | UPERM_CPATH |
	              UPERM_XPATH | UPERM_APATH |
	              UPERM_BIND | UPERM_CONNECT |
	              UPERM_TMPPATH | UPERM_SUBTMPPATH))
		uperms |= UPERM_EXPOSE | UPERM_SEARCH;
	if (uperms & (UPERM_LPATH | UPERM_RPATH))
		uperms |= UPERM_STATUS | UPERM_LPATH;
	if (uperms & UPERM_STATUS)
		uperms |= UPERM_FOLLOW;
	if (uperms & UPERM_RPATH && uperms & UPERM_WPATH && uperms & UPERM_CPATH)
		uperms |= UPERM_TMPPATH | UPERM_SUBTMPPATH;
	return (uperms);
}

static const unveil_perms uperms_inheritable =
    ~(UPERM_FOLLOW | UPERM_EXPOSE | UPERM_SEARCH | UPERM_STATUS |
      UPERM_TMPPATH | UPERM_SUBTMPPATH);

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
#define	UNVEILREG_VERSION	(1 << 24)

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
