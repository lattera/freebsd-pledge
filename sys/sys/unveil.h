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
#include <sys/sysfil.h>
#endif

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

#define	UNVEILREG_VER_SHIFT	(24)
#define	UNVEILREG_VER_MASK	(0xff << UNVEILREG_VER_SHIFT)
#define	UNVEILREG_VERSION(v)	(((v) << UNVEILREG_VER_SHIFT) & UNVEILREG_VER_MASK)
#define	UNVEILREG_THIS_VERSION	UNVEILREG_VERSION(2)

#define	UNVEILREG_REGISTER	(1 <<  0)
#define	UNVEILREG_NONDIRBYNAME	(1 <<  9)

struct curtainent_unveil {
	uint16_t _reserved;
	unveil_index index;
	unveil_perms uperms;
};


#ifdef _KERNEL

struct unveil_base;

enum unveil_on {
	UNVEIL_ON_SELF,
	UNVEIL_ON_EXEC,
};

struct unveil_base *unveil_proc_get_base(struct proc *, bool create);
void unveil_proc_drop_base(struct proc *);

void unveil_base_init(struct unveil_base *);
void unveil_base_copy(struct unveil_base *dst, struct unveil_base *src);
void unveil_base_clear(struct unveil_base *);
void unveil_base_reset(struct unveil_base *);
void unveil_base_free(struct unveil_base *);

void unveil_base_write_begin(struct unveil_base *);
void unveil_base_write_end(struct unveil_base *);

void	unveil_vnode_walk_roll(struct ucred *, int offset);
void	unveil_vnode_walk_annotate_file(struct ucred *, struct file *, struct vnode *);
int	unveil_vnode_walk_start_file(struct ucred *, struct file *);
int	unveil_vnode_walk_start(struct ucred *, struct vnode *);
void	unveil_vnode_walk_component(struct ucred *,
	    struct vnode *dvp, struct componentname *cnp, struct vnode *vp);
void	unveil_vnode_walk_backtrack(struct ucred *, struct vnode *dvp);
void	unveil_vnode_walk_replace(struct ucred *, struct vnode *from_vp, struct vnode *to_vp);
void	unveil_vnode_walk_created(struct ucred *, struct vnode *dvp, struct vnode *vp);
int	unveil_vnode_walk_final(struct ucred *, int error);

#define	UNVEIL_ON_COUNT	2

struct unveil_base_flags {
	struct {
		bool frozen;
	} on[UNVEIL_ON_COUNT];
};

struct unveil_tracker {
	uint64_t serial;
	struct unveil_save *save;
	struct unveil_tree *tree;
	struct unveil_node *cover;
	struct unveil_base_flags flags;
	unveil_perms uperms;
#define	UNVEIL_TRACKER_ENTRIES_COUNT 2
	unsigned fill;
	bool uncharted;
	struct unveil_tracker_entry {
		struct vnode *vp;
		struct mount *mp;
		unsigned vp_nchash, vp_hash;
		int mp_gen;
		unveil_perms uperms, pending_uperms;
	} entries[UNVEIL_TRACKER_ENTRIES_COUNT];
};

struct unveil_stash {
	struct unveil_tree *tree;
	struct unveil_base_flags flags;
};

void unveil_stash_init(struct unveil_stash *);
void unveil_stash_copy(struct unveil_stash *dst, const struct unveil_stash *src);
void unveil_stash_free(struct unveil_stash *);

unveil_perms unveil_stash_mount_lookup(struct unveil_stash *, struct mount *);

void unveil_stash_begin(struct unveil_stash *, struct unveil_base *base);
int unveil_stash_update(struct unveil_stash *, enum unveil_on, unsigned index, unveil_perms);
void unveil_stash_exec_switch(struct unveil_stash *);
bool unveil_stash_need_exec_switch(const struct unveil_stash *);
void unveil_stash_switch(struct unveil_stash *, enum unveil_on, enum unveil_on);
void unveil_stash_unrestrict(struct unveil_stash *, enum unveil_on);
void unveil_stash_sweep(struct unveil_stash *, enum unveil_on);
void unveil_stash_inherit(struct unveil_stash *, enum unveil_on);
void unveil_stash_freeze(struct unveil_stash *, enum unveil_on);
void unveil_stash_commit(struct unveil_stash *, struct unveil_base *);

struct unveil_tracker *unveil_track_get(struct ucred *, bool create);
struct unveil_tracker_entry *unveil_track_find(struct unveil_tracker *, struct vnode *);
struct unveil_tracker_entry *unveil_track_find_mount(struct unveil_tracker *, struct mount *);
void unveil_track_reset(struct unveil_tracker *);

#endif /* _KERNEL */

#endif
