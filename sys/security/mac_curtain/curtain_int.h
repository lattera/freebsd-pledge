#ifndef _CURTAIN_CURTAIN_INT_H_
#define	_CURTAIN_CURTAIN_INT_H_

#include <sys/types.h>
#include <sys/sysfil.h>
#include <sys/ucred.h>
#include <sys/sysctl.h>
#include <sys/queue.h>
#include <sys/curtainctl.h>
#include <sys/curtain_ability.h>
#include <sys/unveil.h>

enum curtain_action {
	CURTAINACT_ALLOW = 0,
	CURTAINACT_DENY = 1,
	CURTAINACT_TRAP = 2,
	CURTAINACT_KILL = 3,
#define	CURTAINACT_COUNT 4
} __packed;

struct curtain_mode {
	enum curtain_action soft : 2, hard : 2;
};

typedef uint16_t curtain_index;

CTASSERT(CURTAINCTL_MAX_ITEMS <= (curtain_index)-1);

struct curtain_unveil {
	struct curtain_unveil *parent;
	struct vnode *vp;
	uint32_t hash;
	unveil_perms soft_uperms, hard_uperms;
	uint8_t name_len;
	uint8_t depth;
	bool hidden_children : 1;
	bool name_ext : 1;
	char name[];
};

CTASSERT(NAME_MAX <= UINT8_MAX);
CTASSERT(sizeof(struct curtain_unveil) <= 32);

struct curtain_item {
	uint8_t type;
	struct curtain_mode mode;
	curtain_index chain;
	union curtain_key {
		/*
		 * Using __packed to reduce the alignment requirements on
		 * specific members to save 4 bytes per item on 64-bits archs.
		 */
		enum curtain_ability ability;
		unsigned long __packed ioctl;
		int sockaf;
		int socklvl;
		struct {
			int level, optname;
		} sockopt;
		int priv;
		int fibnum;
		struct sysctl_shadow __packed *sysctl;
		struct curtain_unveil __packed *unveil;
	} key;
};

CTASSERT(sizeof(struct curtain_item) <= 12);

struct curtain_head {
	struct barrier *cth_barrier;
};

typedef uint16_t barrier_bits;

#define	BARRIER_PROC_STATUS	(1 << 0)
#define	BARRIER_PROC_SIGNAL	(1 << 1)
#define	BARRIER_PROC_SCHED	(1 << 2)
#define	BARRIER_PROC_DEBUG	(1 << 3)
#define	BARRIER_SOCK		(1 << 4)
#define	BARRIER_POSIXIPC	(1 << 5)
#define	BARRIER_SYSVIPC		(1 << 6)
#define	BARRIER_DEVICE		(1 << 7)
#define	BARRIER_POSIXIPC_RENAME	(1 << 8)

#define	BARRIER_NONE	0
#define	BARRIER_ALL	-1

struct barrier_mode {
	barrier_bits soft, hard;
};

#define	CURTAIN_BARRIER(ct) ((ct)->ct_head.cth_barrier)

struct barrier {
	struct curtain_head br_head; /* cth_barrier will point to itself */
	struct barrier *br_parent;
	LIST_HEAD(, barrier) br_children;
	LIST_ENTRY(barrier) br_sibling;
	unsigned br_nchildren;
	volatile int br_ref;
	uint64_t br_serial;
	struct barrier_mode br_mode;
};

CTASSERT(sizeof(struct barrier) <= 64);

struct curtain {
	struct curtain_head ct_head;
#ifdef INVARIANTS
#define	CURTAIN_MAGIC 0x4355525441494e00ULL
	unsigned long long ct_magic;
#endif
	struct curtain *ct_on_exec;
	volatile int ct_ref;
	curtain_index ct_nslots;
	curtain_index ct_nitems;
	curtain_index ct_modulo;
	curtain_index ct_cellar;
	struct {
		sysfilset_t sysfilset;
		bool valid;
		bool restrictive;
		uint8_t sysfilacts[SYSFILSET_BITS];
	} ct_cached;
	struct curtain_mode ct_abilities[CURTAINABL_COUNT];
	bool ct_overflowed;
	struct curtain_item ct_slots[];
};

#define CURTAIN_STATS
#define CURTAIN_STATS_LOOKUP

SDT_PROVIDER_DECLARE(curtain);

SYSCTL_DECL(_security_curtain);
SYSCTL_DECL(_security_curtain_unveil);
#ifdef CURTAIN_STATS
SYSCTL_DECL(_security_curtain_stats);
#endif

extern unsigned __read_mostly curtain_log_level;
extern bool __read_mostly curtain_log_sysctls;

extern const sysfilset_t curtain_preserve_sysfils;
extern const sysfilset_t curtain_abilities_sysfils[CURTAINABL_COUNT];

extern int __read_mostly curtain_slot;
#define	CURTAIN_CTH_IS_CT(cth) ((cth) != &(cth)->cth_barrier->br_head)
#define	CURTAIN_SLOT_CTH(l) ((l) ? (struct curtain_head *)mac_label_get((l), curtain_slot) : NULL)
#define	CURTAIN_SLOT_CT_UNCHECKED(l) ((struct curtain *)CURTAIN_SLOT_CTH(l))
#define	CURTAIN_SLOT_CT(l) ({ \
	struct curtain_head *__cth; \
	struct curtain *__ct; \
	__cth = CURTAIN_SLOT_CTH(l); \
	__ct = __cth && CURTAIN_CTH_IS_CT(__cth) ? (struct curtain *)__cth : NULL; \
	MPASS(!__ct || __ct->ct_magic == CURTAIN_MAGIC); \
	__ct; \
})
#define	CURTAIN_SLOT_BR(l) ({ \
	struct curtain_head *__cth = CURTAIN_SLOT_CTH(l); \
	__cth ? __cth->cth_barrier : NULL; \
})

struct barrier *barrier_hold(struct barrier *);
struct barrier *barrier_dup(const struct barrier *);
void	barrier_bump(struct barrier *);
void	barrier_link(struct barrier *child, struct barrier *parent);
void	barrier_unlink(struct barrier *);
void	barrier_free(struct barrier *);
struct barrier *barrier_cross(struct barrier *, barrier_bits);
bool	barrier_visible(struct barrier *subject, const struct barrier *target,
	    barrier_bits);

void	curtain_invariants(const struct curtain *);
void	curtain_invariants_sync(const struct curtain *);
struct curtain *curtain_make(size_t nitems);
struct curtain *curtain_hold(struct curtain *);
void	curtain_free(struct curtain *);
struct curtain *curtain_dup(const struct curtain *);
struct curtain *curtain_dup_compact(const struct curtain *);
uint64_t curtain_serial(const struct curtain *);
struct curtain_item *curtain_lookup(const struct curtain *, enum curtainreq_type, union curtain_key);
struct curtain_item *curtain_search(struct curtain *, enum curtainreq_type, union curtain_key,
	    bool *inserted);
struct curtain_mode curtain_resolve(const struct curtain *,
	    enum curtainreq_type, union curtain_key );
bool	curtain_need_exec_switch(const struct curtain *);
bool	curtain_restrictive(const struct curtain *);
bool	curtain_equivalent(const struct curtain *, const struct curtain *);
void	curtain_cache_update(struct curtain *);
void	curtain_cred_update(const struct curtain *ct, struct ucred *cr);
void	curtain_exec_switch(struct curtain *);
void	curtain_harden(struct curtain *);
void	curtain_mask_sysfils(struct curtain *, sysfilset_t);
struct curtain_item *curtain_extend(struct curtain *, enum curtainreq_type, union curtain_key);
void	curtain_mask(struct curtain *dst, const struct curtain *src);
int	curtain_finish(struct curtain *, struct ucred *);

bool	curtain_cred_restricted(const struct curtain *, const struct ucred *);
bool	curtain_cred_visible(const struct ucred *subject, const struct ucred *target,
	    barrier_bits);
struct curtain *curtain_from_cred(struct ucred *);


struct unveil_cache {
	struct mtx mtx;
	uint64_t serial;
#define UNVEIL_CACHE_ENTRIES_COUNT 4
	struct unveil_cache_entry {
		struct vnode *vp;
		unsigned vp_nchash, vp_hash;
		struct curtain_unveil *cover;
	} entries[UNVEIL_CACHE_ENTRIES_COUNT];
};

struct unveil_tracker {
	uint64_t serial;
	struct curtain *ct;
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

struct unveil_cache *unveil_proc_get_cache(struct proc *, bool create);
void unveil_proc_drop_cache(struct proc *);

void	unveil_vnode_walk_roll(struct ucred *, int offset);
void	unveil_vnode_walk_annotate_file(struct ucred *, struct file *, struct vnode *);
int	unveil_vnode_walk_start_file(struct ucred *, struct file *);
int	unveil_vnode_walk_start(struct ucred *, struct vnode *);
void	unveil_vnode_walk_component(struct ucred *,
	    struct vnode *dvp, struct componentname *cnp, struct vnode *vp);
void	unveil_vnode_walk_backtrack(struct ucred *, struct vnode *dvp);
void	unveil_vnode_walk_replace(struct ucred *, struct vnode *from_vp, struct vnode *to_vp);
void	unveil_vnode_walk_created(struct ucred *, struct vnode *dvp, struct vnode *vp);
int	unveil_vnode_walk_fixup_errno(struct ucred *, int error);
bool	unveil_vnode_walk_dirent_visible(struct ucred *, struct vnode *dvp, struct dirent *dp);

struct unveil_tracker *unveil_track_get(struct ucred *, bool create);
struct unveil_tracker_entry *unveil_track_find(struct unveil_tracker *, struct vnode *);
struct unveil_tracker_entry *unveil_track_find_mount(struct unveil_tracker *, struct mount *);
void unveil_track_reset(struct unveil_tracker *);

unveil_perms curtain_lookup_mount(const struct curtain *, struct mount *);
int	curtain_fixup_unveils_parents(struct curtain *, struct ucred *);
int	curtain_finish_unveils(struct curtain *, struct ucred *);

#endif

