#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/curtain.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/tree.h>
#include <sys/types.h>
#include <sys/unveil.h>
#include <sysexits.h>

#include <curtain.h>

/*
 * Things that can be restricted (or allowed) are represented by "nodes".
 * Nodes are identified by a type and key and are arranged in an inheritance
 * hierarchy.  "Modes" represent the permissions that can be assigned.
 * Permissions are not directly assigned to nodes, but indirectly through
 * "items".  Items are grouped into "slots" which can have their state changed
 * as a whole.  Items within the same slot can override each others, but not
 * across slots (the idea is that different sets of permissions that are to be
 * merged should never interfere with each others and result in lesser
 * permissions for certain nodes).
 */

struct curtain_slot {
	struct curtain_slot *next;
	struct curtain_node *nodes;
	struct curtain_item *items;
	size_t items_count;
	enum curtain_state state_on[CURTAIN_ON_COUNT];
};

struct curtain_mode {
	union {
		enum curtainreq_level level;
		unveil_perms uperms;
	};
};

struct curtain_node {
	struct curtain_type *type;
	struct curtain_node *parent, *children, *sibling;
	struct curtain_node *slot_next, *type_next;
	struct curtain_item *items;
	size_t items_count;
	union curtain_key {
		enum curtain_ability ability;
		unsigned long ioctl;
		int sockaf;
		int socklvl;
		int sockopt[2];
		int priv;
		struct {
			size_t len;
			const int *mib;
		} sysctl;
		int fibnum;
		unveil_index unveil_idx;
	} key;
	/* scratch */
	bool has_mode_on[CURTAIN_ON_COUNT];
	struct curtain_mode combined_mode_on[CURTAIN_ON_COUNT];
};

struct curtain_item {
	struct curtain_slot *slot;
	struct curtain_node *node;
	struct curtain_item *node_next, *slot_next;
	struct curtain_item *inherit_next, **saved_link, *saved; /* scratch */
	bool override;
	struct curtain_mode mode;
	struct curtain_mode inherited_mode; /* scratch */
};

struct mode_type {
	struct curtain_mode null;
	bool (*is_null)(struct curtain_mode);
	struct curtain_mode (*merge)(struct curtain_mode, struct curtain_mode);
	struct curtain_mode (*inherit)(struct curtain_mode);
	enum curtainreq_level (*level)(struct curtain_mode);
};

struct curtain_type {
	enum curtainreq_type req_type;
	size_t nodes_count, items_count;
	struct curtain_node *nodes;
	struct curtain_node *(*fallback)(struct curtain_node *);
	int (*key_cmp)(const union curtain_key *, const union curtain_key *);
	size_t (*ent_size)(const union curtain_key *);
	void *(*ent_fill)(void *, const union curtain_key *, struct curtain_mode);
	const struct mode_type *mode;
};


static struct curtain_slot *curtain_slots = NULL;

static struct curtain_slot *
curtain_slot_1(const enum curtain_state state_on[CURTAIN_ON_COUNT])
{
	struct curtain_slot *slot;
	slot = malloc(sizeof *slot);
	if (!slot)
		return (NULL);
	*slot = (struct curtain_slot){ 0 };
	memcpy(slot->state_on, state_on, sizeof slot->state_on);
	slot->next = curtain_slots;
	curtain_slots = slot;
	return (slot);
}

struct curtain_slot *
curtain_slot(void)
{
	enum curtain_state state_on[CURTAIN_ON_COUNT] = {
		[CURTAIN_ON_SELF] = CURTAIN_ENABLED,
		[CURTAIN_ON_EXEC] = CURTAIN_ENABLED,
	};
	return (curtain_slot_1(state_on));
}

struct curtain_slot *
curtain_slot_neutral(void)
{
	enum curtain_state state_on[CURTAIN_ON_COUNT];
	for (enum curtain_on on = 0; on < CURTAIN_ON_COUNT; on++)
		state_on[on] = CURTAIN_NEUTRAL;
	return (curtain_slot_1(state_on));
}

struct curtain_slot *
curtain_slot_on(enum curtain_on on)
{
	enum curtain_state state_on[CURTAIN_ON_COUNT] = { 0 };
	state_on[on] = CURTAIN_ENABLED;
	return (curtain_slot_1(state_on));
}

void
curtain_enable(struct curtain_slot *slot, enum curtain_on on)
{ slot->state_on[on] = CURTAIN_ENABLED; };

void
curtain_disable(struct curtain_slot *slot, enum curtain_on on)
{ slot->state_on[on] = CURTAIN_DISABLED; };

void
curtain_state(struct curtain_slot *slot, enum curtain_on on, enum curtain_state state)
{ slot->state_on[on] = state; }

enum { CURTAIN_LEVEL_COUNT = CURTAINLVL_COUNT };


static enum curtainreq_level
flags2level(int flags)
{
	switch (flags & CURTAIN_LEVEL_MASK) {
	case CURTAIN_PASS:	return (CURTAINLVL_PASS);	break;
	case CURTAIN_GATE:	return (CURTAINLVL_GATE);	break;
	case CURTAIN_ALLOW:	/* FALLTHROUGH */
	case CURTAIN_WALL:	return (CURTAINLVL_WALL);	break;
	case CURTAIN_DENY:	return (CURTAINLVL_DENY);	break;
	case CURTAIN_TRAP:	return (CURTAINLVL_TRAP);	break;
	default:
	case CURTAIN_KILL:	return (CURTAINLVL_KILL);	break;
	}
}

static struct curtain_node *curtain_root_nodes;

static void
node_reparent(struct curtain_node *child, struct curtain_node *parent)
{
	/*
	 * When parent is NULL, the child is linked in the curtain_root_nodes
	 * list.  Otherwise, it's linked in the parent node's children list.
	 */
	struct curtain_node **link;
	assert(child != parent);
	/* unlink from old */
	for (link = child->parent ? &child->parent->children : &curtain_root_nodes;
	    *link != child;
	    link = &(*link)->sibling);
	*link = child->sibling;
	/* link in new */
	link = (child->parent = parent) ? &child->parent->children : &curtain_root_nodes;
	child->sibling = *link;
	*link = child;
}

static struct curtain_node *
node_get(struct curtain_type *type, union curtain_key key, bool create)
{
	struct curtain_node *node, **link;
	for (link = &type->nodes; (node = *link); link = &node->type_next)
		if (type->key_cmp(&node->key, &key) == 0)
			break;
	if (node) { /* move-to-front heuristic */
		assert(node->type == type);
		*link = node->type_next;
		node->type_next = type->nodes;
		type->nodes = node;
	} else if (create) {
		node = malloc(sizeof *node);
		if (!node)
			err(EX_TEMPFAIL, "malloc");
		*node = (struct curtain_node){
			.type = type,
			.type_next = *link,
			.parent = NULL,
			.sibling = curtain_root_nodes,
			.key = key,
		};
		*link = node;
		curtain_root_nodes = node;
		type->nodes_count++;
		if (node->type->fallback)
			node_reparent(node, node->type->fallback(node));
	}
	return (node);
}

static struct curtain_item *
item_get(struct curtain_node *node, struct curtain_slot *slot, bool create)
{
	struct curtain_item *item, **nlink;
	if (slot->items_count < node->items_count/2) {
		nlink = NULL;
		for (item = slot->items; item && item->node != node; item = item->slot_next);
	} else {
nslot:		for (nlink = &node->items; (item = *nlink); nlink = &item->node_next)
			/* keeping list ordered by slot */
			if ((uintptr_t)slot <= (uintptr_t)item->slot) {
				if (slot != item->slot)
					item = NULL;
				break;
			}
	}
	if (!item && create) {
		if (!nlink)
			goto nslot;
		item = malloc(sizeof *item);
		if (!item)
			err(EX_TEMPFAIL, "malloc");
		*item = (struct curtain_item){
			.slot = slot,
			.node = node,
			.node_next = *nlink,
			.slot_next = slot->items,
			.override = false,
			.mode = node->type->mode->null,
		};
		*nlink = item;
		slot->items = item;
		node->items_count++;
		slot->items_count++;
		node->type->items_count++;
	}
	return (item);
}

static struct curtain_item *
node_item_get(struct curtain_type *type, struct curtain_slot *slot,
    union curtain_key key, bool create)
{
	struct curtain_node *node;
	node = node_get(type, key, create);
	if (!node)
		return (NULL);
	return (item_get(node, slot, create));
}

static void
item_set_flags(struct curtain_item *item, int flags)
{
	item->override = !(flags & CURTAIN_INHERIT);
}

static void
item_set_flags_level(struct curtain_item *item, int flags)
{
	item_set_flags(item, flags);
	item->mode.level = flags2level(flags);
}

#define	KEY(m, ...) (union curtain_key){ m = __VA_ARGS__ }
#define	CMP(a, b) ((a) < (b) ? -1 : (a) > (b) ? 1 : 0)

#define	DEF_SIMPLE_KEY_FUNCS(name, key_field) \
	static int name ## _key_cmp(const union curtain_key *key0, const union curtain_key *key1) \
		{ return (CMP(key0->key_field, key1->key_field)); }

#define	DEF_SIMPLE_ENT_FUNCS(name, key_field, ent_type) \
	static size_t name ## _ent_size(const union curtain_key *key __unused) \
		{ return (sizeof (ent_type)); } \
	static void *name ## _ent_fill(void *dest, \
	    const union curtain_key *key, struct curtain_mode mode __unused) \
		{ ent_type *fill = dest; *fill++ = key->key_field; return (fill); }


static bool
level_mode_is_null(struct curtain_mode m)
{ return (m.level >= CURTAINLVL_LEAST); }

static struct curtain_mode
level_mode_merge(struct curtain_mode m1, struct curtain_mode m2)
{ return ((struct curtain_mode){ .level = MIN(m1.level, m2.level) }); }

static struct curtain_mode
level_mode_inherit(struct curtain_mode m)
{ return (m); }

static enum curtainreq_level
level_mode_level(struct curtain_mode m)
{ return (m.level); }

static const struct mode_type level_mode_type = {
	.null = { .level = CURTAINLVL_LEAST },
	.is_null = level_mode_is_null,
	.inherit = level_mode_inherit,
	.merge = level_mode_merge,
	.level = level_mode_level,
};


static int
default_key_cmp(const union curtain_key *key0 __unused, const union curtain_key *key1 __unused)
{ return (0); }

static size_t
default_ent_size(const union curtain_key *key __unused)
{ return (0); }

static void *
default_ent_fill(void *dest,
    const union curtain_key *key __unused, struct curtain_mode mode __unused)
{ return (dest); }

static struct curtain_type default_type = {
	.req_type = CURTAINTYP_DEFAULT,
	.key_cmp = default_key_cmp,
	.ent_size = default_ent_size,
	.ent_fill = default_ent_fill,
	.mode = &level_mode_type,
};

int
curtain_default(struct curtain_slot *slot, unsigned flags)
{
	struct curtain_item *item;
	item = node_item_get(&default_type, slot, (union curtain_key){ 0 }, true);
	if (!item)
		return (-1);
	item_set_flags_level(item, flags);
	return (0);
}


DEF_SIMPLE_KEY_FUNCS(ability, ability);
DEF_SIMPLE_ENT_FUNCS(ability, ability, enum curtain_ability);

static struct curtain_node *
ability_fallback(struct curtain_node *node __unused)
{
	return (node_get(&default_type, (union curtain_key){ 0 }, true));
}

static struct curtain_type abilities_type = {
	.req_type = CURTAINTYP_ABILITY,
	.fallback = ability_fallback,
	.key_cmp = ability_key_cmp,
	.ent_size = ability_ent_size,
	.ent_fill = ability_ent_fill,
	.mode = &level_mode_type,
};

static struct curtain_node *
ability_fallback_helper(struct curtain_node *node)
{
	enum curtain_ability ability = curtain_type_fallback[node->type->req_type];
	return (node_get(&abilities_type, KEY(.ability, ability), true));
}

int
curtain_ability(struct curtain_slot *slot, enum curtain_ability ability, int flags)
{
	struct curtain_item *item;
	item = node_item_get(&abilities_type, slot, KEY(.ability, ability), true);
	if (!item)
		return (-1);
	item_set_flags_level(item, flags);
	return (0);
}


DEF_SIMPLE_KEY_FUNCS(ioctl, ioctl);
DEF_SIMPLE_ENT_FUNCS(ioctl, ioctl, unsigned long);

static struct curtain_type ioctls_type = {
	.req_type = CURTAINTYP_IOCTL,
	.fallback = ability_fallback_helper,
	.key_cmp = ioctl_key_cmp,
	.ent_size = ioctl_ent_size,
	.ent_fill = ioctl_ent_fill,
	.mode = &level_mode_type,
};

int
curtain_ioctl(struct curtain_slot *slot, unsigned long ioctl, int flags)
{
	struct curtain_item *item;
	item = node_item_get(&ioctls_type, slot, KEY(.ioctl, ioctl), true);
	if (!item)
		return (-1);
	item_set_flags_level(item, flags);
	return (0);
}

int
curtain_ioctls(struct curtain_slot *slot, const unsigned long *ioctls, int flags)
{
	for (const unsigned long *p = ioctls; *p != (unsigned long)-1; p++)
		curtain_ioctl(slot, *p, flags);
	return (0);
}


DEF_SIMPLE_KEY_FUNCS(sockaf, sockaf);
DEF_SIMPLE_ENT_FUNCS(sockaf, sockaf, int);

static struct curtain_type sockafs_type = {
	.req_type = CURTAINTYP_SOCKAF,
	.fallback = ability_fallback_helper,
	.key_cmp = sockaf_key_cmp,
	.ent_size = sockaf_ent_size,
	.ent_fill = sockaf_ent_fill,
	.mode = &level_mode_type,
};

int
curtain_sockaf(struct curtain_slot *slot, int sockaf, int flags)
{
	struct curtain_item *item;
	item = node_item_get(&sockafs_type, slot, KEY(.sockaf, sockaf), true);
	if (!item)
		return (-1);
	item_set_flags_level(item, flags);
	return (0);
}


DEF_SIMPLE_KEY_FUNCS(socklvl, socklvl);
DEF_SIMPLE_ENT_FUNCS(socklvl, socklvl, int);

static struct curtain_type socklvls_type = {
	.req_type = CURTAINTYP_SOCKLVL,
	.fallback = ability_fallback_helper,
	.key_cmp = socklvl_key_cmp,
	.ent_size = socklvl_ent_size,
	.ent_fill = socklvl_ent_fill,
	.mode = &level_mode_type,
};

int
curtain_socklvl(struct curtain_slot *slot, int socklvl, int flags)
{
	struct curtain_item *item;
	item = node_item_get(&socklvls_type, slot, KEY(.socklvl, socklvl), true);
	if (!item)
		return (-1);
	item_set_flags_level(item, flags);
	return (0);
}


static int
sockopt_key_cmp(const union curtain_key *key0, const union curtain_key *key1)
{
	if (CMP(key0->sockopt[0], key1->sockopt[0]) != 0)
		return (CMP(key0->sockopt[0], key1->sockopt[0]));
	return (CMP(key0->sockopt[1], key1->sockopt[1]));
}

static size_t
sockopt_ent_size(const union curtain_key *key __unused)
{
	return (sizeof (int [2]));
}

static void *
sockopt_ent_fill(void *dest,
    const union curtain_key *key, struct curtain_mode mode __unused)
{
	int *fill = dest;
	*fill++ = key->sockopt[0];
	*fill++ = key->sockopt[1];
	return (fill);
}

static struct curtain_node *
sockopt_fallback(struct curtain_node *node)
{
	return (node_get(&socklvls_type, KEY(.socklvl, node->key.sockopt[0]), true));
}

static struct curtain_type sockopts_type = {
	.req_type = CURTAINTYP_SOCKOPT,
	.fallback = sockopt_fallback,
	.key_cmp = sockopt_key_cmp,
	.ent_size = sockopt_ent_size,
	.ent_fill = sockopt_ent_fill,
	.mode = &level_mode_type,
};

int
curtain_sockopt(struct curtain_slot *slot, int level, int optname, int flags)
{
	struct curtain_item *item;
	item = node_item_get(&sockopts_type, slot, KEY(.sockopt, { level, optname }), true);
	if (!item)
		return (-1);
	item_set_flags_level(item, flags);
	return (0);
}

int
curtain_sockopts(struct curtain_slot *slot, const int (*sockopts)[2], int flags)
{
	for (const int (*p)[2] = sockopts; (*p)[0] != -1 && (*p)[1] != -1; p++)
		curtain_sockopt(slot, (*p)[0], (*p)[1], flags);
	return (0);
}


DEF_SIMPLE_KEY_FUNCS(priv, priv);
DEF_SIMPLE_ENT_FUNCS(priv, priv, int);

static struct curtain_type privs_type = {
	.req_type = CURTAINTYP_PRIV,
	.fallback = ability_fallback_helper,
	.key_cmp = priv_key_cmp,
	.ent_size = priv_ent_size,
	.ent_fill = priv_ent_fill,
	.mode = &level_mode_type,
};

int
curtain_priv(struct curtain_slot *slot, int priv, int flags)
{
	struct curtain_item *item;
	item = node_item_get(&privs_type, slot, KEY(.priv, priv), true);
	if (!item)
		return (-1);
	item_set_flags_level(item, flags);
	return (0);
}


static int
sysctl_key_cmp(const union curtain_key *key0, const union curtain_key *key1)
{
	size_t len0 = key0->sysctl.len, len1 = key1->sysctl.len;
	const int *mib0 = key0->sysctl.mib, *mib1 = key1->sysctl.mib;
	while (len0 && len1) {
		if (CMP(*mib0, *mib1) != 0)
			return (CMP(*mib0, *mib1));
		mib0++, mib1++;
		len0--, len1--;
	}
	return (CMP(len0, len1));
}

static size_t
sysctl_ent_size(const union curtain_key *key __unused)
{
	return ((key->sysctl.len + 1) * sizeof *key->sysctl.mib);
}

static void *
sysctl_ent_fill(void *dest,
    const union curtain_key *key, struct curtain_mode mode __unused)
{
	int *fill = dest;
	size_t len = key->sysctl.len;
	const int *mib = key->sysctl.mib;
	*fill++ = len;
	while (len--)
		*fill++ = *mib++;
	return (fill);
}

static struct curtain_type sysctls_type = {
	.req_type = CURTAINTYP_SYSCTL,
	.fallback = ability_fallback_helper,
	.key_cmp = sysctl_key_cmp,
	.ent_size = sysctl_ent_size,
	.ent_fill = sysctl_ent_fill,
	.mode = &level_mode_type,
};

int
curtain_sysctl(struct curtain_slot *slot, const char *sysctl, int flags)
{
	int mibv[CTL_MAXNAME], *mibp;
	size_t mibn;
	int r;
	struct curtain_node *prev_node, *node;

	mibn = nitems(mibv);
	r = sysctlnametomib(sysctl, mibv, &mibn);
	if (r < 0) {
		if (errno != ENOENT)
			warn("%s", sysctl);
		return (-1);
	}
	mibp = malloc(mibn * sizeof *mibp);
	memcpy(mibp, mibv, mibn * sizeof *mibp);

	prev_node = NULL;
	for (size_t mibc = 1; mibc <= mibn; mibc++) {
		node = node_get(&sysctls_type, KEY(.sysctl, { mibc, mibp }), true);
		if (!node)
			return (-1);
		if (mibc == mibn) {
			struct curtain_item *item;
			item = item_get(node, slot, true);
			if (!item)
				return (-1);
			item_set_flags_level(item, flags);
		}
		if (prev_node)
			node_reparent(node, prev_node);
		prev_node = node;
	}
	return (0);
}


DEF_SIMPLE_KEY_FUNCS(fibnum, fibnum);
DEF_SIMPLE_ENT_FUNCS(fibnum, fibnum, int);

static struct curtain_type fibnums_type = {
	.req_type = CURTAINTYP_FIBNUM,
	.fallback = ability_fallback_helper,
	.key_cmp = fibnum_key_cmp,
	.ent_size = fibnum_ent_size,
	.ent_fill = fibnum_ent_fill,
	.mode = &level_mode_type,
};

int
curtain_fibnum(struct curtain_slot *slot, int fibnum, int flags)
{
	struct curtain_item *item;
	item = node_item_get(&fibnums_type, slot, KEY(.fibnum, fibnum), true);
	if (!item)
		return (-1);
	item_set_flags_level(item, flags);
	return (0);
}


static bool
unveil_mode_is_null(struct curtain_mode m)
{ return (m.uperms == UPERM_NONE); }

static struct curtain_mode
unveil_mode_merge(struct curtain_mode m1, struct curtain_mode m2)
{ return ((struct curtain_mode){ .uperms = m1.uperms | m2.uperms }); }

static struct curtain_mode
unveil_mode_inherit(struct curtain_mode m)
{ return ((struct curtain_mode){ .uperms = uperms_inherit(m.uperms) }); }

static enum curtainreq_level
unveil_mode_level(struct curtain_mode m __unused)
{ return (CURTAINLVL_PASS); }

static const struct mode_type unveil_mode_type = {
	.null = { .uperms = UPERM_NONE },
	.is_null = unveil_mode_is_null,
	.inherit = unveil_mode_inherit,
	.merge = unveil_mode_merge,
	.level = unveil_mode_level,
};

static int
unveil_key_cmp(const union curtain_key *key0, const union curtain_key *key1)
{
	return (CMP(key0->unveil_idx, key1->unveil_idx));
}

static size_t
unveil_ent_size(const union curtain_key *key __unused)
{
	return (sizeof (struct curtainent_unveil));
}

static void *
unveil_ent_fill(void *dest,
    const union curtain_key *key, struct curtain_mode mode __unused)
{
	struct curtainent_unveil *fill = dest;
	*fill++ = (struct curtainent_unveil){
		.index = key->unveil_idx,
		.uperms = mode.uperms,
	};
	return (fill);
}

static struct curtain_type unveils_type = {
	.req_type = CURTAINTYP_UNVEIL,
	.key_cmp = unveil_key_cmp,
	.ent_size = unveil_ent_size,
	.ent_fill = unveil_ent_fill,
	.mode = &unveil_mode_type,
};

int
curtain_unveil(struct curtain_slot *slot,
    const char *path, unsigned flags, unveil_perms uperms)
{
	struct curtain_item *item;
	unveil_index tev[UNVEILREG_MAX_TE][2];
	struct unveilreg reg = {
		.atfd = AT_FDCWD,
		.atflags = flags & CURTAIN_UNVEIL_NOFOLLOW ? AT_SYMLINK_NOFOLLOW : 0,
		.path = path,
		.tec = UNVEILREG_MAX_TE,
		.tev = tev,
	};
	ssize_t ter;
	ter = unveilreg(UNVEILREG_THIS_VERSION | UNVEILREG_REGISTER | UNVEILREG_NONDIRBYNAME, &reg);
	if (ter < 0) {
		if (errno != ENOENT && errno != EACCES && errno != ENOSYS)
			warn("%s: %s", __FUNCTION__, path);
		return (-1);
	}
	item = NULL;
	for (ssize_t i = 0; i < ter; i++) {
		item = node_item_get(&unveils_type, slot,
		    KEY(.unveil_idx, tev[i][1]), true);
		if (tev[i][0] != tev[i][1]) {
			struct curtain_item *parent_item;
			parent_item = node_item_get(&unveils_type, slot,
			    KEY(.unveil_idx, tev[i][0]), true);
			node_reparent(item->node, parent_item->node);
		}
		item->mode.uperms |= UPERM_TRAVERSE;
		if (flags & CURTAIN_UNVEIL_INSPECT)
			item->mode.uperms |= UPERM_INSPECT;
	}
	if (item) {
		item_set_flags(item, flags);
		item->mode.uperms = uperms_expand(uperms);
	}
	return (0);
}

int
curtain_unveils_limit(struct curtain_slot *slot, unveil_perms uperms)
{
	struct curtain_item *item;
	uperms = uperms_expand(uperms | UPERM_TRAVERSE);
	for (item = slot->items; item; item = item->slot_next)
		if (item->node->type == &unveils_type)
			item->mode.uperms &= uperms;
	return (0);
}


static void
node_inherit(struct curtain_node *node,
    struct curtain_item *inherit_head, enum curtain_state min_state)
{
	struct curtain_item *nitem, *iitem, **ilink;
	struct curtain_type *type;
	type = node->type;

	/*
	 * Merge join the inherited and current node's slot item modes to
	 * handle inheritance between nodes of corresponding slots.  The
	 * current node's slot items are spliced into the inherited list
	 * replacing inherited items for the same slot (if any).  The list is
	 * restored to its previous state before returning.
	 */
	for (enum curtain_on on = 0; on < CURTAIN_ON_COUNT; on++) {
		node->combined_mode_on[on] = type->mode->null;
		node->has_mode_on[on] = false;
	}
	nitem = node->items; /* current node's items */
	iitem = *(ilink = &inherit_head); /* inherited items */
	while (nitem || iitem) {
		assert(!nitem || !nitem->node_next ||
		    (uintptr_t)nitem->slot < (uintptr_t)nitem->node_next->slot);
		assert(!iitem || !iitem->inherit_next ||
		    (uintptr_t)iitem->slot < (uintptr_t)iitem->inherit_next->slot);
		assert(*ilink == iitem);
		if (iitem && (!nitem || (uintptr_t)nitem->slot > (uintptr_t)iitem->slot)) {
			/*
			 * Inherited slot item with no corresponding current
			 * node item.  Permissions carry through nodes without
			 * items for a given slot.
			 */
			for (enum curtain_on on = 0; on < CURTAIN_ON_COUNT; on++)
				if (iitem->slot->state_on[on] >= min_state) {
					struct curtain_mode m;
					m = type->mode->merge(
					    iitem->mode, iitem->inherited_mode);
					node->combined_mode_on[on] =
					    type->mode->merge(
						node->combined_mode_on[on],
						type->mode->inherit(m));
					node->has_mode_on[on] = true;
				}
			iitem = *(ilink = &iitem->inherit_next);
		} else {
			bool match, carry;
			/*
			 * Current node item with or without a corresponding
			 * inherited slot item.  Splice the current node's item
			 * in the inherited list with updated permissions
			 * (replacing the inherited item, if any).
			 */
			match = iitem && iitem->slot == nitem->slot;
			if (match && !nitem->override &&
			    iitem->node->type->mode == nitem->node->type->mode) {
				struct curtain_mode m;
				m = type->mode->merge(
				    iitem->mode, iitem->inherited_mode);
				nitem->inherited_mode = type->mode->inherit(m);
			} else
				nitem->inherited_mode = type->mode->null;
			carry = false;
			for (enum curtain_on on = 0; on < CURTAIN_ON_COUNT; on++)
				if (nitem->slot->state_on[on] >= min_state) {
					struct curtain_mode m;
					m = type->mode->merge(
					    nitem->mode, nitem->inherited_mode);
					carry = carry ||
					    !type->mode->is_null(type->mode->inherit(m));
					node->combined_mode_on[on] =
					    type->mode->merge(
						node->combined_mode_on[on], m);
					node->has_mode_on[on] = true;
				}
			nitem->saved_link = ilink;
			nitem->saved = iitem;
			if (match)
				iitem = iitem->inherit_next;
			if (carry) {
				*ilink = nitem;
				ilink = &nitem->inherit_next;
			}
			*ilink = iitem;
			nitem = nitem->node_next;
		}
	}

	for (struct curtain_node *child = node->children; child; child = child->sibling) {
		assert(child->parent == node);
		node_inherit(child, inherit_head, min_state);
	}

	for (struct curtain_item *item = node->items; item; item = item->node_next)
		*item->saved_link = item->saved;
}

static void
root_nodes_inherit(enum curtain_state min_state)
{
	struct curtain_node *node;
	for (node = curtain_root_nodes; node; node = node->sibling) {
		assert(!node->parent);
		node_inherit(node, NULL, min_state);
	}
}


static size_t
type_expand(struct curtain_type *type,
    size_t counts[CURTAIN_ON_COUNT][CURTAIN_LEVEL_COUNT],
    size_t sizes[CURTAIN_ON_COUNT][CURTAIN_LEVEL_COUNT],
    void *fills[CURTAIN_ON_COUNT][CURTAIN_LEVEL_COUNT])
{
	struct curtain_node *node;
	size_t total_size;
	if (counts)
		for (enum curtain_on on = 0; on < CURTAIN_ON_COUNT; on++)
			for (enum curtainreq_level lvl = 0; lvl < CURTAIN_LEVEL_COUNT; lvl++)
				counts[on][lvl] = 0;
	if (sizes)
		for (enum curtain_on on = 0; on < CURTAIN_ON_COUNT; on++)
			for (enum curtainreq_level lvl = 0; lvl < CURTAIN_LEVEL_COUNT; lvl++)
				sizes[on][lvl] = 0;
	for (total_size = 0, node = type->nodes; node; node = node->type_next)
		for (enum curtain_on on = 0; on < CURTAIN_ON_COUNT; on++)
			if (node->has_mode_on[on]) {
				struct curtain_mode mode = node->combined_mode_on[on];
				enum curtainreq_level lvl = type->mode->level(mode);
				size_t size = type->ent_size(&node->key);
				total_size += size;
				if (counts)
					counts[on][lvl]++;
				if (sizes)
					sizes[on][lvl] += size;
				if (fills) {
					void *p;
					p = type->ent_fill(fills[on][lvl], &node->key, mode);
					assert((char *)p == (char *)fills[on][lvl] + size);
					fills[on][lvl] = p;
				}
			}
	return (total_size);
}


static struct curtain_type *const types[] = {
	&default_type,
	&abilities_type,
	&ioctls_type,
	&sockafs_type,
	&socklvls_type,
	&sockopts_type,
	&privs_type,
	&sysctls_type,
	&fibnums_type,
	&unveils_type,
};

static const int curtainreq_flags[CURTAIN_ON_COUNT] = {
	[CURTAIN_ON_SELF] = CURTAINREQ_ON_SELF,
	[CURTAIN_ON_EXEC] = CURTAINREQ_ON_EXEC,
};

static int
curtain_submit_1(int flags, bool neutral_on[CURTAIN_ON_COUNT], enum curtain_state min_state)
{
	struct curtainreq reqv[nitems(types) * CURTAIN_ON_COUNT * CURTAIN_LEVEL_COUNT], *reqp = reqv;
	size_t counts[nitems(types)][CURTAIN_ON_COUNT][CURTAIN_LEVEL_COUNT];
	size_t sizes[nitems(types)][CURTAIN_ON_COUNT][CURTAIN_LEVEL_COUNT], total_size;
	void *fills[nitems(types)][CURTAIN_ON_COUNT][CURTAIN_LEVEL_COUNT];

	/* Merge permissions across all nodes and slots. */
	root_nodes_inherit(min_state);

	total_size = 0;
	for (size_t i = 0; i < nitems(types); i++)
		/* Get size of each run of request entries. */
		total_size += type_expand(types[i], counts[i], sizes[i], NULL);

	/* Get buffer large enough for all entries. */
	char buffer_base[total_size], *buffer_fill = buffer_base;
	/* Figure out offset of each run in the buffer. */
	for (size_t i = 0; i < nitems(types); i++)
		for (enum curtain_on on = 0; on < CURTAIN_ON_COUNT; on++)
			for (enum curtainreq_level lvl = 0; lvl < CURTAIN_LEVEL_COUNT; lvl++) {
				fills[i][on][lvl] = buffer_fill;
				buffer_fill += sizes[i][on][lvl];
			}

	/* Fill each run in the buffer. */
	for (size_t i = 0; i < nitems(types); i++)
		type_expand(types[i], NULL, NULL, fills[i]);

	/* Build requests array. */
	for (enum curtain_on on = 0; on < CURTAIN_ON_COUNT; on++) {
		for (size_t i = 0; i < nitems(types); i++) {
			if (neutral_on[on]) {
				/*
				 * If all existing slots indicate that they are
				 * "neutral" on a certain "on" value (which is
				 * not the default), apply no restrictions.
				 */
				if (types[i] == &default_type)
					*reqp++ = (struct curtainreq){
						.type = CURTAINTYP_DEFAULT,
						.flags = curtainreq_flags[on],
						.level = CURTAINLVL_PASS,
					};
				continue;
			}
			for (enum curtainreq_level lvl = 0; lvl < CURTAIN_LEVEL_COUNT; lvl++) {
				if (counts[i][on][lvl] == 0)
					continue;
				*reqp++ = (struct curtainreq){
					.type = types[i]->req_type,
					.flags = curtainreq_flags[on],
					.level = lvl,
					.data = (char *)fills[i][on][lvl] - sizes[i][on][lvl],
					.size = sizes[i][on][lvl],
				};
			}
		}
	}

	/* Submit requests. */
	return (curtainctl(CURTAINCTL_THIS_VERSION | flags, reqp - reqv, reqv));
}

static int
curtain_submit(bool enforce)
{
	bool neutral_on[CURTAIN_ON_COUNT], has_reserve;
	int r, flags;

	has_reserve = false;
	for (enum curtain_on on = 0; on < CURTAIN_ON_COUNT; on++)
		neutral_on[on] = true;
	for (struct curtain_slot *slot = curtain_slots; slot; slot = slot->next) {
		bool has_neutral = false;
		for (enum curtain_on on = 0; on < CURTAIN_ON_COUNT; on++) {
			if (slot->state_on[on] > CURTAIN_NEUTRAL)
				neutral_on[on] = false;
			else if (neutral_on[on])
				has_neutral = true;
			if (slot->state_on[on] == CURTAIN_RESERVED)
				has_reserve = true;
		}
		if (!has_neutral && has_reserve)
			break;
	}

	flags = CURTAINCTL_ENGAGE;
	if (enforce) {
		int flags1 = flags | CURTAINCTL_ENFORCE;
		if (has_reserve) {
			r = curtain_submit_1(flags1, neutral_on, CURTAIN_RESERVED);
			if (r < 0 && errno != ENOSYS)
				err(EX_OSERR, "curtainctl");
		} else
			flags = flags1;
	}
	r = curtain_submit_1(flags, neutral_on, CURTAIN_ENABLED);
	if (r < 0 && errno != ENOSYS)
		err(EX_OSERR, "curtainctl");
	return (r);
}

int
curtain_engage(void) { return (curtain_submit(false)); }

int
curtain_enforce(void) { return (curtain_submit(true)); }
