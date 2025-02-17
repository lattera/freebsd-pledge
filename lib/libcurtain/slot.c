#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/tree.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <unistd.h>

#include <curtain.h>

#include <sys/curtainctl.h>
#include <security/mac_curtain/ability.h>
#include <security/mac_curtain/unveil.h>

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
	struct curtain_item *items;
	size_t items_count;
	enum curtain_state state_on[CURTAIN_ON_COUNT];
};

struct curtain_mode {
	enum curtainreq_level level : 8, inherit_level : 8;
	union {
		unveil_perms uperms;
	};
};

struct curtain_key_unveil {
	struct curtain_node *chain;
	struct curtain_key_unveil *parent;
	const char *name;
	char *symlink;
	int fd;
	bool opened;
	bool is_dir;
	bool resolving;
};

struct curtain_node {
	struct curtain_type *type;
	struct curtain_node *parent, *children, *sibling;
	struct curtain_node *type_next;
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
		struct curtain_key_unveil unveil;
	} key;
	/* scratch */
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
	struct curtain_mode (*convert)(const struct mode_type *, struct curtain_mode);
	enum curtainreq_level (*level)(struct curtain_mode);
};

struct curtain_type {
	enum curtainreq_type req_type;
	enum curtain_ability fallback_ability;
	size_t nodes_count, items_count;
	struct curtain_node *nodes;
	void (*cleanup)(struct curtain_node *);
	struct curtain_node *(*fallback)(struct curtain_node *);
	int (*key_cmp)(const union curtain_key *, const union curtain_key *);
	size_t (*ent_size)(const union curtain_key *);
	void *(*ent_fill)(void *, const union curtain_key *, struct curtain_mode);
	const struct mode_type *mode;
};


static struct curtain_slot *curtain_slots = NULL;
static struct curtain_node *curtain_root_nodes = NULL;

#define	DEBUG_ENV(name) (issetugid() != 0 ? NULL : getenv(name))

#define	FOREACH_CURTAIN_ON(on) for (enum curtain_on on = 0; on < CURTAIN_ON_COUNT; on++)

static struct curtain_slot *
curtain_slot_1(const enum curtain_state state_on[CURTAIN_ON_COUNT])
{
	struct curtain_slot *slot;
	slot = malloc(sizeof *slot);
	if (slot == NULL)
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
	FOREACH_CURTAIN_ON(on)
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

static void
node_remove(struct curtain_node *node)
{
	struct curtain_node **link, *child;
	/* unlink from parent node */
	for (link = node->parent ? &node->parent->children : &curtain_root_nodes;
	    *link != node; link = &(*link)->sibling);
	*link = node->sibling;
	/* merge children node into parent node */
	for (child = node->children; child; child = child->sibling) {
		child->sibling = *link;
		(*link)->children = child;
	}
	/* unlink from list of all nodes for this type */
	for (link = &node->type->nodes; *link != node; link = &(*link)->type_next);
	*link = node->type_next;
}

static void
node_drop(struct curtain_node *node)
{
	assert(node->items == NULL);
	if (node->type->cleanup)
		node->type->cleanup(node);
	node_remove(node);
	node->type->nodes_count--;
	free(node);
}

static void
node_trim(struct curtain_node *node)
{
	if (node->children == NULL && node->items == NULL) {
		struct curtain_node *parent;
		parent = node->parent;
		node_drop(node);
		if (parent != NULL)
			node_trim(parent);
	}
}

void
curtain_drop(struct curtain_slot *slot)
{
	struct curtain_slot **slot_link;
	struct curtain_item *item, **item_link;
	/* unlink slot from list of all slots */
	for (slot_link = &curtain_slots;
	    *slot_link != slot;
	    slot_link = &(*slot_link)->next);
	*slot_link = slot->next;
	/* unlink all slot items from their nodes */
	while ((item = slot->items)) {
		for (item_link = &item->node->items;
		    *item_link != item;
		    item_link = &(*item_link)->node_next);
		*item_link = item->node_next;
		item->node->items_count--;
		item->node->type->items_count--;
		slot->items = item->slot_next;
		node_trim(item->node);
		free(item);
	}
	free(slot);
}


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
	if (node != NULL) { /* move-to-front heuristic */
		assert(node->type == type);
		*link = node->type_next;
		node->type_next = type->nodes;
		type->nodes = node;
	} else if (create) {
		node = malloc(sizeof *node);
		if (node == NULL)
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
			/* keeping list ordered by slot for node_inherit() */
			if ((uintptr_t)slot <= (uintptr_t)item->slot) {
				if (slot != item->slot)
					item = NULL;
				break;
			}
	}
	if (item == NULL && create) {
		if (nlink == NULL)
			goto nslot;
		item = malloc(sizeof *item);
		if (item == NULL)
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
	if (node == NULL)
		return (NULL);
	return (item_get(node, slot, create));
}

static void
item_set_flags(struct curtain_item *item, int flags)
{
	item->override = (flags & CURTAIN_NOOVERRIDE) == 0;
	item->mode.level = item->mode.inherit_level = flags2level(flags);
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
{
	return (m.level >= CURTAINLVL_LEAST && m.inherit_level >= CURTAINLVL_LEAST);
}

static struct curtain_mode
level_mode_merge(struct curtain_mode m1, struct curtain_mode m2)
{
	return ((struct curtain_mode){
	    .level = MIN(m1.level, m2.level),
	    .inherit_level = MIN(m1.inherit_level, m2.inherit_level),
	});
}

static struct curtain_mode
level_mode_inherit(struct curtain_mode m)
{
	return ((struct curtain_mode){
	    .level = m.inherit_level,
	    .inherit_level = m.inherit_level,
	});
}

static struct curtain_mode
level_mode_convert(const struct mode_type *type __unused, struct curtain_mode m)
{
	return (m);
}

static enum curtainreq_level
level_mode_level(struct curtain_mode m)
{
	return (m.level);
}

#define	LEVEL_MODE_NULL_INIT .level = CURTAINLVL_LEAST, .inherit_level = CURTAINLVL_LEAST

static const struct mode_type level_mode_type = {
	.null = { LEVEL_MODE_NULL_INIT },
	.is_null = level_mode_is_null,
	.inherit = level_mode_inherit,
	.merge = level_mode_merge,
	.convert = level_mode_convert,
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

static struct curtain_node *
default_fallback_helper(struct curtain_node *node __unused)
{
	return (node_get(&default_type, (union curtain_key){ 0 }, true));
}

int
curtain_default(struct curtain_slot *slot, unsigned flags)
{
	struct curtain_item *item;
	item = node_item_get(&default_type, slot, (union curtain_key){ 0 }, true);
	if (item == NULL)
		return (-1);
	item_set_flags(item, flags);
	return (0);
}


DEF_SIMPLE_KEY_FUNCS(ability, ability);
DEF_SIMPLE_ENT_FUNCS(ability, ability, int);

static struct curtain_type abilities_type = {
	.req_type = CURTAINTYP_ABILITY,
	.fallback = default_fallback_helper,
	.key_cmp = ability_key_cmp,
	.ent_size = ability_ent_size,
	.ent_fill = ability_ent_fill,
	.mode = &level_mode_type,
};

static struct curtain_node *
ability_fallback_helper(struct curtain_node *node)
{
	enum curtain_ability ability = node->type->fallback_ability;
	assert(CURTAINABL_USER_VALID(ability));
	return (node_get(&abilities_type, KEY(.ability, ability), true));
}

int
curtain_ability(struct curtain_slot *slot, enum curtain_ability ability, int flags)
{
	struct curtain_item *item;
	assert(CURTAINABL_USER_VALID(ability));
	item = node_item_get(&abilities_type, slot, KEY(.ability, ability), true);
	if (item == NULL)
		return (-1);
	item_set_flags(item, flags);
	return (0);
}


DEF_SIMPLE_KEY_FUNCS(ioctl, ioctl);
DEF_SIMPLE_ENT_FUNCS(ioctl, ioctl, unsigned long);

static struct curtain_type ioctls_type = {
	.req_type = CURTAINTYP_IOCTL,
	.fallback_ability = CURTAINABL_ANY_IOCTL,
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
	if (item == NULL)
		return (-1);
	item_set_flags(item, flags);
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
	.fallback_ability = CURTAINABL_ANY_SOCKAF,
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
	if (item == NULL)
		return (-1);
	item_set_flags(item, flags);
	return (0);
}


DEF_SIMPLE_KEY_FUNCS(socklvl, socklvl);
DEF_SIMPLE_ENT_FUNCS(socklvl, socklvl, int);

static struct curtain_type socklvls_type = {
	.req_type = CURTAINTYP_SOCKLVL,
	.fallback_ability = CURTAINABL_ANY_SOCKOPT,
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
	if (item == NULL)
		return (-1);
	item_set_flags(item, flags);
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

static struct curtain_node *
sockopt_fallback_helper(struct curtain_node *node)
{
	return (node_get(&sockopts_type, node->key, true));
}

static int
curtain_sockopt_1(struct curtain_type *type, struct curtain_slot *slot,
    int level, int optname, int flags)
{
	struct curtain_item *item;
	item = node_item_get(type, slot, KEY(.sockopt, { level, optname }), true);
	if (item == NULL)
		return (-1);
	item_set_flags(item, flags);
	return (0);
}

int
curtain_sockopt(struct curtain_slot *slot, int level, int optname, int flags)
{
	return (curtain_sockopt_1(&sockopts_type, slot, level, optname, flags));
}

int
curtain_sockopts(struct curtain_slot *slot, const int (*sockopts)[2], int flags)
{
	for (const int (*p)[2] = sockopts; (*p)[0] != -1 && (*p)[1] != -1; p++)
		curtain_sockopt(slot, (*p)[0], (*p)[1], flags);
	return (0);
}

static struct curtain_type getsockopts_type = {
	.req_type = CURTAINTYP_GETSOCKOPT,
	.fallback = sockopt_fallback_helper,
	.key_cmp = sockopt_key_cmp,
	.ent_size = sockopt_ent_size,
	.ent_fill = sockopt_ent_fill,
	.mode = &level_mode_type,
};

int
curtain_getsockopt(struct curtain_slot *slot, int level, int optname, int flags)
{
	return (curtain_sockopt_1(&getsockopts_type, slot, level, optname, flags));
}

static struct curtain_type setsockopts_type = {
	.req_type = CURTAINTYP_SETSOCKOPT,
	.fallback = sockopt_fallback_helper,
	.key_cmp = sockopt_key_cmp,
	.ent_size = sockopt_ent_size,
	.ent_fill = sockopt_ent_fill,
	.mode = &level_mode_type,
};

int
curtain_setsockopt(struct curtain_slot *slot, int level, int optname, int flags)
{
	return (curtain_sockopt_1(&setsockopts_type, slot, level, optname, flags));
}


DEF_SIMPLE_KEY_FUNCS(priv, priv);
DEF_SIMPLE_ENT_FUNCS(priv, priv, int);

static struct curtain_type privs_type = {
	.req_type = CURTAINTYP_PRIV,
	.fallback_ability = CURTAINABL_ANY_PRIV,
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
	if (item == NULL)
		return (-1);
	item_set_flags(item, flags);
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
	.fallback_ability = CURTAINABL_ANY_SYSCTL,
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
	if (r < 0)
		return (-1);
	mibp = malloc(mibn * sizeof *mibp);
	memcpy(mibp, mibv, mibn * sizeof *mibp);

	prev_node = NULL;
	for (size_t mibc = 1; mibc <= mibn; mibc++) {
		node = node_get(&sysctls_type, KEY(.sysctl, { mibc, mibp }), true);
		if (node == NULL)
			return (-1);
		if (mibc == mibn) {
			struct curtain_item *item;
			item = item_get(node, slot, true);
			if (item == NULL)
				return (-1);
			item_set_flags(item, flags);
		}
		if (prev_node != NULL)
			node_reparent(node, prev_node);
		prev_node = node;
	}
	return (0);
}


DEF_SIMPLE_KEY_FUNCS(fibnum, fibnum);
DEF_SIMPLE_ENT_FUNCS(fibnum, fibnum, int);

static struct curtain_type fibnums_type = {
	.req_type = CURTAINTYP_FIBNUM,
	.fallback_ability = CURTAINABL_ANY_FIBNUM,
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
	if (item == NULL)
		return (-1);
	item_set_flags(item, flags);
	return (0);
}


static bool
unveil_mode_is_null(struct curtain_mode m)
{
	return (level_mode_is_null(m) && m.uperms == UPERM_NONE);
}

static struct curtain_mode
unveil_mode_merge(struct curtain_mode m1, struct curtain_mode m2)
{
	struct curtain_mode mm;
	mm = level_mode_merge(m1, m2);
	mm.uperms = m1.uperms | m2.uperms;
	return (mm);
}

static struct curtain_mode
unveil_mode_inherit(struct curtain_mode m)
{
	struct curtain_mode mm;
	mm = level_mode_inherit(m);
	mm.uperms = uperms_inherit(m.uperms);
	return (mm);
}

static struct curtain_mode
unveil_mode_convert(const struct mode_type *type, struct curtain_mode m)
{
	struct curtain_mode mm;
	mm = level_mode_convert(type, m);
	if (type == &level_mode_type)
		mm.uperms = mm.level == CURTAINLVL_PASS ? UPERM_ALL : UPERM_NONE;
	return (mm);
}

static const struct mode_type unveil_mode_type = {
	.null = { LEVEL_MODE_NULL_INIT, .uperms = UPERM_NONE },
	.is_null = unveil_mode_is_null,
	.inherit = unveil_mode_inherit,
	.convert = unveil_mode_convert,
	.merge = unveil_mode_merge,
	.level = level_mode_level,
};

static int
unveil_key_cmp(const union curtain_key *key0, const union curtain_key *key1)
{
	return ((uintptr_t)key0->unveil.parent < (uintptr_t)key1->unveil.parent ? -1 :
	        (uintptr_t)key0->unveil.parent > (uintptr_t)key1->unveil.parent ?  1 :
	        strcmp(key0->unveil.name, key1->unveil.name));
}

static size_t
unveil_ent_size(const union curtain_key *key)
{
	size_t n = 0;
	n += sizeof (struct curtainent_unveil);
	n += __align_up((key->unveil.is_dir ? 0 : strlen(key->unveil.name)) + 1,
	    __alignof(struct curtainent_unveil));
	return (n);
}

static void *
unveil_ent_fill(void *dest,
    const union curtain_key *key, struct curtain_mode mode)
{
	struct curtainent_unveil *fill = dest;
	size_t size;
	if ((size = unveil_ent_size(key)) == 0)
		return (fill);
	*fill = (struct curtainent_unveil){
		.dir_fd = key->unveil.is_dir ? key->unveil.fd : key->unveil.parent->fd,
		.uperms = mode.uperms,
	};
	strcpy(fill->name, key->unveil.is_dir ? "" : key->unveil.name);
	return ((char *)fill + size);
}

static struct curtain_node *unveil_root_node;

static void
unveil_node_cleanup(struct curtain_node *node)
{
	if (node->key.unveil.opened && node->key.unveil.fd >= 0)
		close(node->key.unveil.fd);
	if (node == unveil_root_node)
		unveil_root_node = NULL;
}

static struct curtain_type unveils_type = {
	.req_type = CURTAINTYP_UNVEIL,
	.cleanup = unveil_node_cleanup,
	.fallback = default_fallback_helper,
	.key_cmp = unveil_key_cmp,
	.ent_size = unveil_ent_size,
	.ent_fill = unveil_ent_fill,
	.mode = &unveil_mode_type,
};


int
curtain_parse_unveil_perms(unveil_perms *uperms_ret, const char *s)
{
	unveil_perms uperms = UPERM_NONE;
	int r = 0;
	while (*s)
		switch (*s++) {
		case 'e': uperms |= UPERM_EXPOSE; break;
		case 'l': uperms |= UPERM_LIST; break;
		case 'b': uperms |= UPERM_BROWSE; break;
		case 'r': uperms |= UPERM_READ; break;
		case 'p': uperms |= UPERM_APPEND; break;
		case 'm': uperms |= UPERM_WRITE; break;
		case 'w': uperms |= UPERM_WRITE | UPERM_SETATTR |
		                    UPERM_CREATE | UPERM_DELETE; break;
		case 'a': uperms |= UPERM_SETATTR; break;
		case 'c': uperms |= UPERM_CREATE; break;
		case 'd': uperms |= UPERM_DELETE; break;
		case 's': uperms |= UPERM_SHELL; break;
		case 'x': uperms |= UPERM_EXECUTE; break;
		case 'i': uperms |= UPERM_INSPECT; break;
		case 't': uperms |= UPERM_TMPDIR; break;
		case 'u': uperms |= UPERM_UNIX; break;
		case 'v': uperms |= UPERM_CONNECT; break;
		case 'D': uperms |= UPERM_DEVFS; break;
		default: r = -1; break;
		}
	*uperms_ret = uperms_expand(uperms);
	return (r);
}


static struct curtain_node *
unveil_node_get(struct curtain_node *parent, const char *name)
{
	struct curtain_type *type = &unveils_type;
	struct curtain_node *node, **link;
	for (link = &parent->children; *link; link = &(*link)->sibling)
		if (strcmp((*link)->key.unveil.name, name) == 0)
			break;
	if ((node = *link) == NULL) {
		node = malloc(sizeof *node + strlen(name) + 1);
		if (node == NULL)
			err(EX_TEMPFAIL, "malloc");
		*node = (struct curtain_node){
			.type = type,
			.type_next = type->nodes,
			.parent = parent,
			.key = KEY(.unveil, {
				.parent = &parent->key.unveil,
				.fd = -1,
				.name = (char *)(node + 1),
			}),
		};
		strcpy((char *)(node + 1), name);
		*link = node;
		type->nodes = node;
		type->nodes_count++;
	}
	return (node);
}

static void
unveil_node_chain(struct curtain_node **head, struct curtain_node *node)
{
	for (struct curtain_node **link = head; *link; link = &(*link)->key.unveil.chain)
		if (*link == node) {
			*link = (*link)->key.unveil.chain;
			break;
		}
	node->key.unveil.chain = *head;
	*head = node;
}

static int
unveil_node_open(struct curtain_node *node)
{
	struct stat st;
	int r, fd;
	char *symlink;
	const char *path;
	if (node->parent && node->parent->type == node->type) {
		if (!node->parent->key.unveil.opened) {
			r = unveil_node_open(node->parent);
			if (r < 0)
				return (r);
		}
		fd = node->parent->key.unveil.fd;
		path = node->key.unveil.name;
	} else {
		fd = AT_FDCWD;
		path = "/";
	}
	r = openat(fd, path, O_PATH | O_NOFOLLOW | O_CLOEXEC);
	if (r < 0)
		return (-1);
	fd = r;
	r = fstat(fd, &st);
	if (r < 0)
		goto err;
	if (node->key.unveil.fd >= 0)
		close(node->key.unveil.fd);
	node->key.unveil.opened = true;
	node->key.unveil.is_dir = false;
	node->key.unveil.symlink = NULL;
	node->key.unveil.fd = -1;
	switch (st.st_mode & S_IFMT) {
	case S_IFDIR:
		node->key.unveil.is_dir = true;
		node->key.unveil.fd = fd;
		break;
	case S_IFLNK:
		symlink = malloc(st.st_size + 1);
		if (symlink == NULL)
			goto err;
		r = readlinkat(fd, "", symlink, st.st_size);
		if (r < 0)
			goto err;
		assert((off_t)r <= st.st_size);
		symlink[r] = '\0';
		node->key.unveil.symlink = symlink;
		/* FALLTHROUGH */
	default:
		close(fd);
		break;
	}
	return (0);
err:
	close(fd);
	return (-1);
}

static int
unveil_path_1(struct curtain_node **trail, bool nofollow, bool last,
    const char *path, struct curtain_node **path_node)
{
	struct curtain_node *parent_node;
	parent_node = *path_node;
	unveil_node_chain(trail, parent_node);

	while (*path) {
		char name[NAME_MAX + 1], *symlink;
		const char *next;
		struct curtain_node *node;
		int r;

		if (!parent_node->key.unveil.is_dir) {
			errno = ENOTDIR;
			return (-1);
		}

		while (*path == '/')
			path++;
		next = path;
		while (*next && *next != '/')
			next++;
		if (path == next)
			continue;

		if (path[0] == '.') {
			if (next - path == 1) {
				path = next;
				continue;
			} else if (next - path == 2 && path[1] == '.') {
				if (parent_node->parent)
					parent_node = parent_node->parent;
				path = next;
				/*
				 * Move parent to the head of the chain so that
				 * curtain_path_multi() gives it the final
				 * uperms if it is the last path component.
				 */
				unveil_node_chain(trail, parent_node);
				continue;
			}
		}

		if ((size_t)(next - path) >= sizeof name) {
			errno = ENAMETOOLONG;
			return (-1);
		}
		memcpy(name, path, next - path);
		name[next - path] = '\0';

		node = unveil_node_get(parent_node, name);
		if (node == NULL)
			return (-1);
		unveil_node_chain(trail, node);

		if (!node->key.unveil.opened) {
			r = unveil_node_open(node);
			if (r < 0) {
				if (errno == ENOENT && !*next && last)
					break;
				node_trim(node);
				return (r);
			}
		}

		if ((symlink = node->key.unveil.symlink) && (*next || !nofollow)) {
			struct curtain_node *target_node;
			if (node->key.unveil.resolving) {
				errno = ELOOP;
				node_trim(node);
				return (-1);
			}
			node->key.unveil.resolving = true;
			target_node = symlink[0] == '/' ? unveil_root_node : parent_node;
			r = unveil_path_1(trail, false, !*next, symlink, &target_node);
			if (r < 0) {
				node_trim(node);
				return (r);
			}
			node->key.unveil.resolving = false;
			node = target_node;
		}

		parent_node = node;
		path = next;
	}

	*path_node = parent_node;
	return (0);
}

static unveil_perms
expand_interm_uperms(int flags, unveil_perms uperms)
{
	uperms |= UPERM_TRAVERSE;
	if ((flags & CURTAIN_PATH_NOSTAT) == 0)
		uperms |= UPERM_INSPECT;
	if ((flags & CURTAIN_PATH_NOLIST) == 0)
		uperms |= UPERM_LIST;
	return (uperms_expand(uperms));
}

static unveil_perms
expand_final_uperms(int flags, unveil_perms uperms)
{
	if ((flags & CURTAIN_PATH_NOSTAT) == 0 && uperms_overlaps(uperms, ~UPERM_INSPECT))
		uperms |= UPERM_INSPECT;
	return (uperms_expand(uperms));
}

static const unveil_perms curtain_preserve_uperms = UPERM_TRAVERSE;

int
curtain_path_multi(struct curtain_slot **slots, size_t nslots,
    const char *path, unsigned flags,
    unveil_perms *interm_upermsv, unveil_perms *final_upermsv)
{
	struct curtain_node *trail;
	struct curtain_node *node;
	int r;

	if (!path[0])
		return (0);

	if (unveil_root_node == NULL)
		unveil_root_node = node_get(&unveils_type,
		    KEY(.unveil, { .name = "", .fd = -1, .is_dir = true }),
		    true);
	node = unveil_root_node;
	trail = NULL;

	if (path[0] != '/') {
		char *p;
		p = getcwd(NULL, 0);
		if (p == NULL)
			return (-1);
		r = unveil_path_1(&trail, false, false, p, &node);
		free(p);
		if (r < 0)
			return (r);
	}

	r = unveil_path_1(&trail, flags & CURTAIN_PATH_NOFOLLOW, true, path, &node);
	if (r < 0)
		return (r);

	if (trail != NULL) {
		for (size_t i = 0; i < nslots; i++) {
			struct curtain_item *item;
			item = item_get(trail, slots[i], true);
			if (item == NULL)
				return (-1);
			item_set_flags(item, flags);
			item->mode.uperms &= curtain_preserve_uperms;
			item->mode.uperms |= expand_final_uperms(flags, final_upermsv[i]);
		}
		while ((trail = trail->key.unveil.chain)) {
			for (size_t i = 0; i < nslots; i++) {
				struct curtain_item *item;
				item = item_get(trail, slots[i], true);
				if (item == NULL)
					return (-1);
				item->mode.level = flags2level(flags); /* NOTE: Not inherited. */
				item->mode.uperms |= expand_interm_uperms(flags, interm_upermsv[i]);
			}
		}
	}

	return (r);
}

int
curtain_path(struct curtain_slot *slot,
    const char *path, unsigned flags, unveil_perms final_uperms)
{
	unveil_perms interm_uperms = UPERM_NONE;
	return (curtain_path_multi(&slot, 1, path, flags, &interm_uperms, &final_uperms));
}

int
curtain_path_str(struct curtain_slot *slot,
    const char *path, unsigned flags, const char *perms)
{
	unveil_perms uperms;
	int r;
	r = curtain_parse_unveil_perms(&uperms, perms);
	if (r < 0) {
		warnx("%s: invalid unveil permissions: %s", __func__, perms);
		errno = EINVAL;
		return (r);
	}
	return (curtain_path(slot, path, flags, uperms));
}

int
curtain_unveils_limit(struct curtain_slot *slot, unveil_perms uperms)
{
	struct curtain_item *item;
	uperms = uperms_expand(uperms | curtain_preserve_uperms);
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
	struct curtain_type *ntype, *itype;
	/*
	 * Merge join the inherited and current node's slot item modes to
	 * handle inheritance between nodes of corresponding slots.  The
	 * current node's slot items are spliced into the inherited list
	 * replacing inherited items for the same slot (if any).  The list is
	 * restored to its previous state before returning.
	 */
	ntype = node->type;
	FOREACH_CURTAIN_ON(on)
		node->combined_mode_on[on] = ntype->mode->null;
	nitem = node->items; /* current node's items */
	iitem = *(ilink = &inherit_head); /* inherited items */
	while (nitem != NULL || iitem != NULL) {
		assert(nitem == NULL || nitem->node_next == NULL ||
		    (uintptr_t)nitem->slot < (uintptr_t)nitem->node_next->slot);
		assert(iitem == NULL || iitem->inherit_next == NULL ||
		    (uintptr_t)iitem->slot < (uintptr_t)iitem->inherit_next->slot);
		assert(*ilink == iitem);
		if (iitem != NULL && (nitem == NULL ||
		    (uintptr_t)nitem->slot > (uintptr_t)iitem->slot)) {
			/*
			 * Inherited slot item with no corresponding current
			 * node item.  Permissions carry through nodes without
			 * items for a given slot.
			 */
			itype = iitem->node->type;
			FOREACH_CURTAIN_ON(on) {
				struct curtain_mode m;
				if (iitem->slot->state_on[on] < min_state)
					continue;
				m = itype->mode->merge(iitem->mode, iitem->inherited_mode);
				if (itype->mode != ntype->mode)
					m = ntype->mode->convert(itype->mode, m);
				node->combined_mode_on[on] = ntype->mode->merge(
				    node->combined_mode_on[on], ntype->mode->inherit(m));
			}
			iitem = *(ilink = &iitem->inherit_next);
		} else {
			/*
			 * Current node item with or without a corresponding
			 * inherited slot item.  Splice the current node's item
			 * in the inherited list with updated permissions
			 * (replacing the inherited item, if any).
			 */
			bool match, carry;
			assert(nitem->node == node);
			match = iitem != NULL && iitem->slot == nitem->slot;
			if (match && !nitem->override) {
				struct curtain_mode m;
				itype = iitem->node->type;
				m = itype->mode->merge(iitem->mode, iitem->inherited_mode);
				if (itype->mode != ntype->mode)
					m = ntype->mode->convert(itype->mode, m);
				nitem->inherited_mode = ntype->mode->inherit(m);
			} else
				nitem->inherited_mode = ntype->mode->null;
			carry = false;
			FOREACH_CURTAIN_ON(on) {
				struct curtain_mode m;
				if (nitem->slot->state_on[on] < min_state)
					continue;
				m = ntype->mode->merge(nitem->mode, nitem->inherited_mode);
				carry = carry || !ntype->mode->is_null(ntype->mode->inherit(m));
				node->combined_mode_on[on] = ntype->mode->merge(
				    node->combined_mode_on[on], m);
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
		assert(node->parent == NULL);
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
	if (counts != NULL)
		FOREACH_CURTAIN_ON(on)
			for (enum curtainreq_level lvl = 0; lvl < CURTAIN_LEVEL_COUNT; lvl++)
				counts[on][lvl] = 0;
	if (sizes != NULL)
		FOREACH_CURTAIN_ON(on)
			for (enum curtainreq_level lvl = 0; lvl < CURTAIN_LEVEL_COUNT; lvl++)
				sizes[on][lvl] = 0;
	for (total_size = 0, node = type->nodes; node; node = node->type_next)
		FOREACH_CURTAIN_ON(on)
			if (!node->type->mode->is_null(node->combined_mode_on[on])) {
				struct curtain_mode mode = node->combined_mode_on[on];
				enum curtainreq_level lvl = type->mode->level(mode);
				size_t size = type->ent_size(&node->key);
				total_size += size;
				if (counts != NULL)
					counts[on][lvl]++;
				if (sizes != NULL)
					sizes[on][lvl] += size;
				if (fills != NULL) {
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
	&getsockopts_type,
	&setsockopts_type,
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
		FOREACH_CURTAIN_ON(on)
			for (enum curtainreq_level lvl = 0; lvl < CURTAIN_LEVEL_COUNT; lvl++) {
				fills[i][on][lvl] = buffer_fill;
				buffer_fill += sizes[i][on][lvl];
			}

	/* Fill each run in the buffer. */
	for (size_t i = 0; i < nitems(types); i++)
		type_expand(types[i], NULL, NULL, fills[i]);

	/* Build requests array. */
	FOREACH_CURTAIN_ON(on) {
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
curtain_submit(bool soft)
{
	bool neutral_on[CURTAIN_ON_COUNT], has_reserve;
	int r, flags;

	has_reserve = false;
	FOREACH_CURTAIN_ON(on)
		neutral_on[on] = curtain_slots != NULL;
	for (struct curtain_slot *slot = curtain_slots; slot; slot = slot->next) {
		bool has_neutral = false;
		FOREACH_CURTAIN_ON(on) {
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

	flags = DEBUG_ENV("LIBCURTAIN_DEBUG_DUMMY") ? 0 : CURTAINCTL_REPLACE;
	if (soft) {
		flags |= CURTAINCTL_SOFT;
	} else {
		if (has_reserve) {
			r = curtain_submit_1(flags, neutral_on, CURTAIN_RESERVED);
			if (r < 0 && errno != ENOSYS)
				err(EX_OSERR, "curtainctl");
			flags |= CURTAINCTL_SOFT;
		}
	}
	r = curtain_submit_1(flags, neutral_on, CURTAIN_ENABLED);
	if (r < 0 && errno != ENOSYS)
		err(EX_OSERR, "curtainctl");
	return (r);
}

int
curtain_apply_soft(void) { return (curtain_submit(true)); }

int
curtain_apply(void) { return (curtain_submit(false)); }
