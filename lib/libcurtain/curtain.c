#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <err.h>
#include <sysexits.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/param.h>
#include <sys/curtain.h>
#include <sys/unveil.h>

#include <curtain.h>

struct curtain_slot {
	struct curtain_slot *next;
	struct default_mode *default_mode;
	struct unveil_mode *unveil_modes;
	enum curtain_state state_on[CURTAIN_ON_COUNT];
};

struct default_mode {
	struct curtain_slot *slot;
	struct default_mode *next;
	enum curtainreq_level level;
};

struct simple_mode {
	struct curtain_slot *slot;
	struct simple_node *node;
	struct simple_mode *node_next;
	enum curtainreq_level level;
};

struct simple_node {
	struct simple_node *next;
	struct simple_mode *modes;
	union simple_key {
		enum curtain_ability ability;
		unsigned long ioctl;
		int sockaf;
		int socklvl;
		int sockopt[2];
		int priv;
		const int *mib;
	} key;
};

struct unveil_mode {
	struct curtain_slot *slot;
	struct unveil_node *node;
	struct unveil_mode *node_next, *slot_next;
	struct unveil_mode *inherit_next, **inherit_saved_link, *inherit_saved;
	bool inherit, inspect;
	unveil_perms uperms;
	unveil_perms inherited_uperms;
};

struct unveil_node {
	struct unveil_node *parent, *children, *sibling;
	struct unveil_mode *modes;
	unsigned unveil_idx;
	bool initialized;
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


static struct default_mode *default_modes = NULL;

static void
reinit_defaults(void)
{
	default_modes = NULL;
}

int
curtain_default(struct curtain_slot *slot, unsigned flags)
{
	struct default_mode *mode;
	if (!(mode = slot->default_mode)) {
		mode = malloc(sizeof *mode);
		if (!mode)
			err(EX_TEMPFAIL, "malloc");
		*mode = (struct default_mode){
			.slot = slot,
			.next = default_modes,
			.level = -1,
		};
		default_modes = slot->default_mode = mode;
	}
	mode->level = flags2level(flags);
	return (0);
}

static void
fill_defaults(enum curtainreq_level level_on[CURTAIN_ON_COUNT], enum curtain_state min_state)
{
	struct default_mode *mode;
	for (enum curtain_on on = 0; on < CURTAIN_ON_COUNT; on++) {
		level_on[on] = CURTAINLVL_KILL;
		for (mode = default_modes; mode; mode = mode->next)
			if (mode->slot->state_on[on] >= min_state)
				level_on[on] = MIN(mode->level, level_on[on]);
	}
}


struct simple_type {
	enum curtainreq_type type;
	size_t ent_size;
	size_t count;
	struct simple_node *list;
	int (*cmp)(const union simple_key *, const union simple_key *);
	void (*fill)(void **, struct simple_node *);
};

static void
reinit_simples(struct simple_type *type)
{
	type->count = 0;
	type->list = NULL;
}

static struct simple_node *
get_simple_node(struct simple_type *type, const union simple_key *key)
{
	struct simple_node *node, **link;
	for (link = &type->list; (node = *link); link = &node->next)
		if (type->cmp(&node->key, key) == 0)
			break;
	if (!node) {
		node = malloc(sizeof *node);
		if (!node)
			err(EX_TEMPFAIL, "malloc");
		*node = (struct simple_node){ .next = *link, .key = *key };
		*link = node;
	} else { /* move-to-front heuristic */
		*link = node->next;
		node->next = type->list;
		type->list = node;
	}
	return (node);
}

static struct simple_mode *
get_simple_mode(
    struct simple_type *type,
    struct simple_node *node,
    struct curtain_slot *slot)
{
	struct simple_mode *mode, **link;
	for (link = &node->modes; (mode = *link); link = &mode->node_next)
		if (mode->slot == slot)
			break;
	if (!mode) {
		mode = malloc(sizeof *mode);
		if (!mode)
			err(EX_TEMPFAIL, "malloc");
		*mode = (struct simple_mode){
			.slot = slot,
			.node = node,
			.node_next = *link,
		};
		*link = mode;
		type->count++;
	}
	return (mode);
}

static struct simple_mode *
get_simple(struct simple_type *type, struct curtain_slot *slot,
    union simple_key key)
{
	struct simple_node *node;
	node = get_simple_node(type, &key);
	if (!node)
		return (NULL);
	return (get_simple_mode(type, node, slot));
}

static void
fill_simple(struct simple_type *type,
    void *dest[CURTAIN_ON_COUNT][CURTAIN_LEVEL_COUNT],
    enum curtain_state min_state)
{
	struct simple_node *node;
	struct simple_mode *mode;
	for (node = type->list; node; node = node->next)
		for (enum curtain_on on = 0; on < CURTAIN_ON_COUNT; on++) {
			enum curtainreq_level lvl;
			bool any = false;
			for (mode = node->modes; mode; mode = mode->node_next)
				if (mode->slot->state_on[on] >= min_state) {
					lvl = any ? MIN(lvl, mode->level) : mode->level;
					any = true;
				}
			if (any)
				type->fill(&dest[on][lvl], node);
		}
}


static int
cmp_ability(const union simple_key *key0, const union simple_key *key1)
{
	return (key0->ability - key1->ability);
}

static void
fill_ability(void **dest, struct simple_node *node)
{
	unsigned *fill = *dest;
	*fill++ = node->key.ability;
	*dest = fill;
}

static struct simple_type abilities_type = {
	.type = CURTAINTYP_ABILITY,
	.ent_size = sizeof (int),
	.cmp = cmp_ability,
	.fill = fill_ability,
};

int
curtain_ability(struct curtain_slot *slot, enum curtain_ability ability, int flags)
{
	struct simple_mode *mode;
	mode = get_simple(&abilities_type, slot,
	    (union simple_key){ .ability = ability });
	if (!mode)
		return (-1);
	mode->level = flags2level(flags);
	return (0);
}


static int
cmp_ioctl(const union simple_key *key0, const union simple_key *key1)
{
	return (key0->ioctl - key1->ioctl);
}

static void
fill_ioctl(void **dest, struct simple_node *node)
{
	unsigned long *fill = *dest;
	*fill++ = node->key.ioctl;
	*dest = fill;
}

static struct simple_type ioctls_type = {
	.type = CURTAINTYP_IOCTL,
	.ent_size = sizeof (unsigned long),
	.cmp = cmp_ioctl,
	.fill = fill_ioctl,
};

int
curtain_ioctl(struct curtain_slot *slot, unsigned long ioctl, int flags)
{
	struct simple_mode *mode;
	mode = get_simple(&ioctls_type, slot,
	    (union simple_key){ .ioctl = ioctl });
	if (!mode)
		return (-1);
	mode->level = flags2level(flags);
	return (0);
}

int
curtain_ioctls(struct curtain_slot *slot, const unsigned long *ioctls, int flags)
{
	for (const unsigned long *p = ioctls; *p != (unsigned long)-1; p++)
		curtain_ioctl(slot, *p, flags);
	return (0);
}


static int
cmp_sockaf(const union simple_key *key0, const union simple_key *key1)
{
	return (key0->sockaf - key1->sockaf);
}

static void
fill_sockaf(void **dest, struct simple_node *node)
{
	int *fill = *dest;
	*fill++ = node->key.sockaf;
	*dest = fill;
}

static struct simple_type sockafs_type = {
	.type = CURTAINTYP_SOCKAF,
	.ent_size = sizeof (int),
	.cmp = cmp_sockaf,
	.fill = fill_sockaf,
};

int
curtain_sockaf(struct curtain_slot *slot, int sockaf, int flags)
{
	struct simple_mode *mode;
	mode = get_simple(&sockafs_type, slot,
	    (union simple_key){ .sockaf = sockaf });
	if (!mode)
		return (-1);
	mode->level = flags2level(flags);
	return (0);
}


static int
cmp_socklvl(const union simple_key *key0, const union simple_key *key1)
{
	return (key0->socklvl - key1->socklvl);
}

static void
fill_socklvl(void **dest, struct simple_node *node)
{
	int *fill = *dest;
	*fill++ = node->key.socklvl;
	*dest = fill;
}

static struct simple_type socklvls_type = {
	.type = CURTAINTYP_SOCKLVL,
	.ent_size = sizeof (int),
	.cmp = cmp_socklvl,
	.fill = fill_socklvl,
};

int
curtain_socklvl(struct curtain_slot *slot, int level, int flags)
{
	struct simple_mode *mode;
	mode = get_simple(&socklvls_type, slot,
	    (union simple_key){ .socklvl = level });
	if (!mode)
		return (-1);
	mode->level = flags2level(flags);
	return (0);
}


static int
cmp_sockopt(const union simple_key *key0, const union simple_key *key1)
{
	int d;
	return ((d = key0->sockopt[0] - key1->sockopt[0]) != 0 ? d :
	             key0->sockopt[1] - key1->sockopt[1]);
}

static void
fill_sockopt(void **dest, struct simple_node *node)
{
	int (*fill)[2] = *dest;
	(*fill)[0] = node->key.sockopt[0];
	(*fill)[1] = node->key.sockopt[1];
	*dest = ++fill;
}

static struct simple_type sockopts_type = {
	.type = CURTAINTYP_SOCKOPT,
	.ent_size = sizeof (int [2]),
	.cmp = cmp_sockopt,
	.fill = fill_sockopt,
};

int
curtain_sockopt(struct curtain_slot *slot, int level, int optname, int flags)
{
	struct simple_mode *mode;
	mode = get_simple(&sockopts_type, slot,
	    (union simple_key){ .sockopt = { level, optname } });
	if (!mode)
		return (-1);
	mode->level = flags2level(flags);
	return (0);
}

int
curtain_sockopts(struct curtain_slot *slot, const int (*sockopts)[2], int flags)
{
	for (const int (*p)[2] = sockopts; (*p)[0] != -1 && (*p)[1] != -1; p++)
		curtain_sockopt(slot, (*p)[0], (*p)[1], flags);
	return (0);
}


static int
cmp_priv(const union simple_key *key0, const union simple_key *key1)
{
	return (key0->priv - key1->priv);
}

static void
fill_priv(void **dest, struct simple_node *node)
{
	int *fill = *dest;
	*fill++ = node->key.priv;
	*dest = fill;
}

static struct simple_type privs_type = {
	.type = CURTAINTYP_PRIV,
	.ent_size = sizeof (int),
	.cmp = cmp_priv,
	.fill = fill_priv,
};

int
curtain_priv(struct curtain_slot *slot, int priv, int flags)
{
	struct simple_mode *mode;
	mode = get_simple(&privs_type, slot, (union simple_key){ .priv = priv });
	if (!mode)
		return (-1);
	mode->level = flags2level(flags);
	return (0);
}


static int
cmp_sysctl(const union simple_key *key0, const union simple_key *key1)
{
	const int *mib0 = key0->mib, *mib1 = key1->mib;
	while (*mib0 >= 0 || *mib1 >= 0) {
		int cmp = *mib0++ - *mib1++;
		if (cmp != 0)
			return (cmp);
	}
	return (0);
}

static void
fill_sysctl(void **dest, struct simple_node *node)
{
	int *fill = *dest;
	const int *mib = node->key.mib;
	do {
		*fill++ = *mib;
	} while (*mib++ >= 0);
	*dest = fill;
}

static struct simple_type sysctls_type = {
	.type = CURTAINTYP_SYSCTL,
	.ent_size = (CTL_MAXNAME + 1) * sizeof (int), /* XXX */
	.cmp = cmp_sysctl,
	.fill = fill_sysctl,
};

int
curtain_sysctl(struct curtain_slot *slot, const char *sysctl, int flags)
{
	int mibv[64], *mibp;
	size_t mibn;
	int r;
	struct simple_mode *mode;
	mibn = nitems(mibv);
	r = sysctlnametomib(sysctl, mibv, &mibn);
	if (r < 0) {
		if (errno != ENOENT)
			warn("%s", sysctl);
		return (-1);
	}
	mibp = malloc((mibn + 1) * sizeof *mibp);
	memcpy(mibp, mibv, mibn * sizeof *mibp);
	mibp[mibn] = -1;
	mode = get_simple(&sysctls_type, slot, (union simple_key){ .mib = mibp });
	if (!mode)
		return (-1);
	mode->level = flags2level(flags);
	return (0);
}


static size_t unveils_count = 0;
static struct unveil_node **unveils_table = NULL;
static size_t unveils_table_size = 0;

static void
reinit_unveils(void)
{
	unveils_count = 0;
	unveils_table = NULL;
	unveils_table_size = 0;
}

static struct unveil_node **
get_unveil_index_link(unsigned idx)
{
	if (idx >= unveils_table_size) {
		void *ptr;
		ptr = realloc(unveils_table, (idx + 1) * sizeof *unveils_table);
		if (!ptr)
			return (NULL);
		unveils_table = ptr;
		while (idx >= unveils_table_size)
			unveils_table[unveils_table_size++] = NULL;
	}
	return (&unveils_table[idx]);
}

static struct unveil_node *
get_unveil_index(unsigned idx)
{
	struct unveil_node **link;
	link = get_unveil_index_link(idx);
	if (!link)
		return (NULL);
	if (*link) {
		assert((**link).unveil_idx == idx);
	} else {
		*link = malloc(sizeof **link);
		if (!*link)
			return (NULL);
		**link = (struct unveil_node){ .unveil_idx = idx };
		unveils_count++;
	}
	return (*link);
}

static struct unveil_node *
get_unveil_index_pair(unsigned parent_idx, unsigned child_idx)
{
	struct unveil_node *parent, *child;
	if (parent_idx != child_idx) {
		parent = get_unveil_index(parent_idx);
		if (!parent)
			return (NULL);
	} else
		parent = NULL;
	child = get_unveil_index(child_idx);
	if (!child)
		return (NULL);
	if (!child->initialized) {
		/* XXX not reparenting nodes yet */
		if ((child->parent = parent)) {
			child->sibling = parent->children;
			parent->children = child;
		}
		child->initialized = true;
	}
	return (child);
}

static struct unveil_mode *
get_unveil_mode(struct curtain_slot *slot, struct unveil_node *node)
{
	struct unveil_mode *mode, **link;
	for (link = &node->modes; (mode = *link); link = &mode->node_next)
		/* keep list ordered */
		if ((uintptr_t)slot <= (uintptr_t)mode->slot) {
			if (slot != mode->slot)
				mode = NULL;
			break;
		}
	if (!mode) {
		mode = malloc(sizeof *mode);
		if (!mode)
			err(EX_TEMPFAIL, "malloc");
		*mode = (struct unveil_mode){
			.slot = slot,
			.node = node,
			.slot_next = slot->unveil_modes,
			.node_next = *link,
			.inherit = true,
		};
		slot->unveil_modes = *link = mode;
	}
	return (mode);
}

int
curtain_unveil(struct curtain_slot *slot,
    const char *path, unsigned flags, unveil_perms uperms)
{
	struct unveil_node *node;
	struct unveil_mode *mode;
	unveil_index tev[UNVEILREG_MAX_TE][2];
	struct unveilreg reg = {
		.atfd = AT_FDCWD,
		.atflags = flags & CURTAIN_UNVEIL_NOFOLLOW ? AT_SYMLINK_NOFOLLOW : 0,
		.path = path,
		.tec = UNVEILREG_MAX_TE,
		.tev = tev,
	};
	ssize_t ter;
	ter = unveilreg(UNVEILREG_REGISTER | UNVEILREG_NONDIRBYNAME, &reg);
	if (ter < 0) {
		if (errno != ENOENT && errno != EACCES && errno != ENOSYS)
			warn("%s: %s", __FUNCTION__, path);
		return (-1);
	}
	node = NULL;
	mode = NULL;
	for (ssize_t i = 0; i < ter; i++) {
		node = get_unveil_index_pair(tev[i][0], tev[i][1]);
		if (!node)
			err(EX_TEMPFAIL, "malloc");
		mode = get_unveil_mode(slot, node);
		if (!mode)
			return (-1);
		mode->uperms |= UPERM_TRAVERSE;
		if (flags & CURTAIN_UNVEIL_INSPECT)
			mode->uperms |= UPERM_INSPECT;
	}
	if (mode) {
		mode->inherit = flags & CURTAIN_UNVEIL_INHERIT;
		mode->inspect = flags & CURTAIN_UNVEIL_INSPECT;
		mode->uperms = uperms_expand(uperms);
	}
	return (0);
}

int
curtain_unveils_limit(struct curtain_slot *slot, unveil_perms uperms)
{
	struct unveil_mode *mode;
	uperms = uperms_expand(uperms | UPERM_TRAVERSE);
	for (mode = slot->unveil_modes; mode; mode = mode->slot_next)
		mode->uperms &= uperms;
	return (0);
}

int
curtain_unveils_reset_all(void)
{
	struct unveil_node *node, **link;
	struct unveil_mode *mode;
	for (link = unveils_table; link < &unveils_table[unveils_table_size]; link++)
		if ((node = *link))
			for (mode = node->modes; mode; mode = mode->node_next) {
				mode->uperms = UPERM_NONE;
				mode->inherit = true;
				mode->inspect = false;
			}
	return (0);
}

static void
fill_unveils_1(struct unveil_node *node, struct unveil_mode *inherit_head,
    struct curtainent_unveil *ents[CURTAIN_ON_COUNT], enum curtain_state min_state)
{
	struct unveil_mode *mode, *cmode, *imode, **ilink, *inherit_saved;
	struct unveil_node *child;
	unveil_perms uperms_on[CURTAIN_ON_COUNT];

#if 0
	for (mode = node->modes; mode && mode->node_next; mode = mode->node_next)
		assert((uintptr_t)mode->node_next->slot > (uintptr_t)mode->slot);
	for (mode = inherit_head; mode && mode->inherit_next; mode = mode->inherit_next)
		assert((uintptr_t)mode->inherit_next->slot > (uintptr_t)mode->slot);
#endif

	/*
	 * Merge join the inherited and current node's modes to handle
	 * inheritance between modes of corresponding slots.  The current
	 * node's modes are spliced into the inherited list replacing inherited
	 * modes for the same slot (if any).  The list is restored to its
	 * previous state before returning.
	 */
	for (enum curtain_on on = 0; on < CURTAIN_ON_COUNT; on++)
		uperms_on[on] = UPERM_NONE;
	cmode = node->modes;
	inherit_saved = inherit_head;
	imode = *(ilink = &inherit_head);
	while (cmode || imode) {
		assert(!cmode || !cmode->node_next ||
		    (uintptr_t)cmode->slot < (uintptr_t)cmode->node_next->slot);
		assert(!imode || !imode->inherit_next ||
		    (uintptr_t)imode->slot < (uintptr_t)imode->inherit_next->slot);
		assert(*ilink == imode);
		if (imode && (!cmode || (uintptr_t)cmode->slot > (uintptr_t)imode->slot)) {
			/*
			 * Inherited mode with no corresponding current node
			 * mode.  Permissions carry through nodes without
			 * (explicit) modes for a given slot.
			 */
			for (enum curtain_on on = 0; on < CURTAIN_ON_COUNT; on++)
				if (imode->slot->state_on[on] >= min_state)
					uperms_on[on] |= uperms_inherit(
					    imode->uperms | imode->inherited_uperms);
			imode = *(ilink = &imode->inherit_next);
		} else {
			/*
			 * Current node mode with or without a corresponding
			 * inherited mode.  Splice the current node in the
			 * inherited list with updated permissions.
			 */
			bool match, carry;
			match = imode && imode->slot == cmode->slot;
			cmode->inherited_uperms = match && cmode->inherit ?
			    uperms_inherit(imode->inherited_uperms | imode->uperms) :
			    UPERM_NONE;
			carry = false;
			for (enum curtain_on on = 0; on < CURTAIN_ON_COUNT; on++)
				if (cmode->slot->state_on[on] >= min_state) {
					unveil_perms uperms = cmode->uperms |
					    cmode->inherited_uperms;
					uperms_on[on] |= uperms;
					if (uperms != UPERM_NONE)
						carry = true;
				}
			cmode->inherit_saved_link = ilink;
			cmode->inherit_saved = imode;
			if (match)
				imode = imode->inherit_next;
			if (carry) {
				*ilink = cmode;
				*(ilink = &cmode->inherit_next) = imode;
			} else /* no permissions to inherit from this node */
				*ilink = imode;
			cmode = cmode->node_next;
		}
	}
#if 0
	for (mode = inherit_head; mode && mode->inherit_next; mode = mode->inherit_next)
		assert((uintptr_t)mode->inherit_next->slot > (uintptr_t)mode->slot);
#endif

	for (enum curtain_on on = 0; on < CURTAIN_ON_COUNT; on++)
		*ents[on]++ = (struct curtainent_unveil){
			.index = node->unveil_idx,
			.uperms = uperms_on[on],
		};

	for (child = node->children; child; child = child->sibling) {
		assert(child->parent == node);
		fill_unveils_1(child, inherit_head, ents, min_state);
	}

	for (mode = inherit_saved; mode; mode = mode->inherit_next)
		if (mode->node == node && mode->inherit_saved_link)
			*mode->inherit_saved_link = mode->inherit_saved;
}

static void
fill_unveils(struct curtainent_unveil *ents[CURTAIN_ON_COUNT], enum curtain_state min_state)
{
	struct unveil_node *node, **link;
	/* TODO optimize */
	for (link = unveils_table; link < &unveils_table[unveils_table_size]; link++)
		if ((node = *link) && !node->parent)
			fill_unveils_1(node, NULL, ents, min_state);
}


static struct simple_type *const simple_types[] = {
	&abilities_type,
	&ioctls_type,
	&sockafs_type,
	&socklvls_type,
	&sockopts_type,
	&privs_type,
	&sysctls_type,
};

void
curtain_reinit(void)
{
	/* TODO: free memory */
	reinit_defaults();
	for (size_t i = 0; i < nitems(simple_types); i++)
		reinit_simples(simple_types[i]);
	reinit_unveils();
	curtain_slots = NULL;
}

static const int curtainreq_flags[CURTAIN_ON_COUNT] = {
	[CURTAIN_ON_SELF] = CURTAINREQ_ON_SELF,
	[CURTAIN_ON_EXEC] = CURTAINREQ_ON_EXEC,
};

static int
curtain_submit_1(int flags, bool neutral_on[CURTAIN_ON_COUNT], enum curtain_state min_state)
{
	struct curtainreq reqv[1 + 2 * CURTAIN_ON_COUNT + nitems(simple_types) * CURTAIN_ON_COUNT * CURTAIN_LEVEL_COUNT], *reqp = reqv;
	enum curtainreq_level levels_on[CURTAIN_ON_COUNT];

	struct curtainent_unveil unveils_v[CURTAIN_ON_COUNT][unveils_count];
	struct curtainent_unveil *unveils_p[CURTAIN_ON_COUNT];

	void *base_ptrs[nitems(simple_types)][CURTAIN_ON_COUNT][CURTAIN_LEVEL_COUNT];
	void *fill_ptrs[nitems(simple_types)][CURTAIN_ON_COUNT][CURTAIN_LEVEL_COUNT];

	size_t total_space;
	total_space = 0;
	for (size_t i = 0; i < nitems(simple_types); i++)
		total_space += CURTAIN_ON_COUNT * CURTAIN_LEVEL_COUNT *
		    simple_types[i]->count * simple_types[i]->ent_size;
	char buffer[total_space], *cursor = buffer;
	for (size_t i = 0; i < nitems(simple_types); i++) {
		for (enum curtain_on on = 0; on < CURTAIN_ON_COUNT; on++) {
			for (enum curtainreq_level lvl = 0; lvl < CURTAIN_LEVEL_COUNT; lvl++) {
				base_ptrs[i][on][lvl] = fill_ptrs[i][on][lvl] = cursor;
				cursor += simple_types[i]->count * simple_types[i]->ent_size;
			}
		}
	}
	for (size_t i = 0; i < nitems(simple_types); i++)
		fill_simple(simple_types[i], fill_ptrs[i], min_state);

	fill_defaults(levels_on, min_state);
	for (enum curtain_on on = 0; on < CURTAIN_ON_COUNT; on++)
		unveils_p[on] = unveils_v[on];
	fill_unveils(unveils_p, min_state);

	for (enum curtain_on on = 0; on < CURTAIN_ON_COUNT; on++) {
		*reqp++ = (struct curtainreq){
			.type = CURTAINTYP_DEFAULT,
			.flags = curtainreq_flags[on],
			.level = neutral_on[on] ? CURTAINLVL_PASS : levels_on[on],
		};
		if (neutral_on[on])
			continue;
		for (size_t i = 0; i < nitems(simple_types); i++) {
			for (enum curtainreq_level lvl = 0; lvl < CURTAIN_LEVEL_COUNT; lvl++) {
				size_t filled = (char *)fill_ptrs[i][on][lvl] -
						(char *)base_ptrs[i][on][lvl];
				if (filled)
					*reqp++ = (struct curtainreq){
						.type = simple_types[i]->type,
						.flags = curtainreq_flags[on],
						.level = lvl,
						.data = base_ptrs[i][on][lvl],
						.size = filled,
					};
			}
		}
		size_t unveils_c;
		if ((unveils_c = unveils_p[on] - unveils_v[on]) != 0)
			*reqp++ = (struct curtainreq){
				.type = CURTAINTYP_UNVEIL,
				.flags = curtainreq_flags[on],
				.data = unveils_v[on],
				.size = unveils_c * sizeof **unveils_v,
			};
	}

	return (curtainctl(flags, reqp - reqv, reqv));
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
