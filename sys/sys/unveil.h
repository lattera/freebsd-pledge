#ifndef	_SYS_UNVEIL_H_
#define	_SYS_UNVEIL_H_

#include <sys/types.h>
#include <sys/pledge_set.h>
#include <sys/tree.h>
#include <sys/malloc.h>

#ifdef _KERNEL
#ifdef PLEDGE
MALLOC_DECLARE(M_VEIL);
#endif
#endif

struct veil_node;

struct veil {
	/*
	 * First node must have no siblings and an empty name.  It represents
	 * the root of a directory hierarchy.  It may be a NULL pointer.
	 */
	struct veil_node *root;
	struct veil_node *list;
	size_t node_count;
};

typedef uint8_t veil_perms_t;

enum {
	VEIL_PERM_RPATH = 0x01,
	VEIL_PERM_WPATH = 0x02,
	VEIL_PERM_CPATH = 0x04,
	VEIL_PERM_EXEC  = 0x08,
};

/*
 * A node always represents a single path component.  As it is, veils are not
 * designed to store a large number of nodes; lookups within a node are linear
 * searches.
 */

struct veil_node {
	struct veil_node *parent, *sibling, *children, *next;
	veil_perms_t perms;
	char name[]; /* should never contain any '/' */
};

/*
 * Ties a reference to a veiled path to the veil structure.  Process file
 * descriptors and CWD reference will need this.  This allows to deal with ".."
 * accesses while tracking renames.
 */

struct veil_tie {
	struct veil_node *node;
	size_t depth; /* XXX must handle overflows */
};

static inline void
veil_init(struct veil *veil)
{
	*veil = (struct veil){ .root = NULL };
}

void veil_copy(struct veil *dst, const struct veil *src);
void veil_free(struct veil *);

#endif
