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

/*
 * A node always represents a single path component.  As it is, veils are not
 * designed to store a large number of nodes; lookups within a node are linear
 * searches.
 */

struct veil_node {
	struct veil_node *parent, *sibling, *children, *next;
	char name[]; /* should never contain any '/' */
};

/*
 * Ties a reference to a veiled path to the veil structure.  Process file
 * descriptors and CWD reference will need this.  This allows to deal with ".."
 * accesses while tracking renames.
 */

struct veil_tie {
	struct veil_node *node;
	size_t depth;
};

static inline void
veil_init(struct veil *veil)
{
	*veil = (struct veil){ .root = NULL };
}

void veil_copy(struct veil *dst, const struct veil *src);
void veil_free(struct veil *);

#endif
