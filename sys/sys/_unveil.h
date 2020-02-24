#ifndef	_SYS__UNVEIL_H_
#define	_SYS__UNVEIL_H_

#include <sys/types.h>
#include <sys/_pledge.h>

struct veil_node;

struct veil {
	/*
	 * First node must have no siblings and an empty name.  It represents
	 * the root of a directory hierarchy.  It may be a NULL pointer.
	 */
	struct veil_node *root;
	struct veil_node *list;
	u_int node_count;
};

typedef uint8_t veil_perms_t;

/*
 * A node always represents a single path component.
 *
 * As it is, veils are not designed to store a large number of nodes; lookups
 * within a node are linear searches.
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

#endif
