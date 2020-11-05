#ifndef	_SYS__UNVEIL_H_
#define	_SYS__UNVEIL_H_

#include <sys/types.h>
#include <sys/tree.h>
#ifndef _KERNEL
#include <stdbool.h>
#endif

typedef uint8_t unveil_perms_t;

struct unveil_node;

struct unveil_traversal {
	struct unveil_node *cover; /* last unveil encountered */
	struct unveil_save *save;
	bool descended;
};

struct unveil_base {
	RB_HEAD(unveil_node_tree, unveil_node) root;
	u_int node_count;
	bool active, exec_active;
};

#endif
