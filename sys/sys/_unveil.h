#ifndef	_SYS__UNVEIL_H_
#define	_SYS__UNVEIL_H_

#include <sys/types.h>
#ifdef _KERNEL
#include <sys/_sx.h>
#else
#include <stdbool.h>
#endif

typedef uint8_t unveil_perms_t;

#ifdef _KERNEL

struct unveil_node;

struct unveil_traversal {
	struct unveil_save *save;
	struct unveil_tree *tree;
	struct unveil_node *cover; /* last unveil encountered */
	int8_t type; /* type of last file encountered */
	uint8_t depth; /* depth under cover of last file */
};

enum { UNVEIL_ROLE_COUNT = 2 };

struct unveil_base {
	struct sx sx;
	struct unveil_tree *tree;
	unsigned node_count;
	unsigned writers;
	struct unveil_base_flags {
		bool active : 1;
		bool frozen : 1;
	} flags[UNVEIL_ROLE_COUNT];
};

#endif /* _KERNEL */

#endif
