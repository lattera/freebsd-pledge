#ifndef	_SYS__UNVEIL_H_
#define	_SYS__UNVEIL_H_

#include <sys/types.h>
#ifdef _KERNEL
#include <sys/_sx.h>
#else
#include <stdbool.h>
#endif

typedef uint32_t unveil_perms;
typedef uint16_t unveil_index;

#ifdef _KERNEL

struct unveil_node;

struct unveil_traversal {
	struct unveil_tree *tree;
	struct unveil_node *cover; /* last unveil encountered */
	struct unveil_save *save;
	unveil_perms effective_uperms;
	bool first;
	int8_t type; /* vnode type of last file encountered */
	uint8_t depth; /* depth under cover of last file */
};

enum { UNVEIL_ON_COUNT = 2 };

struct unveil_base {
	struct sx sx;
	struct unveil_tree *tree;
	bool modified;
	struct unveil_base_flags {
		bool active;
		bool frozen;
		bool wanted;
	} on[UNVEIL_ON_COUNT];
};

#endif /* _KERNEL */

#endif
