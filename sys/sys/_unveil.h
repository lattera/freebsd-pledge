#ifndef	_SYS__UNVEIL_H_
#define	_SYS__UNVEIL_H_

#include <sys/types.h>
#ifdef _KERNEL
#include <sys/_sx.h>
#else
#include <stdbool.h>
#endif

typedef uint8_t unveil_perms;
typedef uint8_t unveil_slots;

#ifdef _KERNEL

struct unveil_node;

struct unveil_traversal {
	struct unveil_tree *tree;
	struct unveil_node *cover; /* last unveil encountered */
	int save_flags;
	unveil_slots save_slots;
	unveil_perms save_uperms;
	int8_t type; /* type of last file encountered */
	uint8_t depth; /* depth under cover of last file */
};

enum { UNVEIL_ON_COUNT = 2 };

struct unveil_base {
	struct sx sx;
	struct unveil_tree *tree;
	bool modified;
	struct unveil_base_flags {
		bool active : 1;
		bool frozen : 1;
		bool wanted : 1;
		unveil_slots slots;
	} on[UNVEIL_ON_COUNT];
};

#endif /* _KERNEL */

#endif
