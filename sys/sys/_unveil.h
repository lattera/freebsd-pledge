#ifndef	_SYS__UNVEIL_H_
#define	_SYS__UNVEIL_H_

#include <sys/types.h>
#include <sys/tree.h>
#include <sys/_pledge.h>
#ifndef _KERNEL
#include <stdbool.h>
#endif

struct unveil_node;

struct unveil_base {
	RB_HEAD(unveil_dir_tree, unveil_node) dir_root;
	u_int dir_count;
	bool finished;
};

typedef uint8_t unveil_perms_t;

#endif
