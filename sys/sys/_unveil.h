#ifndef	_SYS__UNVEIL_H_
#define	_SYS__UNVEIL_H_

#ifdef _KERNEL
#include "opt_unveil.h"
#endif

#include <sys/types.h>
#include <sys/tree.h>
#include <sys/_sysfil.h>
#ifndef _KERNEL
#include <stdbool.h>
#endif

typedef uint8_t unveil_perms_t;

struct unveil_node;

struct unveil_base {
	RB_HEAD(unveil_node_tree, unveil_node) root;
	u_int node_count;
	bool active;
};

#endif
