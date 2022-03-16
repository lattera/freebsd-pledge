#ifndef	_SYS__UNVEIL_H_
#define	_SYS__UNVEIL_H_

#include <sys/types.h>

typedef uint32_t unveil_perms;
typedef uint16_t unveil_index;
typedef uint8_t unveil_action;

struct file_unveil_info {
	uint64_t	serial;
	unveil_perms	uperms;
	unveil_action	action;
};

#endif
