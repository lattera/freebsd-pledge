#ifndef	_SYS_UNVEIL_H_
#define	_SYS_UNVEIL_H_

#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/_unveil.h>

#ifdef PLEDGE
MALLOC_DECLARE(M_VEIL);
#endif

enum {
	VEIL_PERM_RPATH = 0x01,
	VEIL_PERM_WPATH = 0x02,
	VEIL_PERM_CPATH = 0x04,
	VEIL_PERM_EXEC  = 0x08,
};

static inline void
veil_init(struct veil *veil)
{
	*veil = (struct veil){ .root = NULL };
}

void veil_copy(struct veil *dst, const struct veil *src);
void veil_free(struct veil *);

#endif
