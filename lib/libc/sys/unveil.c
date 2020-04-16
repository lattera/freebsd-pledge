#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <err.h>
#include <sys/unveil.h>

static int
unveil_parse_perms(unveil_perms_t *perms, const char *s)
{
        while (*s)
                switch (*s++) {
                case 'r': *perms |= UNVEIL_PERM_RPATH; break;
                case 'w': *perms |= UNVEIL_PERM_WPATH; break;
                case 'c': *perms |= UNVEIL_PERM_CPATH; break;
                case 'x': *perms |= UNVEIL_PERM_EXEC;  break;
                default:
                          return (-1);
                }
        return (0);
}

int
unveil(const char *path, const char *permissions)
{
#ifdef PLEDGE
	/* TODO: global lock */
	int r;
	unveil_perms_t perms;
	if (!path && !permissions) {
		r = unveilctl(-1, NULL,
		    UNVEIL_FLAG_RESTRICT,
		    UNVEIL_PERM_NONE);
		if (r < 0)
			return (r);
		r = unveilctl(-1, NULL,
		    UNVEIL_FLAG_FOR_ALL | UNVEIL_FLAG_FREEZE,
		    0);
		return (r);
	}
	perms = 0;
	r = unveil_parse_perms(&perms, permissions);
	if (r < 0) {
		errno = EINVAL;
		return (-1);
	}
	/* XXX need to restrict FS access after first unveil */
	return (unveilctl(AT_FDCWD, path, 0, perms));
#else
	errno = ENOSYS;
	return (-1);
#endif
}
