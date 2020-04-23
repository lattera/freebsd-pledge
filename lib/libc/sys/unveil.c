#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <err.h>
#include <sys/unveil.h>

#ifdef PLEDGE

static int
unveil_parse_perms(unveil_perms_t *perms, const char *s)
{
        *perms = 0;
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

static int
unveil_1(int flags, const char *path, const char *permissions, bool *first)
{
	int r;
	unveil_perms_t perms;
	if (!path && !permissions) {
		/*
		 * Disallow increasing any unveil permissions.
		 *
		 * XXX: This also disallows any unveils that future pledge
		 * promise may need to add.
		 */
		r = unveilctl(-1, NULL,
		    flags |
		    UNVEIL_FLAG_IMPLICIT |
		    UNVEIL_FLAG_FOR_ALL |
		    UNVEIL_FLAG_FREEZE,
		    0);
		return (r);
	}
	r = unveil_parse_perms(&perms, permissions);
	if (r < 0) {
		errno = EINVAL;
		return (-1);
	}
	if (*first) {
		/*
		 * After the first call to unveil(), filesystem access must be
		 * restricted to what has been unveiled.  However, modifying or
		 * adding unveils with higher permissions is still permitted.
		 */
		r = unveilctl(-1, NULL,
		    flags | UNVEIL_FLAG_IMPLICIT | UNVEIL_FLAG_MASK,
		    UNVEIL_PERM_NONE);
		if (r < 0)
			return (r);
		*first = false;
	}
	return (unveilctl(AT_FDCWD, path, flags, perms));
}

#endif

static bool first_unveil = true;
static bool exec_first_unveil = true;

int
unveil(const char *path, const char *permissions)
{
#ifdef PLEDGE
	/* TODO: global lock */
	int r;
	r = unveil_1(0, path, permissions, &first_unveil);
	if (r < 0)
		return (r);
	r = unveil_1(UNVEIL_FLAG_FOR_EXEC, path, permissions, &exec_first_unveil);
	if (r < 0)
		return (r);
	return (0);
#else
	errno = ENOSYS;
	return (-1);
#endif
}
