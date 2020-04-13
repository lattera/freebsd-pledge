#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_capsicum.h"

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/ucred.h>
#include <sys/sysfil.h>

#ifdef PLEDGE

#endif /* PLEDGE */

int
sys_old_pledge(struct thread *td, struct old_pledge_args *uap)
{
	return (ENOSYS);
}

