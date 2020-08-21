#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_kdb.h"

#include <sys/param.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/namei.h>
#include <sys/sysctl.h>
#include <sys/unveil.h>
#include <sys/capsicum.h>
#include <sys/sysfil.h>
#include <sys/kdb.h>

#if defined(UNVEIL) || defined(SYSFIL)
static cap_rights_t __read_mostly unveil_merged_rights[1 << 5];
#endif

#ifdef SYSFIL

static inline const cap_rights_t *
sysfil_to_rights(struct thread *td)
{
	int i = 0;
	i |= (sysfil_check(td, SYSFIL_RPATH) == 0) << 1;
	i |= (sysfil_check(td, SYSFIL_WPATH) == 0) << 2;
	i |= (sysfil_check(td, SYSFIL_CPATH) == 0) << 3;
	i |= (sysfil_check(td, SYSFIL_EXEC ) == 0) << 4;
	return (&unveil_merged_rights[i]);
}

int
sysfil_namei_check(struct nameidata *ndp, struct thread *td)
{
	const cap_rights_t *haverights;
	if (!IN_RESTRICTED_MODE(td))
		return (0);
	haverights = sysfil_to_rights(td);
	if (cap_rights_contains(haverights, ndp->ni_rightsneeded))
		return (0);
	return (EPERM);
}

#endif

#ifdef UNVEIL

void
unveil_namei_start(struct nameidata *ndp, struct thread *td)
{
	struct filedesc *fdp = td->td_proc->p_fd;
	struct unveil_base *base = &fdp->fd_unveil;
	FILEDESC_SLOCK(fdp);
	if (!ndp->ni_unveil_data && (!base->active || ndp->ni_startdir))
		ndp->ni_lcf |= NI_LCF_UNVEIL_DISABLED;
	FILEDESC_SUNLOCK(fdp);
}

int
unveil_lookup_update(struct nameidata *ndp, struct vnode *vp)
{
	struct componentname *cnp = &ndp->ni_cnd;
	struct filedesc *fdp = cnp->cn_thread->td_proc->p_fd;
	struct unveil_base *base = &fdp->fd_unveil;
	struct unveil_node *node;
	if (ndp->ni_lcf & NI_LCF_UNVEIL_DISABLED)
		return (0);
	FILEDESC_SLOCK(fdp);
	node = unveil_lookup(base, vp);
	FILEDESC_SUNLOCK(fdp);
	if (node)
		ndp->ni_unveil = node;
	if (ndp->ni_unveil_data) {
		int error;
		FILEDESC_XLOCK(fdp);
		error = unveil_save(base, ndp->ni_unveil_data, false,
		    vp, &ndp->ni_unveil);
		FILEDESC_XUNLOCK(fdp);
		if (error)
			return (error);
	}
	return (0);
}

void
unveil_lookup_update_dotdot(struct nameidata *ndp, struct vnode *vp)
{
	struct unveil_node *node;
	if (ndp->ni_lcf & NI_LCF_UNVEIL_DISABLED)
		return;
	if ((node = ndp->ni_unveil) && node->vp == vp)
		ndp->ni_unveil = node->cover;
}

static inline const cap_rights_t *
unveil_perms_to_rights(unveil_perms_t uperms)
{
	int i = 0;
	i |= ((uperms & UNVEIL_PERM_INSPECT) != 0) << 0;
	i |= ((uperms & UNVEIL_PERM_RPATH)   != 0) << 1;
	i |= ((uperms & UNVEIL_PERM_WPATH)   != 0) << 2;
	i |= ((uperms & UNVEIL_PERM_CPATH)   != 0) << 3;
	i |= ((uperms & UNVEIL_PERM_XPATH)   != 0) << 4;
	return (&unveil_merged_rights[i]);
}

int
unveil_lookup_check(struct nameidata *ndp)
{
	struct componentname *cnp = &ndp->ni_cnd;
	struct filedesc *fdp = cnp->cn_thread->td_proc->p_fd;
	struct unveil_base *base = &fdp->fd_unveil;
	struct unveil_node *node;
	unveil_perms_t uperms;
	const cap_rights_t *haverights;
	int failed;
	if (ndp->ni_lcf & NI_LCF_UNVEIL_DISABLED)
		return (0);

	if (ndp->ni_unveil_data) {
		int error;
		FILEDESC_XLOCK(fdp);
		error = unveil_save(base, ndp->ni_unveil_data, true,
		    ndp->ni_vp, &ndp->ni_unveil);
		FILEDESC_XUNLOCK(fdp);
		if (error)
			return (error);
	}

#if 0
	if ((cnp->cn_flags & FOLLOW) &&
	    ndp->ni_vp && ndp->ni_vp->v_type == VLNK)
		return (0);
#endif

	if ((node = ndp->ni_unveil)) {
		FILEDESC_SLOCK(fdp);
		uperms = unveil_node_soft_perms(node, UNVEIL_ROLE_CURR);
		FILEDESC_SUNLOCK(fdp);
		uperms &= UNVEIL_PERM_ALL; /* drop internal bit */
		if (node->vp != ndp->ni_vp)
			/* The unveil covered a parent directory. */
			uperms &= ~UNVEIL_PERM_NONINHERITED_MASK;
		failed = uperms & ~UNVEIL_PERM_INSPECT ? EACCES : ENOENT;
	} else {
		uperms = UNVEIL_PERM_NONE;
		failed = ENOENT;
	}

	haverights = unveil_perms_to_rights(uperms);
	if (!cap_rights_contains(haverights, ndp->ni_rightsneeded))
		return (failed);

	/*
	 * This should not be necessary, but it could catch some namei() calls
	 * that have the wrong rights.
	 */
	if ((cnp->cn_nameiop == DELETE || cnp->cn_nameiop == CREATE) &&
	    !(uperms & UNVEIL_PERM_CPATH)) {
		printf("namei DELETE/CREATE blocked despite rights.\n");
#ifdef KDB
		kdb_backtrace();
#endif
		return (failed);
	}

	return (0);
}

#endif

#if defined(UNVEIL) || defined(SYSFIL)

static void
unveil_rights_sysinit(void __unused *data)
{
	cap_rights_t null_rights;
	cap_rights_t inspect_rights;
	cap_rights_t rpath_rights;
	cap_rights_t wpath_rights;
	cap_rights_t cpath_rights;
	cap_rights_t xpath_rights;

	cap_rights_init(&null_rights);
	cap_rights_init(&inspect_rights,
	    CAP_LOOKUP,
	    CAP_FPATHCONF,
	    CAP_FSTAT,
	    CAP_FSTATAT);
	cap_rights_init(&rpath_rights,
	    CAP_LOOKUP,
	    CAP_READ,
	    CAP_SEEK,
	    CAP_FPATHCONF,
	    CAP_MMAP,
	    CAP_FCHDIR,
	    CAP_FSTAT,
	    CAP_FSTATAT,
	    CAP_FSTATFS,
	    CAP_RENAMEAT_SOURCE,
	    CAP_LINKAT_SOURCE,
	    CAP_MAC_GET,
	    CAP_EXTATTR_GET,
	    CAP_EXTATTR_LIST);
	cap_rights_init(&wpath_rights,
	    CAP_LOOKUP,
	    CAP_WRITE,
	    CAP_SEEK,
	    CAP_FPATHCONF,
	    CAP_MMAP,
	    CAP_FSYNC,
	    CAP_FTRUNCATE,
	    CAP_FCHFLAGS,
	    CAP_CHFLAGSAT,
	    CAP_FCHMOD,
	    CAP_FCHMODAT,
	    CAP_FCHOWN,
	    CAP_FCHOWNAT,
	    CAP_FUTIMES,
	    CAP_FUTIMESAT,
	    CAP_MAC_SET,
	    CAP_REVOKEAT,
	    CAP_EXTATTR_SET,
	    CAP_EXTATTR_DELETE);
	cap_rights_init(&cpath_rights,
	    CAP_LOOKUP,
	    CAP_CREATE,
	    CAP_FPATHCONF,
	    CAP_LINKAT_TARGET,
	    CAP_MKDIRAT,
	    CAP_MKFIFOAT,
	    CAP_MKNODAT,
	    CAP_SYMLINKAT,
	    CAP_UNLINKAT,
	    CAP_BINDAT,
	    CAP_CONNECTAT,
	    CAP_RENAMEAT_TARGET,
	    CAP_UNDELETEAT);
	cap_rights_init(&xpath_rights,
	    CAP_LOOKUP,
	    CAP_FEXECVE,
	    CAP_EXECAT);

	/* Pre-merge rights for every possible set of unveil permissions. */
	for (int i = 0; i < nitems(unveil_merged_rights); i++) {
		cap_rights_t *rights = &unveil_merged_rights[i];
		cap_rights_init(rights);
		cap_rights_merge(rights, i & (1 << 0) ? &inspect_rights : &null_rights);
		cap_rights_merge(rights, i & (1 << 1) ? &rpath_rights   : &null_rights);
		cap_rights_merge(rights, i & (1 << 2) ? &wpath_rights   : &null_rights);
		cap_rights_merge(rights, i & (1 << 3) ? &cpath_rights   : &null_rights);
		cap_rights_merge(rights, i & (1 << 4) ? &xpath_rights   : &null_rights);
	}
}

SYSINIT(unveil_rights_sysinit, SI_SUB_COPYRIGHT, SI_ORDER_ANY,
    unveil_rights_sysinit, NULL);

#endif
