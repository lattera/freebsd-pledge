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
#include <sys/kdb.h>

#ifdef UNVEIL

void
unveil_ndinit(struct nameidata *ndp, struct thread *td)
{
	ndp->ni_unveil = NULL;
	ndp->ni_unveil_data = NULL;
}

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

static cap_rights_t __read_mostly unveil_inspect_rights;
static cap_rights_t __read_mostly unveil_rpath_rights;
static cap_rights_t __read_mostly unveil_wpath_rights;
static cap_rights_t __read_mostly unveil_cpath_rights;
static cap_rights_t __read_mostly unveil_xpath_rights;

static void
unveil_rights_sysinit(void __unused *data)
{
	cap_rights_init(&unveil_inspect_rights,
	    CAP_LOOKUP,
	    CAP_FPATHCONF,
	    CAP_FSTAT,
	    CAP_FSTATAT);
	cap_rights_init(&unveil_rpath_rights,
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
	cap_rights_init(&unveil_wpath_rights,
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
	cap_rights_init(&unveil_cpath_rights,
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
	cap_rights_init(&unveil_xpath_rights,
	    CAP_LOOKUP,
	    CAP_FEXECVE,
	    CAP_EXECAT);
}
SYSINIT(unveil_rights_sysinit, SI_SUB_COPYRIGHT, SI_ORDER_ANY,
    unveil_rights_sysinit, NULL);

static void
unveil_perms_to_rights(cap_rights_t *rights, unveil_perms_t uperms)
{
	cap_rights_init(rights);
	if (uperms & UNVEIL_PERM_INSPECT)
		cap_rights_merge(rights, &unveil_inspect_rights);
	if (uperms & UNVEIL_PERM_RPATH)
		cap_rights_merge(rights, &unveil_rpath_rights);
	if (uperms & UNVEIL_PERM_WPATH)
		cap_rights_merge(rights, &unveil_wpath_rights);
	if (uperms & UNVEIL_PERM_CPATH)
		cap_rights_merge(rights, &unveil_cpath_rights);
	if (uperms & UNVEIL_PERM_XPATH)
		cap_rights_merge(rights, &unveil_xpath_rights);
}

int
unveil_lookup_check(struct nameidata *ndp)
{
	struct componentname *cnp = &ndp->ni_cnd;
	struct filedesc *fdp = cnp->cn_thread->td_proc->p_fd;
	struct unveil_base *base = &fdp->fd_unveil;
	struct unveil_node *node;
	unveil_perms_t uperms;
	cap_rights_t haverights;
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
		if (node->vp != ndp->ni_vp)
			uperms &= UNVEIL_PERM_INHERITABLE_MASK;
		failed = uperms ? EACCES : ENOENT;
	} else {
		uperms = UNVEIL_PERM_NONE;
		failed = ENOENT;
	}

	unveil_perms_to_rights(&haverights, uperms);
	if (!cap_rights_contains(&haverights, ndp->ni_rightsneeded))
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
