#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/namei.h>
#include <sys/sysctl.h>
#include <sys/sysfil.h>
#include <sys/unveil.h>
#include <sys/capsicum.h>

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

static void
unveil_perms_to_rights(cap_rights_t *rights, unveil_perms_t uperms)
{
	cap_rights_init(rights, CAP_LOOKUP);
	/* TODO: cache these sets */
	/* TODO: ACLs caps */
	if (uperms & UNVEIL_PERM_INSPECT)
		cap_rights_set(rights,
		    CAP_FPATHCONF,
		    CAP_FSTAT,
		    CAP_FSTATAT);
	if (uperms & UNVEIL_PERM_RPATH)
		cap_rights_set(rights,
		    CAP_READ,
		    CAP_SEEK,
		    CAP_FPATHCONF,
		    CAP_MMAP,
		    CAP_FCHDIR,
		    CAP_FSTAT,
		    CAP_FSTATAT,
		    CAP_FSTATFS,
		    CAP_RENAMEAT_SOURCE,
		    CAP_LINKAT_SOURCE);
	if (uperms & UNVEIL_PERM_WPATH)
		cap_rights_set(rights,
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
		    CAP_FUTIMESAT);
	if (uperms & UNVEIL_PERM_CPATH)
		cap_rights_set(rights,
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
		    CAP_RENAMEAT_TARGET);
	if (uperms & UNVEIL_PERM_XPATH)
		cap_rights_set(rights,
		    CAP_FEXECVE,
		    CAP_EXECAT);
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

	/*
	 * When unveil checking is enabled, only allow namei() calls that were
	 * given a set of needed capability rights (NDINIT_ATRIGHTS()).
	 * Otherwise those calls would always pass the permission check.  Some
	 * calls haven't been converted to use capability rights yet.
	 */
	if (!(ndp->ni_intflags & NI_INT_HASRIGHTS))
		return (failed);

	/*
	 * This should not be necessary, but it could catch some namei() calls
	 * that have the wrong rights.
	 */
	if ((cnp->cn_nameiop == DELETE || cnp->cn_nameiop == CREATE) &&
	    !(uperms & UNVEIL_PERM_CPATH))
		return (failed);

	unveil_perms_to_rights(&haverights, uperms);
	if (!cap_rights_contains(&haverights, &ndp->ni_rightsneeded))
		return (failed);

	return (0);
}

#endif
