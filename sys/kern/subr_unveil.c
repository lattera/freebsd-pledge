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

static int unveil_lookup_verbose = 0;
SYSCTL_INT(_vfs, OID_AUTO, unveil_lookup_verbose, CTLFLAG_RWTUN,
    &unveil_lookup_verbose, 0, NULL);

void
unveil_namei_start(struct nameidata *ndp, struct thread *td)
{
	struct filedesc *fdp = td->td_proc->p_fd;
	struct unveil_base *ubase;
	ndp->ni_unveil = NULL;
	FILEDESC_SLOCK(fdp);
	ubase = &fdp->fd_unveil;
	if (!ubase->active || ndp->ni_startdir) {
		/*
		 * If a start vnode was explicitly specified, assume that
		 * unveil checks don't need to apply.
		 */
		ndp->ni_lcf |= NI_LCF_UNVEIL_DISABLED;
	}
	FILEDESC_SUNLOCK(fdp);
}

void
unveil_lookup_update(struct nameidata *ndp, struct vnode *vp)
{
	struct componentname *cnp = &ndp->ni_cnd;
	struct filedesc *fdp = cnp->cn_thread->td_proc->p_fd;
	struct unveil_node *unveil;
	struct unveil_base *ubase;
	if (ndp->ni_lcf & NI_LCF_UNVEIL_DISABLED)
		return;
	FILEDESC_SLOCK(fdp);
	ubase = &fdp->fd_unveil;
	if (ubase)
		unveil = unveil_lookup(ubase, vp);
	else
		unveil = NULL;
	FILEDESC_SUNLOCK(fdp);
	if (unveil) {
		if (unveil_lookup_verbose)
			printf("unveil_lookup_update: unveil found %#x %p for %p (\"%s\" \"%s\")\n",
			    unveil->soft_perms, unveil, vp, cnp->cn_pnbuf, cnp->cn_nameptr);
		ndp->ni_unveil = unveil;
	} else {
		unveil = ndp->ni_unveil;
		if (unveil && unveil_lookup_verbose)
			printf("unveil_lookup_update: unveil carry down %#x %p for %p (\"%s\" \"%s\")\n",
			    unveil->soft_perms, unveil, vp, cnp->cn_pnbuf, cnp->cn_nameptr);
	}
}

void
unveil_lookup_update_dotdot(struct nameidata *ndp, struct vnode *vp)
{
	struct componentname *cnp = &ndp->ni_cnd;
	struct unveil_node *unveil;
	if (ndp->ni_lcf & NI_LCF_UNVEIL_DISABLED)
		return;
	if ((unveil = ndp->ni_unveil) && ndp->ni_unveil->vp == vp) {
		unveil = unveil->cover;
		if (unveil) {
			if (unveil_lookup_verbose)
				printf("unveil_lookup_update_dotdot: unveil cover %#x %p for %p (\"%s\" \"%s\")\n",
				    unveil->soft_perms, unveil, vp, cnp->cn_pnbuf, cnp->cn_nameptr);
			ndp->ni_unveil = unveil;
		} else {
			if (unveil_lookup_verbose)
				printf("unveil_lookup_update_dotdot: unveil drop for %p (\"%s\" \"%s\")\n",
				    vp, cnp->cn_pnbuf, cnp->cn_nameptr);
			ndp->ni_unveil = NULL;
		}
	} else {
		unveil = ndp->ni_unveil;
		if (unveil && unveil_lookup_verbose)
			printf("unveil_lookup_update_dotdot: unveil carry up %#x %p for %p (\"%s\" \"%s\")\n",
			    unveil->soft_perms, unveil, vp, cnp->cn_pnbuf, cnp->cn_nameptr);
	}
}

static void
unveil_perms_to_rights(cap_rights_t *rights,
    unveil_perms_t uperms, bool descendant)
{
	cap_rights_init(rights, CAP_LOOKUP);
	/* TODO: cache these sets */
	/* TODO: ACLs caps */
	if (uperms & UNVEIL_PERM_INSPECT && !descendant)
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
	struct unveil_node *node;
	bool descendant;
	unveil_perms_t uperms;
	cap_rights_t haverights;
	if (ndp->ni_lcf & NI_LCF_UNVEIL_DISABLED)
		return (0);

	if (unveil_lookup_verbose)
		printf("unveil_check_namei %lu %#x %p: %s\n",
		    cnp->cn_nameiop, ndp->ni_lcf,
		    ndp->ni_unveil,
		    cnp->cn_pnbuf
		);

	if ((cnp->cn_flags & FOLLOW) &&
	    ndp->ni_vp && ndp->ni_vp->v_type == VLNK)
		return (0);

	if ((node = ndp->ni_unveil)) {
		uperms = node->soft_perms;
		descendant = node->vp != ndp->ni_vp;
	} else {
		uperms = UNVEIL_PERM_NONE;
		descendant = true;
	}

	if ((cnp->cn_nameiop == DELETE || cnp->cn_nameiop == CREATE) &&
	    !(uperms & UNVEIL_PERM_CPATH))
		return (EACCES);

	unveil_perms_to_rights(&haverights, uperms, descendant);
	if (!cap_rights_contains(&haverights, &ndp->ni_rightsneeded))
		return (EACCES);

	return (0);
}

#endif
