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

#ifdef UNVEIL

static int unveil_lookup_verbose = 0;
SYSCTL_INT(_vfs, OID_AUTO, unveil_lookup_verbose, CTLFLAG_RWTUN,
    &unveil_lookup_verbose, 0, NULL);

void
unveil_namei_init(struct nameidata *ndp, struct vnode *startdir, struct thread *td)
{
	struct filedesc *fdp = td->td_proc->p_fd;
	struct unveil_base *ubase;
	ndp->ni_uflags = 0;
	ndp->ni_unveil = NULL;
	FILEDESC_SLOCK(fdp);
	ubase = &fdp->fd_unveil;
	if (!ubase->active || startdir) {
		/*
		 * If a start vnode was explicitly specified, assume that
		 * unveil checks don't need to apply.
		 */
		ndp->ni_uflags |= NIUNV_DISABLED;
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
	if (ndp->ni_uflags & NIUNV_DISABLED)
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
	if (ndp->ni_uflags & NIUNV_DISABLED)
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

int
unveil_lookup_check(struct nameidata *ndp)
{
	struct componentname *cnp = &ndp->ni_cnd;
	unveil_perms_t uperms;
	if (ndp->ni_uflags & NIUNV_DISABLED)
		return (0);
	if (unveil_lookup_verbose)
		printf("unveil_check_namei %lu %#x %p: %s\n",
		    cnp->cn_nameiop, ndp->ni_uflags,
		    ndp->ni_unveil,
		    cnp->cn_pnbuf
		);
	if ((cnp->cn_flags & FOLLOW) &&
	    ndp->ni_vp && ndp->ni_vp->v_type == VLNK)
		return (0);
	uperms = ndp->ni_unveil ? ndp->ni_unveil->soft_perms : UNVEIL_PERM_NONE;
	if ((cnp->cn_nameiop == DELETE || cnp->cn_nameiop == CREATE) &&
	    !(uperms & UNVEIL_PERM_CPATH))
		return (EPERM);
	if ((ndp->ni_uflags & NIUNV_FORREAD) && !(uperms & UNVEIL_PERM_RPATH))
		return (EPERM);
	if ((ndp->ni_uflags & NIUNV_FORWRITE) && !(uperms & UNVEIL_PERM_WPATH))
		return (EPERM);
	return (0);
}

#endif
