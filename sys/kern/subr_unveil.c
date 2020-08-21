#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

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

#ifdef SYSFIL

static inline const cap_rights_t *
sysfil_to_rights(struct thread *td)
{
	int i = 0;
	i |= (sysfil_check(td, SYSFIL_RPATH) == 0) << 1;
	i |= (sysfil_check(td, SYSFIL_WPATH) == 0) << 2;
	i |= (sysfil_check(td, SYSFIL_CPATH) == 0) << 3;
	i |= (sysfil_check(td, SYSFIL_EXEC ) == 0) << 4;
	return (&cap_unveil_merged_rights[i]);
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

bool
unveil_lookup_tolerate_error(struct nameidata *ndp, int error)
{
	return (error == ENOENT && ndp->ni_unveil_save);
}

void
unveil_namei_start(struct nameidata *ndp, struct thread *td)
{
	struct filedesc *fdp = td->td_proc->p_fd;
	struct unveil_base *base = &fdp->fd_unveil;
	FILEDESC_SLOCK(fdp);
	if (!ndp->ni_unveil_save && (!base->active || ndp->ni_startdir))
		ndp->ni_lcf |= NI_LCF_UNVEIL_DISABLED;
	FILEDESC_SUNLOCK(fdp);
}

int
unveil_lookup_update(struct nameidata *ndp, struct vnode *vp, bool last)
{
	struct componentname *cnp = &ndp->ni_cnd;
	struct filedesc *fdp = cnp->cn_thread->td_proc->p_fd;
	struct unveil_base *base = &fdp->fd_unveil;
	int error;
	if (ndp->ni_lcf & NI_LCF_UNVEIL_DISABLED)
		return (0);
	/* NOTE: vp and ndp->ni_dvp may be NULL and may both be equal */
	if (ndp->ni_unveil_save) {
		FILEDESC_XLOCK(fdp);
		error = unveil_traverse_save(
		    base, ndp->ni_unveil_save, &ndp->ni_unveil,
		    ndp->ni_dvp, cnp->cn_nameptr, cnp->cn_namelen, vp, last);
		FILEDESC_XUNLOCK(fdp);
	} else {
		FILEDESC_SLOCK(fdp);
		error = unveil_traverse(
		    base, ndp->ni_unveil_save, &ndp->ni_unveil,
		    ndp->ni_dvp, cnp->cn_nameptr, cnp->cn_namelen, vp, last);
		FILEDESC_SUNLOCK(fdp);
	}
	return (error);
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
	return (&cap_unveil_merged_rights[i]);
}

int
unveil_lookup_check(struct nameidata *ndp)
{
	struct componentname *cnp = &ndp->ni_cnd;
	struct filedesc *fdp = cnp->cn_thread->td_proc->p_fd;
	struct unveil_node *node;
	unveil_perms_t uperms;
	const cap_rights_t *haverights;
	int failed;
	if (ndp->ni_lcf & NI_LCF_UNVEIL_DISABLED)
		return (0);

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

	return (0);
}

#endif

