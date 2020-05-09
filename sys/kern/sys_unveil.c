#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_capsicum.h"

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/ucred.h>
#include <sys/syslog.h>
#include <sys/jail.h>
#include <sys/namei.h>
#include <sys/sysfil.h>
#include <sys/unveil.h>

#ifdef UNVEIL

MALLOC_DEFINE(M_UNVEIL, "unveil", "unveil");

static unsigned int unveil_max_nodes_per_process = 100;
SYSCTL_UINT(_kern, OID_AUTO, maxunveilsperproc, CTLFLAG_RW,
	&unveil_max_nodes_per_process, 0, "Maximum unveils allowed per process");

static int
unveil_node_cmp(struct unveil_node *a, struct unveil_node *b)
{
	uintptr_t ak = (uintptr_t)a->vp, bk = (uintptr_t)b->vp;
	return (ak > bk ? 1 : ak < bk ? -1 : 0);
}

RB_GENERATE_STATIC(unveil_node_tree, unveil_node, entry, unveil_node_cmp);

void
unveil_init(struct unveil_base *base)
{
	*base = (struct unveil_base){
		.root = RB_INITIALIZER(&base->root),
		.active = false,
		.finished = false,
	};
}

void
unveil_merge(struct unveil_base *dst, struct unveil_base *src)
{
	struct unveil_node *dst_node, *src_node;
	dst->active = src->active;
	dst->finished = src->finished;
	/* first pass, copy the nodes without cover links */
	RB_FOREACH(src_node, unveil_node_tree, &src->root) {
		dst_node = unveil_insert(dst, src_node->vp);
		dst_node->hard_perms = src_node->hard_perms;
		dst_node->soft_perms = src_node->soft_perms;
		dst_node->exec_perms = src_node->exec_perms;
	}
	/* second pass, fixup the cover links */
	RB_FOREACH(src_node, unveil_node_tree, &src->root) {
		if (!src_node->cover)
			continue;
		dst_node = unveil_lookup(dst, src_node->vp);
		KASSERT(dst_node, ("unveil node missing"));
		dst_node->cover = unveil_lookup(dst, src_node->cover->vp);
		KASSERT(dst_node->cover, ("cover unveil node missing"));
	}
}

static void
unveil_node_drop(struct unveil_base *base, struct unveil_node *node)
{
	RB_REMOVE(unveil_node_tree, &base->root, node);
	base->node_count--;
	vrele(node->vp);
	free(node, M_UNVEIL);
}

void
unveil_clear(struct unveil_base *base)
{
	struct unveil_node *node, *node_tmp;
	RB_FOREACH_SAFE(node, unveil_node_tree, &base->root, node_tmp)
	    unveil_node_drop(base, node);
	MPASS(base->node_count == 0);
}

void
unveil_free(struct unveil_base *base)
{
	unveil_clear(base);
}

struct unveil_node *
unveil_insert(struct unveil_base *base, struct vnode *vp)
{
	struct unveil_node *new, *old;
	new = malloc(sizeof *new, M_UNVEIL, M_WAITOK);
	*new = (struct unveil_node){
		.cover = NULL,
		.vp = vp,
		.hard_perms = UNVEIL_PERM_ALL,
	};
	old = RB_INSERT(unveil_node_tree, &base->root, new);
	if (old) {
		free(new, M_UNVEIL);
		new = old;
	} else {
		vref(vp);
		base->node_count++;
	}
	return (new);
}

struct unveil_node *
unveil_lookup(struct unveil_base *base, struct vnode *vp)
{
	struct unveil_node key = { .vp = vp };
	return (RB_FIND(unveil_node_tree, &base->root, &key));
}


void
unveil_fd_init(struct filedesc *fd)
{
	unveil_init(&fd->fd_unveil);
}

void
unveil_fd_merge(struct filedesc *dst_fdp, struct filedesc *src_fdp)
{
	unveil_merge(&dst_fdp->fd_unveil, &src_fdp->fd_unveil);
}

void
unveil_fd_free(struct filedesc *fdp)
{
	unveil_free(&fdp->fd_unveil);
}

void
unveil_proc_exec_switch(struct thread *td)
{
	struct filedesc *fdp = td->td_proc->p_fd;
	struct unveil_base *base = &fdp->fd_unveil;
	struct unveil_node *node, *node_tmp;
	RB_FOREACH_SAFE(node, unveil_node_tree, &base->root, node_tmp) {
		node->hard_perms = node->soft_perms = node->exec_perms;
		/*
		 * TODO: Allow to drop unneeded unveils that came from the
		 * parent process after exec rather than just masking them.
		 * Only unveils that do not cover any unveils that are to be
		 * kept should be dropped (since they can guard against
		 * escapes).  Right now dropping unveils is unsafe.
		 */
		node->from_exec = true;
	}
}


static inline void
update_node_perms(struct unveil_node *np, int flags,
    unveil_perms_t perms, unveil_perms_t execperms)
{
	if (flags & UNVEIL_FLAG_MASK) {
		np->soft_perms &= perms;
		np->exec_perms &= execperms;
	} else {
		np->from_exec = false;
		np->soft_perms = np->hard_perms & perms;
		/*
		 * exec_perms is allowed to be higher than hard_perms, but it
		 * can never be added permissions that aren't in hard_perms.
		 */
		np->exec_perms = (np->exec_perms | np->hard_perms) & execperms;
	}
	if (flags & UNVEIL_FLAG_HARDEN)
		np->hard_perms &= np->soft_perms;
}

static int
do_unveil(struct thread *td, int atfd, const char *path, int flags,
    unveil_perms_t perms, unveil_perms_t execperms)
{
	struct filedesc *fdp = td->td_proc->p_fd;
	struct unveil_base *base;
	struct unveil_node *node;
	struct nameidata nd;
	int error = 0;
	bool adding;

	/*
	 * TODO: Must keep the cwd's uperms up-to-date somehow.  Same with open
	 * directory FDs once they're made to remember their uperms.
	 */

	if ((adding = path != NULL)) {
		int nd_flags = LOCKLEAF;
		if (!(flags & UNVEIL_FLAG_NOFOLLOW))
			nd_flags |= FOLLOW;
		NDINIT_AT(&nd, LOOKUP, nd_flags, UIO_SYSSPACE, path, atfd, td);
		error = namei(&nd);
		if (error)
			return (error);
	}

	FILEDESC_XLOCK(fdp);
	base = &fdp->fd_unveil;

	if (adding) {
		node = unveil_lookup(base, nd.ni_vp);
		if (base->node_count >= unveil_max_nodes_per_process && !node) {
			error = E2BIG;
			goto out;
		}
		if (!(flags & UNVEIL_FLAG_MASK)) {
			unveil_perms_t limit;
			/*
			 * Restrict permissions of a newly added node to "hard"
			 * permissions of the last node that was encountered
			 * during traversal.  If the node was already present,
			 * permissions will be restricted against its own
			 * hard permissions.
			 */
			limit = nd.ni_unveil   ? nd.ni_unveil->hard_perms :
			        base->finished ? UNVEIL_PERM_NONE :
			                         UNVEIL_PERM_ALL ;
			if (perms & ~limit) {
				error = EPERM;
				goto out;
			}
			if (!node) {
				node = unveil_insert(base, nd.ni_vp);
				node->cover = nd.ni_unveil;
				node->hard_perms = limit;
			}
		}
		if (node)
			update_node_perms(node, flags, perms, execperms);
	}

	if (flags & UNVEIL_FLAG_FOR_ALL)
		RB_FOREACH(node, unveil_node_tree, &base->root)
			if (!(flags & UNVEIL_FLAG_FROM_EXEC) || node->from_exec)
				update_node_perms(node, flags, perms, execperms);

	if (flags & UNVEIL_FLAG_ACTIVATE)
		base->active = true;
	if (flags & UNVEIL_FLAG_FINISH)
		base->finished = true;

out:	FILEDESC_XUNLOCK(fdp);
	if (adding)
		NDFREE(&nd, 0);
	return (error);
}

#endif /* UNVEIL */

int
sys_unveilctl(struct thread *td, struct unveilctl_args *uap)
{
#ifdef UNVEIL
	char *path;
	int error;
	if (uap->path) {
		path = malloc(MAXPATHLEN, M_TEMP, M_WAITOK);
		error = copyinstr(uap->path, path, MAXPATHLEN, NULL);
		if (error) {
			free(path, M_TEMP);
			return (error);
		}
	} else
		path = NULL;
	error = do_unveil(td, uap->atfd, path, uap->flags,
	    uap->perms, uap->execperms);
	if (path)
		free(path, M_TEMP);
	return (error);
#else
	return (ENOSYS);
#endif /* UNVEIL */
}
