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

#ifdef PLEDGE

MALLOC_DEFINE(M_UNVEIL, "unveil", "unveil");

static u_int unveil_max_nodes = 100; /* TODO: sysctl? */

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
		.implicit_perms = UNVEIL_PERM_ALL,
		.implicit_frozen_perms = UNVEIL_PERM_ALL,
	};
}

void
unveil_merge(struct unveil_base *dst, struct unveil_base *src)
{
	struct unveil_node *dst_node, *src_node;
	dst->implicit_perms = src->implicit_perms;
	dst->implicit_frozen_perms = src->implicit_frozen_perms;
	/* first pass, copy the nodes without cover links */
	RB_FOREACH(src_node, unveil_node_tree, &src->root) {
		dst_node = unveil_insert(dst, NULL, src_node->vp);
		dst_node->frozen_perms = src_node->frozen_perms;
		dst_node->regular_perms = src_node->regular_perms;
		dst_node->special_perms = src_node->special_perms;
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

void
unveil_clear(struct unveil_base *base)
{
	struct unveil_node *node, *node_tmp;
	RB_FOREACH_SAFE(node, unveil_node_tree, &base->root, node_tmp) {
		vrele(node->vp);
		RB_REMOVE(unveil_node_tree, &base->root, node);
		base->node_count--;
		free(node, M_UNVEIL);
	}
	MPASS(base->node_count == 0);
}

void
unveil_free(struct unveil_base *base)
{
	unveil_clear(base);
}

struct unveil_node *
unveil_insert(struct unveil_base *base,
    struct unveil_node *cover, struct vnode *vp)
{
	struct unveil_node *new, *old;
	new = malloc(sizeof *new, M_UNVEIL, M_WAITOK);
	*new = (struct unveil_node){
		.cover = cover,
		.vp = vp,
		.frozen_perms = UNVEIL_PERM_ALL,
		.regular_perms = UNVEIL_PERM_NONE,
		.special_perms = UNVEIL_PERM_NONE,
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
	fd->fd_unveil_exec = NULL;
}

void
unveil_fd_merge(struct filedesc *dst_fdp, struct filedesc *src_fdp)
{
	unveil_merge(&dst_fdp->fd_unveil, &src_fdp->fd_unveil);
	if (src_fdp->fd_unveil_exec) {
		if (!dst_fdp->fd_unveil_exec) {
			dst_fdp->fd_unveil_exec = malloc(
			    sizeof *dst_fdp->fd_unveil_exec, M_UNVEIL, M_WAITOK);
			unveil_init(dst_fdp->fd_unveil_exec);
		}
		unveil_merge(dst_fdp->fd_unveil_exec, src_fdp->fd_unveil_exec);
	}
}

void
unveil_fd_free(struct filedesc *fdp)
{
	unveil_free(&fdp->fd_unveil);
	if (fdp->fd_unveil_exec) {
		unveil_free(fdp->fd_unveil_exec);
		free(fdp->fd_unveil_exec, M_UNVEIL);
		fdp->fd_unveil_exec = NULL;
	}
}

void
unveil_proc_exec_switch(struct thread *td)
{
	struct filedesc *fdp = td->td_proc->p_fd;
	unveil_clear(&fdp->fd_unveil);
	if (fdp->fd_unveil_exec)
		unveil_merge(&fdp->fd_unveil, fdp->fd_unveil_exec);
}


static int
do_unveil(struct thread *td, int atfd, const char *path, int flags,
    unveil_perms_t perms)
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

	if (!(flags & UNVEIL_FLAG_SPECIAL))
		flags |= UNVEIL_FLAG_REGULAR;

	if ((adding = path != NULL)) {
		int nd_flags = LOCKLEAF;
		if (!(flags & UNVEIL_FLAG_NOFOLLOW))
			nd_flags |= FOLLOW;
		NDINIT_AT(&nd, LOOKUP, nd_flags, UIO_SYSSPACE, path, atfd, td);
		/*
		 * XXX: For-execute unveils probably should be checked against
		 * the current-process unveils.
		 */
		if (flags & UNVEIL_FLAG_FOR_EXEC)
			nd.ni_uflags |= NIUNV_EXECBASE;
		error = namei(&nd);
		if (error)
			return (error);
	}

	FILEDESC_XLOCK(fdp);

	if (flags & UNVEIL_FLAG_FOR_EXEC) {
		if (!(base = fdp->fd_unveil_exec)) {
			base = malloc(sizeof *base, M_UNVEIL, M_WAITOK);
			unveil_init(base);
			fdp->fd_unveil_exec = base;
		}
	} else
		base = &fdp->fd_unveil;

	node = NULL;
	if (adding) {
		unveil_perms_t limit;
		if (base->node_count >= unveil_max_nodes) {
			if (!(node = unveil_lookup(base, nd.ni_vp))) {
				error = E2BIG;
				goto out;
			}
		}
		if (!node)
			node = unveil_insert(base, nd.ni_unveil, nd.ni_vp);
		if (nd.ni_unveil)
			/*
			 * Restrict permissions of a newly added node to
			 * "frozen" permissions of the last node that was
			 * encountered during traversal.  If the node was
			 * already present, permissions will be restricted to
			 * its own frozen permissions.
			 */
			limit = nd.ni_unveil->frozen_perms;
		else
			/* XXX: Wrong for FD-relative unveils. */
			limit = base->implicit_frozen_perms;
		if (perms & ~limit) {
			error = EPERM;
			goto out;
		}
		/*
		 * Unveils have multiple sets of permissions to help
		 * implementing the userland pledge() wrapper.  The "special"
		 * permissions will be those that were done for the pledge
		 * promises that require unveils, while the "regular"
		 * permissions will be for unveils done directly by the user.
		 * The "effective" permissions of a node is their union.  These
		 * permissions may be modified, but are limited by the node's
		 * "frozen" permissions.
		 */
		if (flags & UNVEIL_FLAG_REGULAR)
			node->regular_perms = perms & limit;
		if (flags & UNVEIL_FLAG_SPECIAL)
			node->special_perms = perms & limit;
		node->frozen_perms &= limit; /* for newly-added nodes */
		if (flags & UNVEIL_FLAG_FREEZE)
			node->frozen_perms &= unveil_node_perms(node);
#if 0
		printf("pid %d (%s) unveil \"%s\" %#x: %p cover %p\n",
		    td->td_proc->p_pid, td->td_proc->p_comm, path, perms, node, node->cover);
#endif
	}

	if (flags & UNVEIL_FLAG_IMPLICIT) {
		if (flags & UNVEIL_FLAG_MASK)
			base->implicit_perms &= perms;
		if (flags & (UNVEIL_FLAG_FREEZE))
			base->implicit_frozen_perms &= base->implicit_perms;
	}

	if (flags & UNVEIL_FLAG_FOR_ALL) {
		/*
		 * This was specifically designed to allow the userland
		 * pledge() wrapper to restrict filesystem access while keeping
		 * the unveils that were done for pledge promises working.
		 */
		RB_FOREACH(node, unveil_node_tree, &base->root) {
			if (flags & UNVEIL_FLAG_MASK) {
				if (flags & UNVEIL_FLAG_REGULAR)
					node->regular_perms &= perms;
				if (flags & UNVEIL_FLAG_SPECIAL)
					node->special_perms &= perms;
			}
			if (flags & UNVEIL_FLAG_FREEZE)
				node->frozen_perms &= unveil_node_perms(node);
		}
		node = NULL;
	}

out:	FILEDESC_XUNLOCK(fdp);
	if (adding)
		NDFREE(&nd, 0);
	return (error);
}

#endif /* PLEDGE */

int
sys_unveilctl(struct thread *td, struct unveilctl_args *uap)
{
#ifdef PLEDGE
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
	error = do_unveil(td, uap->atfd, path, uap->flags, uap->perms);
	if (path)
		free(path, M_TEMP);
	return (error);
#else
	return (ENOSYS);
#endif /* PLEDGE */
}
