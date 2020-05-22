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

/* TODO: global on/off switch for unveil support */

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
	};
}

static struct unveil_node *
find_non_ghost_cover(struct unveil_node *node)
{
	do {
		if (!node->ghost)
			return (node);
	} while ((node = node->cover));
	return (NULL);
}

unveil_perms_t
unveil_node_effective_perms(struct unveil_node *node)
{
	struct unveil_node *parent;
	if ((parent = find_non_ghost_cover(node)))
		return (parent->curr_want_perms & node->curr_hard_perms);
	return (UNVEIL_PERM_NONE);
}

static void
unveil_node_harden_perms(struct unveil_node *node,
    unveil_perms_t curr_keep_perms, unveil_perms_t exec_keep_perms)
{
	struct unveil_node *parent;
	if ((parent = find_non_ghost_cover(node))) {
		curr_keep_perms |= parent->curr_want_perms;
		exec_keep_perms |= parent->exec_want_perms;
	}
	node->curr_hard_perms &= curr_keep_perms;
	node->exec_hard_perms &= exec_keep_perms;
}

static void
unveil_node_ghost(struct unveil_node *node)
{
	node->ghost = true;
	node->curr_want_perms = node->exec_want_perms = UNVEIL_PERM_NONE;
}

static void
unveil_node_unghost(struct unveil_node *node)
{
	struct unveil_node *parent;
	parent = find_non_ghost_cover(node);
	node->curr_want_perms = parent ? parent->curr_want_perms : UNVEIL_PERM_NONE;
	node->exec_want_perms = parent ? parent->exec_want_perms : UNVEIL_PERM_NONE;
	node->ghost = false;
}


void
unveil_merge(struct unveil_base *dst, struct unveil_base *src)
{
	struct unveil_node *dst_node, *src_node;
	dst->active = src->active;
	/* first pass, copy the nodes without cover links */
	RB_FOREACH(src_node, unveil_node_tree, &src->root) {
		dst_node = unveil_insert(dst, src_node->vp, NULL);
		dst_node->ghost = src_node->ghost;
		dst_node->curr_want_perms = src_node->curr_want_perms;
		dst_node->curr_hard_perms = src_node->curr_hard_perms;
		dst_node->exec_want_perms = src_node->exec_want_perms;
		dst_node->exec_hard_perms = src_node->exec_hard_perms;
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
unveil_node_remove(struct unveil_base *base, struct unveil_node *node)
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
	    unveil_node_remove(base, node);
	MPASS(base->node_count == 0);
}

void
unveil_free(struct unveil_base *base)
{
	unveil_clear(base);
}

struct unveil_node *
unveil_insert(struct unveil_base *base, struct vnode *vp, struct unveil_node *cover)
{
	struct unveil_node *new, *old;
	new = malloc(sizeof *new, M_UNVEIL, M_WAITOK);
	*new = (struct unveil_node){
		.cover = cover,
		.vp = vp,
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
		unveil_node_harden_perms(node, UNVEIL_PERM_NONE, UNVEIL_PERM_NONE);
		unveil_node_unghost(node);
		node->curr_want_perms = node->exec_want_perms;
		node->curr_hard_perms = node->exec_hard_perms;
	}
}

static int
do_unveil_add(struct unveil_base *base, int flags,
    unveil_perms_t curr_perms, unveil_perms_t exec_perms,
    struct vnode *vp, struct unveil_node *cover)
{
	unveil_perms_t curr_limit, exec_limit;
	struct unveil_node *node;
	node = cover && cover->vp == vp ? cover : NULL;
	if (base->node_count >= unveil_max_nodes_per_process && !node)
		return (E2BIG);

	if (cover) {
		curr_limit = cover->curr_hard_perms;
		exec_limit = cover->exec_hard_perms;
	} else
		curr_limit = exec_limit = base->active ? UNVEIL_PERM_NONE
		                                       : UNVEIL_PERM_ALL;
	if (node) {
		node->ghost = false;
	} else {
		node = unveil_insert(base, vp, cover);
		node->curr_hard_perms = curr_limit;
		node->exec_hard_perms = exec_limit;
	}
	node->curr_want_perms = curr_perms;
	node->exec_want_perms = exec_perms;
	return (0);
}

static int
do_unveil(struct thread *td, int atfd, const char *path, int flags,
    unveil_perms_t curr_perms, unveil_perms_t exec_perms)
{
	struct filedesc *fdp = td->td_proc->p_fd;
	struct unveil_base *base;
	struct nameidata nd;
	int error = 0;
	bool adding;

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
		if (flags & (UNVEIL_FLAG_SWEEP|UNVEIL_FLAG_RESTRICT)) {
			error = EINVAL;
			goto out;
		}
		error = do_unveil_add(base, flags, curr_perms, exec_perms,
		    nd.ni_vp, nd.ni_unveil);
		if (error)
			goto out;
		base->active = true;
	} else {
		struct unveil_node *node;
		if (flags & UNVEIL_FLAG_RESTRICT)
			RB_FOREACH(node, unveil_node_tree, &base->root)
				unveil_node_harden_perms(node, curr_perms, exec_perms);
		if (flags & UNVEIL_FLAG_SWEEP)
			RB_FOREACH(node, unveil_node_tree, &base->root)
				unveil_node_ghost(node);
	}

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
