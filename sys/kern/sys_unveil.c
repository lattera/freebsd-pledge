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
#include <sys/pledge.h>
#include <sys/unveil.h>

#ifdef PLEDGE

MALLOC_DEFINE(M_UNVEIL, "unveil", "unveil");

static u_int unveil_max_nodes = 100; /* TODO: sysctl? */

static int
unveil_dir_node_cmp(struct unveil_node *a, struct unveil_node *b)
{
	uintptr_t ak = (uintptr_t)a->vp, bk = (uintptr_t)b->vp;
	return (ak > bk ? 1 : ak < bk ? -1 : 0);
}

RB_GENERATE_STATIC(unveil_dir_tree, unveil_node, entry, unveil_dir_node_cmp);

void
unveil_merge(struct unveil_base *dst, struct unveil_base *src)
{
	/* TODO */
}

void
unveil_destroy(struct unveil_base *base)
{
	struct unveil_node *node, *node_tmp;
	RB_FOREACH_SAFE(node, unveil_dir_tree, &base->dir_root, node_tmp) {
		vrele(node->vp);
		RB_REMOVE(unveil_dir_tree, &base->dir_root, node);
		base->dir_count--;
		free(node, M_UNVEIL);
	}
	MPASS(base->dir_count == 0);
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
	};
	old = RB_INSERT(unveil_dir_tree, &base->dir_root, new);
	if (old) {
		free(new, M_UNVEIL);
		return (old);
	}
	vref(vp);
	base->dir_count++;
	return (new);
}

struct unveil_node *
unveil_lookup(struct unveil_base *base, struct vnode *vp)
{
	struct unveil_node key = { .vp = vp };
	return (RB_FIND(unveil_dir_tree, &base->dir_root, &key));
}

static int
do_unveil(struct thread *td, const char *path, unveil_perms_t perms)
{
	struct filedesc *fdp = td->td_proc->p_fd;
	struct unveil_base *base = &fdp->fd_unveil;
	struct unveil_node *node;
	struct nameidata nd;
	int error;

	FILEDESC_SLOCK(fdp);
	if (base->finished)
		error = EPERM;
	else if (base->dir_count >= unveil_max_nodes)
		error = E2BIG;
	else
		error = 0;
	FILEDESC_SUNLOCK(fdp);
	if (error)
		return (error);

	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_SYSSPACE, path, td);
	error = namei(&nd);
	if (error)
		return (error);

	FILEDESC_XLOCK(fdp);
	node = unveil_insert(base, nd.ni_unveil, nd.ni_vp);
	node->perms = perms; /* TODO: check previous permissions */
	FILEDESC_XUNLOCK(fdp);

	NDFREE(&nd, 0);
	printf("pid %d (%s) unveil \"%s\" %#x: %p cover %p\n",
	    td->td_proc->p_pid, td->td_proc->p_comm, path, perms, node, node->cover);
	return (error);
}

static void
do_unveil_finished(struct thread *td)
{
	struct filedesc *fdp = td->td_proc->p_fd;
	FILEDESC_XLOCK(fdp);
	fdp->fd_unveil.finished = true;
	FILEDESC_XUNLOCK(fdp);
}

static int
unveil_parse_perms(unveil_perms_t *perms, const char *s)
{
	while (*s)
		switch (*s++) {
		case 'r': *perms |= UNVEIL_PERM_RPATH; break;
		case 'w': *perms |= UNVEIL_PERM_WPATH; break;
		case 'c': *perms |= UNVEIL_PERM_CPATH; break;
		case 'x': *perms |= UNVEIL_PERM_EXEC;  break;
		default:
			  return (EINVAL);
		}
	return (0);
}

#endif /* PLEDGE */

int
sys_unveil(struct thread *td, struct unveil_args *uap)
{
#ifdef PLEDGE
	char *path, *permissions;
	unveil_perms_t perms;
	int error;

	if (!uap->path && !uap->permissions) {
		do_unveil_finished(td);
		return (0);
	}

	permissions = malloc(MAXPATHLEN, M_TEMP, M_WAITOK);
	error = copyinstr(uap->permissions, permissions, MAXPATHLEN, NULL);
	if (error) {
		free(permissions, M_TEMP);
		return (error);
	}
	perms = 0;
	error = unveil_parse_perms(&perms, permissions);
	free(permissions, M_TEMP);
	if (error)
		return (error);

	path = malloc(MAXPATHLEN, M_TEMP, M_WAITOK);
	error = copyinstr(uap->path, path, MAXPATHLEN, NULL);
	if (error) {
		free(path, M_TEMP);
		return (error);
	}
	error = do_unveil(td, path, perms);
	free(path, M_TEMP);
	return (error);
#else
	return (ENOSYS);
#endif /* PLEDGE */
}
