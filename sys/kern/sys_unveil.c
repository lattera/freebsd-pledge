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
#include <sys/pledge.h>
#include <sys/unveil.h>

#ifdef PLEDGE

MALLOC_DEFINE(M_VEIL, "veil", "Veil path filter nodes");

static size_t veil_max_nodes = 100; /* TODO: sysctl? */

static void
veil_check(struct veil *veil)
{
	struct veil_node *node;
	if ((node = veil->root)) {
		KASSERT(!node->parent, ("veil root node parent set"));
		KASSERT(!node->sibling, ("veil root node sibling set"));
		KASSERT(!node->name[0], ("veil root node name set"));
	}
}

static struct veil_node *
veil_lookup(struct veil *veil, const char **path_ret)
{
	struct veil_node *matched_node, *node, *parent_node;
	const char *matched_path, *path;
	veil_check(veil);
	node = matched_node = veil->root;
	path = matched_path = *path_ret;
	while (node) {
		while (*path == '/')
			path++;
		if (!*path)
			break;
		if (path[0] == '.') {
			if (!path[1] || path[1] == '/') {
				path++;
				continue;
			} else if (path[2] == '.') {
				if (!path[3] || path[3] == '/') {
					path += 2;
					node = node->parent;
					matched_node = node;
					matched_path = path;
					continue;
				}
			}
		}
		parent_node = node;
		for (node = node->children; node; node = node->sibling) {
			const char *p, *q;
			KASSERT(node->parent == parent_node,
			        ("veil node parent mismatch"));
			for (p = node->name, q = p; *p && *p == *q; p++, q++);
			if (!*q || *q == '/') {
				path = q;
				matched_node = node;
				matched_path = path;
				break;
			}
		}
	}
	if (matched_path)
		*path_ret = matched_path;
	return (matched_node);

}

static struct veil_node *
veil_insert(struct veil *veil, const char *path)
{
	struct veil_node **link, *parent;
	const char *path_next;
	veil_check(veil);
	parent = NULL;
	link = &veil->root;
	path_next = path;
	while (true) {
		KASSERT(path_next >= path, ("path_next got behind path"));
		if (!*link) {
			struct veil_node *node;
			size_t n = path_next - path;
			node = malloc(sizeof *node + n + 1, M_VEIL, M_WAITOK);
			*node = (struct veil_node){
				.parent = parent,
				.next = veil->list,
			};
			memcpy(node->name, path, n);
			node->name[n] = '\0';
			veil->list = node;
			*link = node;
		}
		while (*path_next == '/')
			path_next++;
		if (!*path_next)
			break;
		path = path_next;
		/* TODO: handle "." and ".." here too */
		parent = *link;
		link = &(*link)->children;
		while (true) {
			if (*link) {
				KASSERT((*link)->parent == parent,
					("veil node parent mismatch"));
				const char *p, *q;
				for (p = path, q = (*link)->name;
				    *p && *p == *q;
				    p++, q++);
				if (!*p || *p == '/') {
					path_next = p;
					parent = *link;
					link = &(*link)->children;
					break;
				}
				link = &(*link)->sibling;
			} else {
				while (*path_next && *path_next != '/')
					path_next++;
				break;
			}
		}
	}
	veil->node_count++;
	return (*link);
}

void
veil_copy(struct veil *dst, const struct veil *src)
{
	veil_init(dst); /* XXX */
}

void
veil_free(struct veil *veil)
{
	struct veil_node *node, *next;
	for (node = veil->list; node; node = next) {
		next = node->next;
		free(node, M_TEMP);
	}
}

#endif /* PLEDGE */

int
sys_unveil(struct thread *td, struct unveil_args *uap)
{
#ifdef PLEDGE
	struct veil *veil = &td->td_proc->p_fd->fd_veil;
	struct veil_node *node;
	char *path = NULL;
	int error;
	if (veil->node_count >= veil_max_nodes)
		return (ENFILE);
	path = malloc(MAXPATHLEN, M_TEMP, M_WAITOK);
	error = copyinstr(uap->path, path, MAXPATHLEN, NULL);
	if (error)
		goto error;
	node = veil_insert(veil, path);
	printf("pid %d (%s) unveil \"%s\"\n",
	    td->td_proc->p_pid, td->td_proc->p_comm,
	    path);
error:
	if (path)
		free(path, M_TEMP);
	return (error);
#else
	return (ENOSYS);
#endif /* PLEDGE */
}
