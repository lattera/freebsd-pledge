#include <assert.h>
#include <curtain.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <paths.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/unveil.h>
#include <sys/param.h>
#include <sysexits.h>
#include <unistd.h>

#include "common.h"
#include "pathexp.h"

struct parser {
	struct curtain_config *cfg;
	FILE *file;
	const char *file_name;
	off_t line_no;
	char *line;
	size_t line_size;
	bool apply;
	bool skip;
	bool matched;
	bool visited;
	bool error;
	struct curtain_slot *slot;
	char *last_matched_section_path;
	size_t section_path_offset;
	int directive_flags;
	bool explicit_flags;
	unveil_perms uperms;
	bool unveil_create;
	void *unveil_setmode;
	char unveil_pending[PATH_MAX];
};

static const struct {
	const char name[16];
	const unsigned long *ioctls;
} ioctls_bundles[] = {
	{ "tty_basic", curtain_ioctls_tty_basic },
	{ "tty_pts", curtain_ioctls_tty_pts },
	{ "net_basic", curtain_ioctls_net_basic },
	{ "net_route", curtain_ioctls_net_route },
	{ "oss", curtain_ioctls_oss },
	{ "cryptodev", curtain_ioctls_cryptodev },
	{ "bpf", curtain_ioctls_bpf_all },
};


int
curtain_parse_unveil_perms(unveil_perms *uperms, const char *s)
{
	*uperms = UPERM_NONE;
	while (*s)
		switch (*s++) {
		case 'l': *uperms |= UPERM_LIST; break;
		case 'b': *uperms |= UPERM_BROWSE; break;
		case 'r': *uperms |= UPERM_READ; break;
		case 'p': *uperms |= UPERM_APPEND; break;
		case 'm': *uperms |= UPERM_WRITE; break;
		case 'w': *uperms |= UPERM_WRITE | UPERM_SETATTR |
		                     UPERM_CREATE | UPERM_DELETE; break;
		case 'a': *uperms |= UPERM_SETATTR; break;
		case 'c': *uperms |= UPERM_CREATE | UPERM_DELETE; break;
		case 'x': *uperms |= UPERM_EXECUTE; break;
		case 'i': *uperms |= UPERM_INSPECT; break;
		case 't': *uperms |= UPERM_TMPDIR; break;
		case 'u': *uperms |= UPERM_UNIX; break;
		case 'D': *uperms |= UPERM_DEVFS; break;
		default:
			return (-1);
		}
	return (0);
}


static void
pathfmt(char *path, const char *fmt, ...)
{
	int r;
	va_list ap;
	va_start(ap, fmt);
	r = vsnprintf(path, PATH_MAX, fmt, ap);
	va_end(ap);
	if (r < 0)
		err(EX_TEMPFAIL, "snprintf");
}

static int
strmemcmp(const char *s, const char *b, size_t n)
{
	while (*s && n) {
		if (*s != *b)
			return ((unsigned)*s - (unsigned)*b);
		s++, b++, n--;
	}
	return (n ? -1 : *s ? 1 : 0);
}


static struct curtain_config_tag *
curtain_config_tag_find_mem(struct curtain_config *cfg, const char *buf, size_t len)
{
	struct curtain_config_tag *tag;
	for (tag = cfg->tags_pending; tag; tag = tag->chain)
		if (strmemcmp(tag->name, buf, len) == 0)
			break;
	return (tag);
}

struct curtain_config_tag *
curtain_config_tag_push_mem(struct curtain_config *cfg, const char *buf, size_t len)
{
	struct curtain_config_tag *tag;
	tag = curtain_config_tag_find_mem(cfg, buf, len);
	if (tag)
		return (tag);
	tag = malloc(sizeof *tag + len + 1);
	if (!tag)
		err(EX_TEMPFAIL, "malloc");
	*tag = (struct curtain_config_tag){
		.chain = cfg->tags_pending,
	};
	memcpy(tag->name, buf, len);
	tag->name[len] = '\0';
	cfg->tags_pending = tag;
	return (tag);
}

struct curtain_config_tag *
curtain_config_tag_block_mem(struct curtain_config *cfg, const char *buf, size_t len)
{
	struct curtain_config_tag *tag;
	tag = curtain_config_tag_push_mem(cfg, buf, len);
	if (tag)
		tag->blocked = true;
	return (tag);
}


static void
need_slot(struct parser *par)
{
	if (!par->slot) {
		if (par->cfg->on_exec_only)
			curtain_enable((par->slot = curtain_slot_neutral()), CURTAIN_ON_EXEC);
		else
			par->slot = curtain_slot();
	}
}

static void
parse_error(struct parser *par, const char *error)
{
	par->error = true;
	warnx("%s:%ju: %s", par->file_name, (uintmax_t)par->line_no, error);
}

#define	SPACE_CASES \
	case ' ': \
	case '\t': \
	case '\n': \
	case '\r': \
	case '\f': \
	case '\v':

static inline bool
is_space(char c)
{
	switch (c) {
	SPACE_CASES
		return (true);
	default:
		return (false);
	}
}

static inline char *
skip_spaces(char *p)
{
next:	switch (*p) {
	case '#':
		do {
			p++;
		} while (*p);
		/* FALLTHROUGH */
	case '\0':
		break;
	SPACE_CASES
		p++;
		goto next;
	}
	return (p);
}

static inline char *
skip_word(char *p, const char *brk)
{
	while (*p) {
		if (*p == '\\') {
			p++;
			if (!*p)
				break;
		} else if (is_space(*p) || strchr(brk, *p))
			break;
		p++;
	}
	return (p);
}


static int process_file(struct curtain_config *, const char *path);
static void process_dir(struct curtain_config *, const char *path);

struct word {
	struct word *next;
	char *ptr;
	size_t len;
};

static void
parse_words_1(struct parser *par, char *p,
    struct word **head, struct word **link,
    void (*fin)(struct parser *, struct word *))
{
	if (*(p = skip_spaces(p))) {
		char *q;
		struct word w;
		q = skip_word(p, "");
		if (q == p)
			return (parse_error(par, "invalid word"));
		w.ptr = p;
		w.len = q - p;
		if (*q)
			*q++ = '\0';
		*link = &w;
		return (parse_words_1(par, q, head, &w.next, fin));
	}
	*link = NULL;
	return (fin(par, *head));
}

static void
parse_words(struct parser *par, char *p,
    void (*fin)(struct parser *, struct word *))
{
	struct word *list;
	return (parse_words_1(par, p, &list, &list, fin));
}

static int
do_include_callback(void *ctx, char *path)
{
	struct parser *par = ctx;
	if (*path) {
		if (path[0] == '/') {
			if (path[strlen(path) - 1] == '/')
				process_dir(par->cfg, path);
			else
				process_file(par->cfg, path);
		} else
			parse_error(par, "include path must be absolute");
	}
	return (0);
}

static void
parse_include(struct parser *par, struct word *w)
{
	while (w) {
		if (par->apply) {
			char path[PATH_MAX];
			const char *error;
			int r;
			r = pathexp(w->ptr, path, sizeof path,
			    &error, do_include_callback, par);
			if (r < 0)
				parse_error(par, error);
		}
		w = w->next;
	}
}

static void
parse_push(struct parser *par, struct word *w)
{
	while (w) {
		if (par->apply)
			curtain_config_tag_push_mem(par->cfg, w->ptr, w->len);
		w = w->next;
	}
}

static int
do_unveil(struct parser *par, const char *path)
{
	size_t len;
	int flags, r;
	bool is_dir;
	flags = par->directive_flags;
	len = strlen(path);
	/*
	 * Do not follow symlinks on the final path component of the unveil
	 * (thus unveiling symlinks themselves rather than their targets) when
	 * the path could be a symlink created by the sandboxed application.
	 *
	 * When the path ends with '/', the unveil target will necessarily be
	 * an existing directory.  The directory can be deleted by the
	 * application, but since directory unveils are associated directly
	 * with the directory vnode (and not its name in the parent directory),
	 * the application will not be allowed to replace it with a symlink.
	 */
	is_dir = len && path[len - 1] == '/';
	if (par->uperms & UPERM_CREATE && !is_dir)
		flags |= CURTAIN_UNVEIL_NOFOLLOW;

	r = curtain_unveil(par->slot, path, flags, par->uperms);
	if (par->unveil_create) {
		if (!is_dir) {
			struct stat st;
			r = stat(path, &st);
		}
		if (r < 0) {
			if (errno == ENOENT && !*par->unveil_pending)
				memcpy(par->unveil_pending, path, len + 1);
		} else {
			par->unveil_create = false;
			*par->unveil_pending = '\0';
		}
	}
	return (r);
}

static int
do_unveil_callback(void *ctx, char *path)
{
	struct parser *par = ctx;
	if (path[0] && path[0] != '/' && par->last_matched_section_path)
		path -= par->section_path_offset;
	do_unveil(par, path);
	return (0);
}

static void
do_unveils(struct parser *par, const char *pattern)
{
	char buf[PATH_MAX*2];
	size_t n;
	int r;
	const char *error;
	if (par->last_matched_section_path) {
		n = strlen(par->last_matched_section_path);
		if (n >= PATH_MAX)
			abort();
		memcpy(buf, par->last_matched_section_path, n);
		if (!n || buf[n - 1] != '/')
			buf[n++] = '/';
		par->section_path_offset = n;
	} else
		n = 0;
	r = pathexp(pattern, buf + n, PATH_MAX, &error, do_unveil_callback, par);
	if (r < 0)
		parse_error(par, error);
}

static void
do_unveil_pending(struct parser *par)
{
	char *path, *next, delim;
	struct stat st;
	bool created;
	int r;
	path = par->unveil_pending;
	if (!*path)
		return;
	next = path;
	do {
		created = false;
		next = strchrnul(next, '/');
		delim = *next;
		*next = '\0';
		if (delim == '/') {
			r = mkdir(*path ? path : "/", S_IRWXU | S_IRWXG | S_IRWXO);
			if (r >= 0)
				created = true;
			else if (errno == EISDIR || errno == EEXIST)
				r = 0;
		} else {
			r = open(path, O_WRONLY | O_CREAT | O_EXCL, DEFFILEMODE);
			if ((created = r >= 0))
				close(r);
			else if (errno == EEXIST)
				r = 0;
		}
		if (r < 0)
			break;
		*next = delim;
		while (*next == '/')
			next++;
	} while (*next);
	if (created) {
		if (par->cfg->verbosity >= 1)
			fprintf(stderr, "%s: %s:%ju: created path: %s\n",
			    getprogname(), par->file_name, (uintmax_t)par->line_no,
			    path);
		r = stat(path, &st);
		if (r >= 0)
			r = chmod(path, getmode(par->unveil_setmode, st.st_mode));
	}
	if (r < 0)
		warn("%s", path);
	else
		do_unveil(par, path);
	*next = delim;
}

static void
parse_unveil(struct parser *par, struct word *w)
{
	struct word *patterns, *patterns_end;
	int r;
	patterns = w;
	par->unveil_create = false;
	par->unveil_setmode = NULL;
	*par->unveil_pending = '\0';
	par->uperms = UPERM_READ;
	while (w && !(w->len == 1 && w->ptr[0] == ':'))
		w = w->next;
	patterns_end = w;
	if (w) {
		par->uperms = UPERM_NONE;
		if ((w = w->next)) {
			r = curtain_parse_unveil_perms(&par->uperms, w->ptr);
			if (r < 0)
				return (parse_error(par, "invalid unveil permissions"));
			w = w->next;
		}
	}
	if (w) {
		par->unveil_create = true;
		par->unveil_setmode = setmode(w->ptr);
		if (!par->unveil_setmode) {
			if (errno == EINVAL || errno == ERANGE)
				return (parse_error(par, "invalid creation mode"));
			else
				err(errno == ENOMEM ? EX_TEMPFAIL : EX_OSERR, "setmode");
		}
		w = w->next;
	}
	if (w) {
		free(par->unveil_setmode);
		return (parse_error(par, "unexpected word"));
	}
	if (par->apply) {
		while (patterns != patterns_end) {
			do_unveils(par, patterns->ptr);
			patterns = patterns->next;
		}
		if (*par->unveil_pending)
			do_unveil_pending(par);
	}
	free(par->unveil_setmode);
}

static void
parse_ability(struct parser *par, struct word *w)
{
	while (w) {
		const struct abilityent *e;
		for (e = curtain_abilitytab; e->name; e++)
			if (strmemcmp(e->name, w->ptr, w->len) == 0)
				break;
		if (!e->name)
			parse_error(par, "unknown ability");
		else if (par->apply)
			curtain_ability(par->slot, e->ability, par->directive_flags);
		w = w->next;
	}
}

static void
parse_sysctl(struct parser *par, struct word *w)
{
	while (w) {
		if (par->apply)
			curtain_sysctl(par->slot, w->ptr, par->directive_flags);
		w = w->next;
	}
}

static void
parse_priv(struct parser *par, struct word *w)
{
	while (w) {
		const struct privent *e;
		for (e = curtain_privtab; e->name; e++)
			if (strmemcmp(e->name, w->ptr, w->len) == 0)
				break;
		if (!e->name)
			parse_error(par, "unknown privilege");
		else if (par->apply)
			curtain_priv(par->slot, e->priv, par->directive_flags);
		w = w->next;
	}
}

static void
parse_ioctls(struct parser *par, struct word *w)
{
	while (w) {
		if (w->ptr[0] >= '0' && w->ptr[0] <= '9') {
			unsigned long n;
			char *end;
			errno = 0;
			n = strtoul(w->ptr, &end, 0);
			if (errno || *end)
				parse_error(par, "invalid ioctl");
			else if (par->apply)
				curtain_ioctl(par->slot, n, par->directive_flags);
		} else {
			const unsigned long *bundle;
			bundle = NULL;
			for (size_t i = 0; i < nitems(ioctls_bundles); i++)
				if (strmemcmp(ioctls_bundles[i].name, w->ptr, w->len) == 0) {
					bundle = ioctls_bundles[i].ioctls;
					break;
				}
			if (!bundle)
				parse_error(par, "unknown ioctl bundle");
			else if (par->apply)
				curtain_ioctls(par->slot, bundle, par->directive_flags);
		}
		w = w->next;
	}
}

static void
parse_sockaf(struct parser *par, struct word *w)
{
	while (w) {
		const struct sockafent *e;
		for (e = curtain_sockaftab; e->name; e++)
			if (strmemcmp(e->name, w->ptr, w->len) == 0)
				break;
		if (!e->name)
			parse_error(par, "unknown address family");
		else if (par->apply)
			curtain_sockaf(par->slot, e->sockaf, par->directive_flags);
		w = w->next;
	}
}

static void
parse_socklvl(struct parser *par, struct word *w)
{
	while (w) {
		const struct socklvlent *e;
		for (e = curtain_socklvltab; e->name; e++)
			if (strmemcmp(e->name, w->ptr, w->len) == 0)
				break;
		if (!e->name)
			parse_error(par, "unknown socket level");
		else if (par->apply)
			curtain_socklvl(par->slot, e->socklvl, par->directive_flags);
		w = w->next;
	}
}

static void
parse_fibnum(struct parser *par, struct word *w)
{
	while (w) {
		long n;
		char *end;
		errno = 0;
		n = strtol(w->ptr, &end, 0);
		if (errno || *end)
			parse_error(par, "invalid fibnum");
		else if (par->apply)
			curtain_fibnum(par->slot, n, par->directive_flags);
		w = w->next;
	}
}

static void
parse_default(struct parser *par, struct word *w)
{
	if (w)
		return (parse_error(par, "unexpected word"));
	if (!par->explicit_flags)
		return (parse_error(par, "expected flags"));
	curtain_default(par->slot, par->directive_flags);
}

static const int path_flags = CURTAIN_UNVEIL_INSPECT | CURTAIN_UNVEIL_LIST;

static const struct {
	const char name[8];
	void (*func)(struct parser *, struct word *);
	int flags;
} directives[] = {
	{ "merge",	parse_push,	0 },
	{ "push",	parse_push,	0 },
	{ "unveil",	parse_unveil,	0 },
	{ "path",	parse_unveil,	path_flags },
	{ "ability",	parse_ability,	0 },
	{ "sysctl",	parse_sysctl,	0 },
	{ "priv",	parse_priv,	0 },
	{ "ioctl",	parse_ioctls,	0 },
	{ "ioctls",	parse_ioctls,	0 },
	{ "sockaf",	parse_sockaf,	0 },
	{ "socklvl",	parse_socklvl,	0 },
	{ "fibnum",	parse_fibnum,	0 },
	{ "default",	parse_default,	0 },
};

static const struct {
	const char name[8];
	int flags;
} directive_flags[] = {
	{ "allow",	CURTAIN_ALLOW },
	{ "pass",	CURTAIN_PASS },
	{ "gate",	CURTAIN_GATE },
	{ "wall",	CURTAIN_WALL },
	{ "deny",	CURTAIN_DENY },
	{ "trap",	CURTAIN_TRAP },
	{ "kill",	CURTAIN_KILL },
	{ "inherit",	CURTAIN_INHERIT },
};

static void
parse_directive(struct parser *par, char *p)
{
	char *dir, *dir_end;
	int unsafety;

	dir = p = skip_spaces(p);
	dir_end = p = skip_word(p, "-!:");

	par->directive_flags = 0;
	par->explicit_flags = false;
	while (*p == '-') {
		char *q;
		bool found;
		q = skip_word(++p, "-!:");
		found = false;
		for (size_t i = 0; i < nitems(directive_flags); i++)
			if (strmemcmp(directive_flags[i].name, p, q - p) == 0) {
				found = true;
				par->explicit_flags = true;
				par->directive_flags |= directive_flags[i].flags;
				break;
			}
		if (!found) {
			parse_error(par, "unknown directive flag");
			return;
		}
		p = q;
	}

	unsafety = 0;
	while (*p == '!')
		p++, unsafety++;
	if (unsafety > par->cfg->unsafety)
		return;

	if (*p == ':') /* intended for argv directives */
		p++;

	if (strmemcmp("include", dir, dir_end - dir) == 0) {
		/*
		 * Always process included files (when the include directive is
		 * in a matched section) even if they already have been
		 * processed before because the file could contain sections for
		 * newly enabled tags that haven't been applied yet.
		 */
		if (par->matched)
			parse_words(par, p, parse_include);
		return;
	}

	if (par->skip)
		return;
	for (size_t i = 0; i < nitems(directives); i++)
		if (strmemcmp(directives[i].name, dir, dir_end - dir) == 0) {
			par->directive_flags |= directives[i].flags;
			need_slot(par);
			parse_words(par, p, directives[i].func);
			return;
		}
	parse_error(par, "unknown directive");
}

static int
match_section_pred_cwd_cb(void *ctx, char *path)
{
	struct parser *par = ctx;
	int r;
	r = curtain_cwd_is_within(path);
	if (r < 0) {
		if (errno != ENOENT && errno != EACCES)
			warn("%s", path);
	} else if (r > 0) {
		par->last_matched_section_path = strdup(path);
		if (!par->last_matched_section_path)
			err(EX_TEMPFAIL, "strdup");
		return (-1); /* stop searching */
	}
	return (0);
}

static void
match_section_pred_cwd(struct parser *par,
    bool *matched, bool *visited,
    char *name, char *name_end)
{
	char buf[PATH_MAX], c;
	const char *error;
	*matched = *visited = false;
	c = *name_end;
	*name_end = '\0';
	par->last_matched_section_path = NULL;
	error = NULL;
	pathexp(name, buf, sizeof buf, &error, match_section_pred_cwd_cb, par);
	*name_end = c;
	if (error)
		parse_error(par, error);
	else if (par->last_matched_section_path)
		*matched = true;
}

static void
match_section_pred_tag(struct parser *par,
    bool *matched, bool *visited,
    char *name, char *name_end)
{
	*matched = *visited = false;
	for (const struct curtain_config_tag *tag = par->cfg->tags_current; tag; tag = tag->chain) {
		if (tag == par->cfg->tags_visited)
			*visited = true;
		if (!tag->blocked &&
		    strmemcmp(tag->name, name, name_end - name) == 0) {
			*matched = true;
			break;
		}
	}
}

static char *
parse_section_pred(struct parser *par, char *p)
{
	/* [a !b c, d e, f] -> (a && !b && c) || (d && e) || f */
	bool empty, or_matched, or_visited, and_matched, and_visited;
	empty = true;
	or_matched = or_visited = false;
	and_matched = and_visited = true;
	do {
		/*
		 * XXX The same tag names escaped differently will not match.
		 *
		 * XXX Negations are dodgy because a section won't be unapplied
		 * if it matched due to a negated tag that later gets set.
		 */
		bool branched, finished, negated, matched, visited;
		char *name, *name_end;

		branched = false;
		while (*(p = skip_spaces(p)) == ',')
			p++, branched = true;

		negated = false;
		while (*(p = skip_spaces(p)) == '!')
			p++, negated = !negated;

		name = p = skip_spaces(p);
		name_end = p = skip_word(p, ",:]");
		finished = name == name_end;

		if (finished || branched) {
			if (!empty && and_matched) {
				or_matched = true;
				if (and_visited)
					or_visited = true;
			}
			and_matched = and_visited = true;
			if (finished) {
				if (empty) {
					/* [] restores initial state */
					or_matched = true;
					or_visited = par->visited;
				}
				break;
			}
		}
		empty = false;

		if (strchr(name, '/'))
			match_section_pred_cwd(par, &matched, &visited, name, name_end);
		else
			match_section_pred_tag(par, &matched, &visited, name, name_end);
		if (!matched != negated)
			and_matched = false;
		if (!visited)
			and_visited = false;
	} while (true);

	par->matched = or_matched;
	par->skip = !or_matched || or_visited;
	return (p);
}

static void
parse_section(struct parser *par, char *p)
{
	par->slot = NULL;
	par->last_matched_section_path = NULL;
	p = parse_section_pred(par, p + 1);
	if (par->cfg->verbosity >= 2 && par->matched)
		fprintf(stderr, "%s: %s:%ju: matched section%s\n",
		    getprogname(), par->file_name, (uintmax_t)par->line_no,
		    par->skip ? ", already applied" : "");
	if (*(p = skip_spaces(p)) == ':') {
		p++;
		while (*(p = skip_spaces(p))) {
			char *w;
			p = skip_word((w = p), ":]");
			if (w == p)
				break;
			if (par->matched)
				curtain_config_tag_push_mem(par->cfg, w, p - w);
		}
	}
	if (*p++ != ']')
		return (parse_error(par, "expected closing bracket"));
	if (*(p = skip_spaces(p)))
		return (parse_error(par, "unexpected characters at end of line"));
}

static void
parse_line(struct parser *par)
{
	char *p;
	p = par->line;
next:	switch (*p) {
	case '\0':
	case '#':
		return;
	SPACE_CASES
		p++;
		goto next;
	case '[':
		parse_section(par, p);
		return;
	case '\\':
	case '/':
	case '.':
	case '{':
	case '$':
	case '~':
	case '%':
		if (!par->skip) {
			par->directive_flags = path_flags;
			need_slot(par);
			parse_words(par, p, parse_unveil);
		}
		return;
	case '@': /* old syntax */
		p++;
		/* FALLTHROUGH */
	default:
		if (par->matched)
			parse_directive(par, p);
		return;
	}
}

static void
parse_config(struct parser *par)
{
	while (getline(&par->line, &par->line_size, par->file) >= 0) {
		par->line_no++;
		parse_line(par);
	}
}

static int
process_file_at(struct curtain_config *cfg,
    const char *base_path, int base_fd, const char *sub_path)
{
	char path[PATH_MAX];
	struct parser par = {
		.cfg = cfg,
		.matched = true,
		.apply = true,
		.skip = cfg->tags_visited,
		.visited = cfg->tags_visited,
	};
	int fd, saved_errno;
	if (base_path) {
		pathfmt(path, "%s/%s", base_path, sub_path);
		par.file_name = path;
	} else
		par.file_name = sub_path;
	fd = openat(base_fd, sub_path, O_RDONLY);
	if (fd < 0) {
		if (errno != ENOENT)
			warn("%s", par.file_name);
		return (-1);
	}
	par.file = fdopen(fd, "r");
	if (!par.file)
		err(EX_OSERR, "fopen");
	if (cfg->verbosity >= 1) {
		fprintf(stderr, "%s: %s: processing with tags [", getprogname(), par.file_name);
		for (const struct curtain_config_tag *tag = cfg->tags_current; tag; tag = tag->chain)
			fprintf(stderr, "%s%s", tag->name,
			    !tag->chain ? "" : tag->chain == cfg->tags_visited ? "; " : ", ");
		fprintf(stderr, "]\n");
	}
	parse_config(&par);
	saved_errno = errno;
	fclose(par.file);
	errno = saved_errno;
	return (par.error ? -1 : 0);
}

static int
process_file(struct curtain_config *cfg, const char *path)
{
	return (process_file_at(cfg, "", AT_FDCWD, path));
}

int
curtain_config_directive(struct curtain_config *cfg, struct curtain_slot *slot,
    const char *directive)
{
	struct parser par = {
		.cfg = cfg,
		.file_name = "argv",
		.matched = true,
		.apply = true,
		.slot = slot,
	};
	par.line = strdup(directive);
	if (!par.line)
		err(EX_TEMPFAIL, "strdup");
	par.line_size = strlen(par.line);
	parse_directive(&par, par.line);
	free(par.line);
	return (par.error ? -1 : 0);
}


static void
process_dir_tag(struct curtain_config *cfg, struct curtain_config_tag *tag,
    const char *base_path, int base_fd)
{
	char path[PATH_MAX];
	DIR *dir;
	struct dirent *ent;
	int dir_fd, r;
	if (tag->name[0] == '.' || strchr(tag->name, '/'))
		return;

	pathfmt(path, "%s.conf", tag->name);
	process_file_at(cfg, base_path, base_fd, path);

	pathfmt(path, "%s.d", tag->name);
	dir_fd = openat(base_fd, path, O_RDONLY|O_DIRECTORY);
	if (dir_fd < 0) {
		if (errno != ENOENT)
			warn("%s/%s", base_path, path);
		return;
	}
	dir = fdopendir(dir_fd);
	if (!dir)
		err(EX_OSERR, "opendir");
	while ((ent = readdir(dir))) {
		if (ent->d_name[0] == '.')
			continue;
		if (ent->d_namlen < 5 ||
		    strcmp(ent->d_name + ent->d_namlen - 5, ".conf") != 0)
			continue;
		process_file_at(cfg, path, dirfd(dir), ent->d_name);
	}
	r = closedir(dir);
	if (r < 0)
		warn("%s", path);
}

static void
process_dir(struct curtain_config *cfg, const char *base)
{
	int dir_fd, r;
	bool visited;
	dir_fd = open(base, O_SEARCH|O_DIRECTORY);
	if (dir_fd < 0) {
		if (errno != ENOENT)
			warn("%s", base);
		return;
	}

	visited = false;
	for (struct curtain_config_tag *tag = cfg->tags_current; tag; tag = tag->chain) {
		struct curtain_config_tag *saved_tags_visited = cfg->tags_visited;
		if (tag == cfg->tags_visited)
			visited = true;
		/* Don't skip anything in files that haven't been visited yet. */
		if (!visited)
			cfg->tags_visited = NULL;
		process_dir_tag(cfg, tag, base, dir_fd);
		if (!visited)
			cfg->tags_visited = saved_tags_visited;
	}

	r = close(dir_fd);
	if (r < 0)
		warn("%s", base);
}

void
curtain_config_load(struct curtain_config *cfg)
{
	char path[PATH_MAX];
	const char *home;
	home = issetugid() ? NULL : getenv("HOME");

	/*
	 * The tags list contains all of the section names that must be applied
	 * when parsing the configuration files.
	 *
	 * The are 3 pointers into the list.  The sublist beginning at
	 * tags_visited is for tags for which the corresponding curtain.d
	 * configuration files have already been processed.  The sublist at
	 * tags_current is for the tags currently being processed by an
	 * iteration of this loop.  Newly enabled tags are inserted at
	 * tags_pending and aren't processed until the next iteration.
	 *
	 * This is used to skip over sections that have already been applied
	 * when reparsing the same files to apply newly enabled tags.
	 */
	do {
		cfg->tags_current = cfg->tags_pending;

		if (home) {
			pathfmt(path, "%s/.curtain.d", home);
			process_dir(cfg, path);
			pathfmt(path, "%s/.curtain.conf", home);
			process_file(cfg, path);
		}

		process_dir(cfg, _PATH_ETC "/curtain.d");
		process_file(cfg, _PATH_ETC "/curtain.conf");

		process_file(cfg, _PATH_ETC "/defaults/curtain.conf");

		cfg->tags_visited = cfg->tags_current;

	} while (cfg->tags_current != cfg->tags_pending);
}

void
curtain_config_tags_clear(struct curtain_config *cfg)
{
	struct curtain_config_tag *tag, *tag_next;
	tag_next = cfg->tags_pending;
	while ((tag = tag_next)) {
		tag_next = tag->chain;
		free(tag);
	}
	cfg->tags_pending = cfg->tags_current = cfg->tags_visited = NULL;
}

static void
curtain_config_init(struct curtain_config *cfg, unsigned flags)
{
	*cfg = (struct curtain_config){
		.on_exec_only = flags & CURTAIN_CONFIG_ON_EXEC_ONLY,
	};
	if (issetugid() || !(cfg->old_tmpdir = getenv("TMPDIR")))
		cfg->old_tmpdir = _PATH_TMP;
}

struct curtain_config *
curtain_config_new(unsigned flags)
{
	struct curtain_config *cfg;
	cfg = malloc(sizeof *cfg);
	if (!cfg)
		err(EX_TEMPFAIL, "malloc");
	curtain_config_init(cfg, flags);
	return (cfg);
}

int
curtain_config_verbosity(struct curtain_config *cfg, int new)
{
	int old = cfg->verbosity;
	cfg->verbosity = new;
	return (old);
}

int
curtain_config_unsafety(struct curtain_config *cfg, int new)
{
	int old = cfg->unsafety;
	cfg->unsafety = new;
	return (old);
}

void
curtain_config_free(struct curtain_config *cfg)
{
	/* XXX: there should be some way to free the slots eventually */
	curtain_config_tags_clear(cfg);
	free(cfg);
}

void
curtain_config_tags_from_env(struct curtain_config *cfg, const char *name)
{
	char *p, *q;
	if (!name)
		name = "CURTAIN_TAGS";
	if (issetugid() || !(p = getenv(name)))
		return;
	q = p;
	do {
		if (!*q || is_space(*q)) {
			if (p != q)
				curtain_config_tag_push_mem(cfg, p, q - p);
			if (!*q)
				break;
			p = ++q;
		} else
			q++;
	} while (true);
}

