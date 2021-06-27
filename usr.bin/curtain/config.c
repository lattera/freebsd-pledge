#include <assert.h>
#include <ctype.h>
#include <curtain.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <paths.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/unveil.h>
#include <sysexits.h>

#include "common.h"
#include "pathexp.h"

struct parser {
	struct config *cfg;
	FILE *file;
	const char *file_name;
	off_t line_no;
	char *line;
	size_t line_size;
	bool skip;
	bool matched;
	bool visited;
	bool error;
	struct curtain_slot *slot;
	unveil_perms uperms;
	char *last_matched_section_path;
	size_t section_path_offset;
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
parse_unveil_perms(unveil_perms *uperms, const char *s)
{
	*uperms = UPERM_NONE;
	while (*s)
		switch (*s++) {
		case 'b': *uperms |= UPERM_BROWSE; break;
		case 'r': *uperms |= UPERM_READ; break;
		case 'm': *uperms |= UPERM_WRITE; break;
		case 'w': *uperms |= UPERM_WRITE | UPERM_SETATTR |
		                     UPERM_CREATE | UPERM_DELETE; break;
		case 'a': *uperms |= UPERM_SETATTR; break;
		case 'c': *uperms |= UPERM_CREATE | UPERM_DELETE; break;
		case 'x': *uperms |= UPERM_EXECUTE; break;
		case 'i': *uperms |= UPERM_INSPECT; break;
		case 't': *uperms |= UPERM_TMPDIR; break;
		case 'u': *uperms |= UPERM_UNIX; break;
		default:
			return (-1);
		}
	return (0);
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

struct config_tag *
config_tag_push_mem(struct config *cfg, const char *buf, size_t len)
{
	struct config_tag *tag;
	for (tag = cfg->tags_pending; tag; tag = tag->chain)
		if (strmemcmp(tag->name, buf, len) == 0)
			break;
	if (tag)
		return (tag);
	tag = malloc(sizeof *tag + len + 1);
	if (!tag)
		err(EX_TEMPFAIL, "malloc");
	*tag = (struct config_tag){ .chain = cfg->tags_pending };
	memcpy(tag->name, buf, len);
	tag->name[len] = '\0';
	cfg->tags_pending = tag;
	return (tag);
}


static void
need_slot(struct parser *par)
{
	if (!par->slot)
		curtain_enable((par->slot = curtain_slot_neutral()), CURTAIN_ON_EXEC);
}

static void
parse_error(struct parser *par, const char *error)
{
	par->error = true;
	warnx("%s:%zu: %s", par->file_name, (uintmax_t)par->line_no, error);
}

static inline char *
skip_spaces(char *p)
{
	while (isspace(*p))
		p++;
	if (*p == '#')
		do p++;
		while (*p);
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
		} else if (isspace(*p) || strchr(brk, *p))
			break;
		p++;
	}
	return (p);
}

static void
expect_eol(struct parser *par, char *p)
{
	if (*(p = skip_spaces(p)))
		parse_error(par, "unexpected characters at end of line");
}


static int process_file(struct config *, const char *path);

static void
parse_include(struct parser *par, char *p, bool apply)
{
	while (*(p = skip_spaces(p))) {
		char *w, c;
		p = skip_word((w = p), "");
		if (w == p)
			break;
		if (apply) {
			c = *p;
			*p = '\0';
			process_file(par->cfg, w);
			*p = c;
		}
	}
	return (expect_eol(par, p));
}


static char *
parse_merge_tags(struct parser *par, char *p, bool apply)
{
	do {
		char *tag, *tag_end;
		tag = p = skip_spaces(p);
		tag_end = p = skip_word(p, ":]");
		if (tag == tag_end)
			break;
		if (apply)
			config_tag_push_mem(par->cfg, tag, tag_end - tag);
	} while (true);
	return (p);
}

static void
parse_merge(struct parser *par, char *p, bool apply)
{
	p = parse_merge_tags(par, p, apply);
	if (!p)
		return;
	return (expect_eol(par, p));
}

static int
do_unveil_callback(void *ctx, char *path)
{
	struct parser *par = ctx;
	if (path[0] && path[0] != '/' && par->last_matched_section_path)
		path -= par->section_path_offset;
	curtain_unveil(par->slot, path, CURTAIN_UNVEIL_INSPECT, par->uperms);
	return (0);
}

static void
do_unveil(struct parser *par, const char *pattern)
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
parse_unveil(struct parser *par, char *p, bool apply)
{
	char *pattern, *pattern_end, *perms, *perms_end;

	pattern = p = skip_spaces(p);
	pattern_end = p = skip_word(p, "");

	if (*(p = skip_spaces(p)) == ':') {
		int r;
		p = skip_spaces(++p);
		perms = p;
		while (*p && !isspace(*p))
			p++;
		perms_end = p;
		if (*(p = skip_spaces(p)))
			return (parse_error(par, "unexpected characters at end of line"));

		*pattern_end = '\0';
		if (!*pattern)
			return (parse_error(par, "empty pattern"));

		*perms_end = '\0';
		r = parse_unveil_perms(&par->uperms, perms);
		if (r < 0)
			return (parse_error(par, "invalid unveil permissions"));
	} else {
		if (*p)
			return (parse_error(par, "unexpected characters at end of line"));
		*pattern_end = '\0';
		par->uperms = UPERM_READ;
	}

	return (apply ? do_unveil(par, pattern) : 0);
}

static void
parse_sysfil(struct parser *par, char *p, bool apply)
{
	while (*(p = skip_spaces(p))) {
		char *w;
		const struct sysfilent *e;
		p = skip_word((w = p), "");
		if (w == p)
			break;
		for (e = sysfiltab; e->name; e++)
			if (strmemcmp(e->name, w, p - w) == 0)
				break;
		if (!e->name)
			parse_error(par, "unknown sysfil");
		else if (apply)
			curtain_sysfil(par->slot, e->sysfil, 0);
	}
	return (expect_eol(par, p));
}

static void
parse_sysctl(struct parser *par, char *p, bool apply)
{
	while (*(p = skip_spaces(p))) {
		char *w, c;
		p = skip_word((w = p), "");
		if (w == p)
			break;
		if (apply) {
			c = *p;
			*p = '\0';
			curtain_sysctl(par->slot, w, 0);
			*p = c;
		}
	}
	return (expect_eol(par, p));
}

static void
parse_priv(struct parser *par, char *p, bool apply)
{
	while (*(p = skip_spaces(p))) {
		char *w;
		const struct privent *e;
		p = skip_word((w = p), "");
		if (w == p)
			break;
		for (e = privtab; e->name; e++)
			if (strmemcmp(e->name, w, p - w) == 0)
				break;
		if (!e->name)
			parse_error(par, "unknown privilege");
		else if (apply)
			curtain_priv(par->slot, e->priv, 0);
	}
	return (expect_eol(par, p));
}

static void
parse_ioctls(struct parser *par, char *p, bool apply)
{
	while (*(p = skip_spaces(p))) {
		char *w;
		const unsigned long *bundle;
		p = skip_word((w = p), "");
		if (w == p)
			break;
		bundle = NULL;
		for (size_t i = 0; i < nitems(ioctls_bundles); i++)
			if (strmemcmp(ioctls_bundles[i].name, w, p - w) == 0) {
				bundle = ioctls_bundles[i].ioctls;
				break;
			}
		if (!bundle)
			parse_error(par, "unknown ioctl bundle");
		else if (apply)
			curtain_ioctls(par->slot, bundle, 0);
	}
	return (expect_eol(par, p));
}

static void
parse_reprotect(struct parser *par, char *p, bool apply)
{
	if (apply)
		par->cfg->need_reprotect = true;
	return (expect_eol(par, p));
}

static const struct {
	const char name[16];
	void (*func)(struct parser *par, char *p, bool apply);
} directives[] = {
	{ "include", parse_include },
	{ "merge", parse_merge },
	{ "unveil", parse_unveil },
	{ "sysfil", parse_sysfil },
	{ "sysctl", parse_sysctl },
	{ "priv", parse_priv },
	{ "ioctls", parse_ioctls },
	{ "reprotect", parse_reprotect },
};

static void
parse_directive(struct parser *par, char *p)
{
	char *dir, *dir_end;
	unsigned unsafe_level;
	dir = p = skip_spaces(p + 1);
	dir_end = p = skip_word(p, "!");
	unsafe_level = 0;
	while (*p == '!')
		p++, unsafe_level++;
	for (size_t i = 0; i < nitems(directives); i++)
		if (strmemcmp(directives[i].name, dir, dir_end - dir) == 0) {
			bool apply = unsafe_level <= par->cfg->unsafe_level &&
			    (directives[i].func == parse_include ?
			     par->matched : !par->skip);
			/*
			 * Only parse unnecessarily the first time a file is
			 * being processed to report syntax errors to the user.
			 */
			if (!apply && par->visited)
				return;
			if (apply)
				need_slot(par);
			return (directives[i].func(par, p, apply));
		}
	parse_error(par, "unknown directive");
}

static int
match_section_pred_cwd_cb(void *ctx, char *path)
{
	struct parser *par = ctx;
	int r;
	r = cwd_is_within(path);
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
	for (const struct config_tag *tag = par->cfg->tags_current; tag; tag = tag->chain) {
		if (tag == par->cfg->tags_visited)
			*visited = true;
		if (strmemcmp(tag->name, name, name_end - name) == 0) {
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
	if (par->cfg->verbose && par->matched)
		fprintf(stderr, "%s: %s:%zu: matched section%s\n",
		    getprogname(), par->file_name, (uintmax_t)par->line_no,
		    par->skip ? ", already applied" : "");
	if (*(p = skip_spaces(p)) == ':') {
		p++;
		p = parse_merge_tags(par, p, par->matched);
		if (!p)
			return;
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
	p = skip_spaces(par->line);
	if (!*p)
		return;
	if (*p == '[')
		return (parse_section(par, p));
	/*
	 * Parse everything at least once to report syntax errors.
	 *
	 * Note that directives may need to be re-processed even in sections
	 * known to already have been applied to re-process "include" directives
	 * in case there are sections in included files for newly enabled tags.
	 */
	if (!par->matched && par->visited)
		return;
	if (p[0] == '@')
		return (parse_directive(par, p));
	if (par->skip && par->visited)
		return;
	if (!par->skip)
		need_slot(par);
	return (parse_unveil(par, p, !par->skip));
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
process_file(struct config *cfg, const char *path)
{
	struct parser par = {
		.cfg = cfg,
		.file_name = path,
		.matched = true,
		.skip = cfg->tags_visited,
		.visited = cfg->tags_visited,
	};
	int saved_errno;
	par.file = fopen(path, "r");
	if (!par.file) {
		if (errno != ENOENT)
			warn("%s", par.file_name);
		return (-1);
	}
	if (cfg->verbose) {
		fprintf(stderr, "%s: %s: processing with tags [", getprogname(), path);
		for (const struct config_tag *tag = cfg->tags_current; tag; tag = tag->chain)
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

static void
config_load_tag(struct config *cfg, struct config_tag *tag, const char *base)
{
	char path[PATH_MAX];
	DIR *dir;
	struct dirent *ent;
	int r;
	if (tag->name[0] == '.' || strchr(tag->name, '/'))
		return;

	pathfmt(path, "%s/%s.conf", base, tag->name);
	process_file(cfg, path);

	pathfmt(path, "%s/%s.d", base, tag->name);
	dir = opendir(path);
	if (!dir) {
		if (errno != ENOENT)
			warn("%s", path);
		return;
	}
	while ((ent = readdir(dir))) {
		if (ent->d_name[0] == '.')
			continue;
		if (ent->d_namlen < 5 ||
		    strcmp(ent->d_name + ent->d_namlen - 5, ".conf") != 0)
			continue;
		pathfmt(path, "%s/%s.d/%s", base, tag->name, ent->d_name);
		process_file(cfg, path);
	}
	r = closedir(dir);
	if (r < 0)
		warn("%s", path);
}

static void
config_load_tags_d(struct config *cfg, const char *base)
{
	bool visited = false;
	for (struct config_tag *tag = cfg->tags_current; tag; tag = tag->chain) {
		struct config_tag *saved_tags_visited = cfg->tags_visited;
		if (tag == cfg->tags_visited)
			visited = true;
		/* Don't skip anything in files that haven't been visited yet. */
		if (!visited)
			cfg->tags_visited = NULL;
		config_load_tag(cfg, tag, base);
		if (!visited)
			cfg->tags_visited = saved_tags_visited;
	}
}

void
config_load_tags(struct config *cfg)
{
	char path[PATH_MAX];
	const char *home;
	home = getenv("HOME");

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

		process_file(cfg, _PATH_ETC "/curtain.conf");
		process_file(cfg, _PATH_LOCALBASE "/etc/curtain.conf");
		if (home) {
			pathfmt(path, "%s/.curtain.conf", home);
			process_file(cfg, path);
		}

		config_load_tags_d(cfg, _PATH_ETC "/curtain.d");
		config_load_tags_d(cfg, _PATH_LOCALBASE "/etc/curtain.d");
		if (home) {
			pathfmt(path, "%s/.curtain.d", home);
			config_load_tags_d(cfg, path);
		}

		cfg->tags_visited = cfg->tags_current;

	} while (cfg->tags_current != cfg->tags_pending);
}

void
config_init(struct config *cfg)
{
	*cfg = (struct config){ 0 };
}

