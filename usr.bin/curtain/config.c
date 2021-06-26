#include <assert.h>
#include <ctype.h>
#include <curtain.h>
#include <curtain.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <paths.h>
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
	bool matched_section;
	bool error;
	struct curtain_slot *slot;
	unveil_perms uperms;
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

static char *
strmemdup(const char *b, size_t n)
{
	char *s;
	s = malloc(n + 1);
	if (!s)
		return (NULL);
	memcpy(s, b, n);
	s[n] = '\0';
	return (s);
}

static void
parse_error(struct parser *par, const char *error)
{
	par->error = true;
	warnx("%s:%zu: %s", par->file_name, (uintmax_t)par->line_no, error);
}

static char *
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

static int load_config(const char *path, struct config *);

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
			load_config(w, par->cfg);
			*p = c;
		}
	}
	return (expect_eol(par, p));
}


static char *
parse_merge_tags(struct parser *par, char *p, bool apply) {
	do {
		char *tag, *tag_end;
		bool found;
		tag = p = skip_spaces(p);
		tag_end = p = skip_word(p, ":]");
		if (tag == tag_end)
			break;
		if (apply) {
			found = false;
			for (const char **tagp = par->cfg->tags_base;
			    tagp < par->cfg->tags_last; tagp++)
				if (strmemcmp(*tagp, tag, tag_end - tag) == 0) {
					found = true;
					break;
				}
			if (!found) {
				if (par->cfg->tags_fill == par->cfg->tags_end) {
					parse_error(par, "too many tags in stack");
					return (NULL);
				}
				tag = strmemdup(tag, tag_end - tag);
				if (!tag)
					err(EX_TEMPFAIL, NULL);
				*par->cfg->tags_fill++ = tag;
			}
		}
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
	curtain_unveil(par->slot, path, CURTAIN_UNVEIL_INSPECT, par->uperms);
	return (0);
}

static void
do_unveil(struct parser *par, const char *pattern)
{
	char buf[PATH_MAX];
	int r;
	const char *error;
	r = pathexp(pattern, buf, sizeof buf, &error, do_unveil_callback, par);
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

static const struct {
	const char name[8];
	void (*func)(struct parser *par, char *p, bool apply);
} directives[] = {
	{ "include", parse_include },
	{ "merge", parse_merge },
	{ "unveil", parse_unveil },
	{ "sysfil", parse_sysfil },
	{ "sysctl", parse_sysctl },
	{ "priv", parse_priv },
	{ "ioctls", parse_ioctls },
};

static void
parse_directive(struct parser *par, char *p)
{
	char *dir, *dir_end;
	unsigned unsafe_level;
	assert(*p == '.');
	dir = p = skip_spaces(p + 1);
	dir_end = p = skip_word(p, "!");
	unsafe_level = 0;
	while (*p == '!')
		p++, unsafe_level++;
	for (size_t i = 0; i < nitems(directives); i++)
		if (strmemcmp(directives[i].name, dir, dir_end - dir) == 0)
			return (directives[i].func(par, p,
			    (unsafe_level <= par->cfg->unsafe_level) &&
			    (directives[i].func == parse_include ?
			         par->matched_section : !par->skip)));
	parse_error(par, "unknown directive");
}

static void
parse_section(struct parser *par, char *p)
{
	char *tag, *tag_end;
	assert(*p == '[');
	p++;
	tag = p = skip_spaces(p);
	tag_end = p = skip_word(p, ":]");
	if (tag == tag_end) {
		par->matched_section = true;
		par->skip = par->cfg->skip_default_tag;
	} else {
		par->matched_section = false;
		par->skip = true;
		for (const char **tagp = par->cfg->tags_base;
		    tagp < par->cfg->tags_last; tagp++)
			if (strmemcmp(*tagp, tag, tag_end - tag) == 0) {
				par->matched_section = true;
				par->skip = false;
				break;
			}
	}

	p = skip_spaces(p);
	if (*p == ':') {
		p++;
		p = parse_merge_tags(par, p, par->matched_section);
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
	if (p[0] == '.' && p[1] != '/')
		return (parse_directive(par, p));
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
load_config(const char *path, struct config *cfg)
{
	struct parser par = {
		.file_name = path,
		.matched_section = true,
		.skip = cfg->skip_default_tag,
		.cfg = cfg,
	};
	int saved_errno;
#if 0
	warnx("%s: %s", __FUNCTION__, path);
#endif
	curtain_enable((par.slot = curtain_slot_neutral()), CURTAIN_ON_EXEC);
	par.file = fopen(path, "r");
	if (!par.file) {
		if (errno != ENOENT)
			warn("%s", par.file_name);
		return (-1);
	}
	parse_config(&par);
	saved_errno = errno;
	fclose(par.file);
	errno = saved_errno;
	return (par.error ? -1 : 0);
}


static void
load_tags_d(const char *base, struct config *cfg)
{
	char path[PATH_MAX];
	for (const char **tagp = cfg->tags_base; tagp < cfg->tags_last; tagp++) {
		const char *tag = *tagp;
		DIR *dir;
		struct dirent *ent;
		int r;
		if (tag[0] == '.')
			continue;

		r = snprintf(path, sizeof path, "%s/%s.conf", base, tag);
		if (r < 0) {
			warn("snprintf");
			continue;
		}
		load_config(path, cfg);

		r = snprintf(path, sizeof path, "%s/%s.d", base, tag);
		if (r < 0) {
			warn("snprintf");
			continue;
		}
		dir = opendir(path);
		if (!dir) {
			if (errno != ENOENT)
				warn("%s", path);
			continue;
		}
		while ((ent = readdir(dir))) {
			if (ent->d_name[0] == '.')
				continue;
			if (ent->d_namlen < 5 ||
			    strcmp(ent->d_name + ent->d_namlen - 5, ".conf") != 0)
				continue;
			r = snprintf(path, sizeof path, "%s/%s.d/%s", base, tag, ent->d_name);
			if (r < 0) {
				warn("snprintf");
				continue;
			}
			load_config(path, cfg);
		}
		r = closedir(dir);
		if (r < 0)
			warn("%s", path);
	}
}

void
load_tags(struct config *cfg)
{
	char path[PATH_MAX];
	const char *home;
	home = getenv("HOME");

	do {
		cfg->tags_last = cfg->tags_fill;

		load_config(_PATH_ETC "/curtain.conf", cfg);
		load_config(_PATH_LOCALBASE "/etc/curtain.conf", cfg);
		if (home) {
			strlcpy(path, home, sizeof path);
			strlcat(path, "/.curtain.conf", sizeof path);
			load_config(path, cfg);
		}

		cfg->skip_default_tag = false;

		load_tags_d(_PATH_ETC "/curtain.d", cfg);
		load_tags_d(_PATH_LOCALBASE "/etc/curtain.d", cfg);
		if (home) {
			strlcpy(path, home, sizeof path);
			strlcat(path, "/.curtain.d", sizeof path);
			load_tags_d(path, cfg);
		}

		cfg->skip_default_tag = true;
	} while (cfg->tags_last != cfg->tags_fill);
}

