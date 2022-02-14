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
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/unveil.h>
#include <sysexits.h>
#include <unistd.h>

#include "common.h"
#include "pathexp.h"

struct config_parser {
	struct curtain_config *cfg;
	struct config_section *current_section;
	struct config_block *current_block;
	FILE *file;
	const char *file_name;
	char *line, *cursor;
	unsigned line_no;
	bool errors;
};

struct config_tag {
	struct config_tag **link, *next;
	bool locked;
	bool enabled;
	char name[];
};

struct config_include {
	struct config_include *next;
	char path[];
};

struct config_command {
	struct config_command *next;
	struct config_block *block;
	void (*perform)(struct config_section *, struct config_command *);
	unsigned line_no;
	int curtain_flags;
	size_t words_count;
	const char *words[];
};

struct config_merge {
	struct config_merge *next;
	struct config_tag *tag;
};

struct config_guard {
	enum config_guard_type {
		CONFIG_GUARD_TAG,
		CONFIG_GUARD_NOT,
		CONFIG_GUARD_OR,
		CONFIG_GUARD_AND,
	} type;
	struct config_guard *next;
	union {
		struct config_tag *tag;
		struct config_guard *child;
	};
};

struct config_block {
	struct config_block *next;
	struct config_guard *guard;
	struct config_merge *merges;
	struct config_include *new_includes;
	struct config_block *subblocks;
	unsigned line_no;
	bool matched;
};

struct config_section {
	struct config_section *next;
	struct curtain_config *cfg;
	struct config_command *commands, **commands_tail;
	struct config_block block;
	struct curtain_slot *slot;
	bool slot_owned;
	bool slot_filled;
	bool slot_synced;
	char file_name[];
};


static void *
emalloc(size_t n)
{
	void *p;
	p = malloc(n);
	if (!p)
		err(EX_TEMPFAIL, "malloc");
	return (p);
}

static char *
estrdup(const char *src)
{
	char *dst;
	dst = strdup(src);
	if (!dst)
		err(EX_TEMPFAIL, "strdup");
	return (dst);
}


#define	CONFIG_DIAG(vrb, cfg, ...) do { \
	if ((cfg)->verbosity >= (vrb)) \
		warnx(__VA_ARGS__); \
} while (0)

#define	COMMAND_DIAG_1(vrb, sec, cmd, fmt, ...) do { \
	if ((sec)->cfg->verbosity >= (vrb)) \
		fprintf(stderr, "%s: %s:%u: " fmt "%s", \
		    getprogname(), (sec)->file_name, (cmd)->line_no, \
		    __VA_ARGS__); \
} while (0)

#define	COMMAND_DIAG(par, ...) COMMAND_DIAG_1(par, __VA_ARGS__, "\n");

#define	COMMAND_ERROR(sec, cmd, ...) do { \
	COMMAND_DIAG_1(0, sec, cmd, __VA_ARGS__, "\n"); \
	(sec)->cfg->errors = true; \
} while (0)

#define	PARSE_ERROR_1(par, fmt, ...) do { \
	fprintf(stderr, "%s: %s:%u: " fmt "%s", \
	    getprogname(), (par)->file_name, (par)->line_no, \
	    __VA_ARGS__); \
	(par)->errors = true; \
} while (0)

#define	PARSE_ERROR(par, ...) PARSE_ERROR_1(par, __VA_ARGS__, "\n");


static struct config_tag **
tag_find(struct curtain_config *cfg, const char *name)
{
	struct config_tag **link;
	for (link = &cfg->tags_pending; *link; link = &(*link)->next) {
		assert((*link)->link == link);
		if (strcmp((*link)->name, name) == 0)
			break;
	}
	return (link);
}

static struct config_tag *
tag_make(struct curtain_config *cfg __unused, struct config_tag **link, const char *name)
{
	struct config_tag *tag;
	tag = emalloc(offsetof(struct config_tag, name) + strlen(name) + 1);
	*tag = (struct config_tag){ .link = link, .next = *link };
	strcpy(tag->name, name);
	if (tag->next)
		tag->next->link = &tag->next;
	*tag->link = tag;
	return (tag);
}

static struct config_tag *
tag_get(struct curtain_config *cfg, const char *name)
{
	struct config_tag *tag, **link;
	if ((tag = *(link = tag_find(cfg, name))))
		return (tag);
	return (tag_make(cfg, link, name));
}

static void
tag_relink(struct config_tag *tag, struct config_tag **link)
{
	assert(*tag->link == tag);
	assert(!tag->next || tag->next->link == &tag->next);
	if ((*tag->link = tag->next))
		tag->next->link = tag->link;
	if ((tag->next = *link))
		tag->next->link = &tag->next;
	*(tag->link = link) = tag;
}

static void
tag_merge(struct curtain_config *cfg, struct config_tag *tag)
{
	if (!tag->enabled && !tag->locked) {
		tag_relink(tag, &cfg->tags_pending);
		tag->enabled = true;
	}
}

static struct config_tag *
tag_push(struct curtain_config *cfg, const char *name)
{
	struct config_tag *tag, **link;
	if ((tag = *(link = tag_find(cfg, name)))) {
		if (!tag->enabled) {
			tag_relink(tag, &cfg->tags_pending);
			tag->enabled = true;
		}
	} else {
		tag = tag_make(cfg, &cfg->tags_pending, name);
		tag->enabled = true;
	}
	return (tag);
}

static void
tags_sweep(struct curtain_config *cfg)
{
	for (struct config_tag *tag = cfg->tags_pending; tag; tag = tag->next)
		if (!tag->locked)
			tag->enabled = false;
}


static struct config_include *
include_add(struct curtain_config *cfg, const char *path)
{
	struct config_include *inc;
	if (!*path)
		return (NULL);
	inc = emalloc(sizeof *inc + strlen(path) + 1);
	*inc = (struct config_include){ .next = cfg->incs_pending };
	strcpy(inc->path, path);
	cfg->incs_pending = inc;
	return (inc);
}


static struct config_guard *
guard_make_tag(struct config_tag *tag)
{
	struct config_guard *guard;
	*(guard = emalloc(sizeof *guard)) = (struct config_guard){
	    .type = CONFIG_GUARD_TAG, .tag = tag };
	return (guard);
}

static struct config_guard *
guard_make_child(enum config_guard_type type, struct config_guard *child)
{
	struct config_guard *guard;
	*(guard = emalloc(sizeof *guard)) = (struct config_guard){
	    .type = type, .child = child };
	return (guard);
}

static void
guard_free(struct config_guard *guard)
{
	switch (guard->type) {
	case CONFIG_GUARD_NOT:
	case CONFIG_GUARD_AND:
	case CONFIG_GUARD_OR:
		for (struct config_guard *child = guard->child, *next; child; child = next) {
			next = child->next;
			guard_free(child);
		}
		/* FALLTHROUGH */
	case CONFIG_GUARD_TAG:
		free(guard);
		break;
	}
}

static void
guard_dump(struct config_guard *guard, bool top, FILE *file)
{
	switch (guard->type) {
	case CONFIG_GUARD_TAG:
		fprintf(file, "%c%s", "-+"[guard->tag->enabled], guard->tag->name);
		break;
	case CONFIG_GUARD_NOT:
		fputs("!", file);
		/* FALLTHROUGH */
	case CONFIG_GUARD_AND:
	case CONFIG_GUARD_OR:
		if (!top)
			fputc('(', file);
		for (struct config_guard *child = guard->child; child; child = child->next) {
			if (child != guard->child)
				fputs(guard->type == CONFIG_GUARD_AND ? " " : ", ", file);
			guard_dump(child, top && guard->type == CONFIG_GUARD_OR, file);
		}
		if (!top)
			fputc(')', file);
		break;
	}
}


static struct config_command *
command_make(struct config_parser *par, size_t words_count, size_t words_total_size)
{
	struct config_command *cmd;
	cmd = emalloc(sizeof *cmd + words_count * sizeof *cmd->words + words_total_size);
	*cmd = (struct config_command){
		.line_no = par->line_no,
		.block = par->current_block,
		.words_count = words_count,
	};
	return (cmd);
}

static void
command_free(struct config_command *cmd)
{
	free(cmd);
}


static struct config_block *
block_make(struct config_parser *par, struct config_guard *guard)
{
	struct config_block *blk;
	blk = emalloc(sizeof *blk);
	*blk = (struct config_block){
		.next = par->current_block->subblocks,
		.guard = guard,
		.line_no = par->line_no,
	};
	par->current_block->subblocks = blk;
	par->current_block = blk;
	return (blk);
}

static void block_free(struct config_block *);

static void
block_free_1(struct config_block *blk)
{
	if (blk->guard)
		guard_free(blk->guard);
	for (struct config_merge *mrg = blk->merges, *next; mrg; mrg = next) {
		next = mrg->next;
		free(mrg);
	}
	for (struct config_include *inc = blk->new_includes, *next; inc; inc = next) {
		next = inc->next;
		free(inc);
	}
	for (struct config_block *subblk = blk->subblocks, *next; subblk; subblk = next) {
		next = subblk->next;
		block_free(subblk);
	}
}

static void
block_free(struct config_block *blk)
{
	block_free_1(blk);
	free(blk);
}


static struct config_section *
section_make(struct config_parser *par)
{
	struct config_section *sec;
	sec = emalloc(offsetof(struct config_section, file_name) + strlen(par->file_name) + 1);
	*sec = (struct config_section){
		.next = par->cfg->sections,
		.cfg = par->cfg,
		.commands_tail = &sec->commands,
		.block = { .line_no = par->line_no },
	};
	strcpy(sec->file_name, par->file_name);
	par->cfg->sections = sec;
	par->current_block = &sec->block;
	return (sec);
}

static struct config_section *
section_get(struct config_parser *par)
{
	if (!par->current_section)
		par->current_section = section_make(par);
	return (par->current_section);
}

static struct curtain_slot *
section_slot(struct config_section *sec)
{
	if (!sec->slot) {
		if (sec->cfg->on_exec_only)
			curtain_enable((sec->slot = curtain_slot_neutral()), CURTAIN_ON_EXEC);
		else
			sec->slot = curtain_slot();
		sec->slot_owned = true;
	}
	return (sec->slot);
}

static void
section_free(struct config_section *sec)
{
	for (struct config_command *cmd = sec->commands, *next; cmd; cmd = next) {
		next = cmd->next;
		command_free(cmd);
	}
	block_free_1(&sec->block);
	if (sec->slot_owned)
		curtain_drop(sec->slot);
	free(sec);
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

static char *
unescape(char *p)
{
	char *q = p;
	while (*p) {
		if (*p == '\\') {
			p++;
			if (!*p)
				break;
		}
		*q++ = *p++;
	}
	*q = '\0';
	return (q);
}


static void
perform_diag(struct config_section *sec, struct config_command *cmd)
{
	COMMAND_DIAG_1(0, sec, cmd, "", "");
	for (size_t i = 0; i < cmd->words_count; i++) {
		if (i)
			fputc(' ', stderr);
		fputs(cmd->words[i], stderr);
	}
	fputc('\n', stderr);
}

static void
perform_tmpdir(struct config_section *sec, struct config_command *cmd)
{
	if (cmd->words_count) {
		COMMAND_ERROR(sec, cmd, "unexpected word");
		return;
	}
	if (sec->cfg->setup_separate_tmpdir == CONFIG_SETUP_NO)
		sec->cfg->setup_separate_tmpdir = CONFIG_SETUP_WANT;
}

static void
perform_default(struct config_section *sec, struct config_command *cmd)
{
	if (cmd->words_count) {
		COMMAND_ERROR(sec, cmd, "unexpected word");
		return;
	}
	curtain_default(section_slot(sec), cmd->curtain_flags);
}

static void
perform_ability(struct config_section *sec, struct config_command *cmd)
{
	for (size_t i = 0; i < cmd->words_count; i++) {
		const struct abilityent *e;
		for (e = curtain_abilitytab; e->name; e++)
			if (strcmp(e->name, cmd->words[i]) == 0)
				break;
		if (!e->name) {
			COMMAND_ERROR(sec, cmd, "unknown ability: %s", cmd->words[i]);
			continue;
		}
		curtain_ability(section_slot(sec), e->ability, cmd->curtain_flags);
	}
}

static void
perform_sysctl(struct config_section *sec, struct config_command *cmd)
{
	for (size_t i = 0; i < cmd->words_count; i++) {
		int r;
		r = curtain_sysctl(section_slot(sec), cmd->words[i], cmd->curtain_flags);
		if (r < 0)
			COMMAND_ERROR(sec, cmd, "sysctl %s: %m", cmd->words[i]);
	}
}

static void
perform_priv(struct config_section *sec, struct config_command *cmd)
{
	for (size_t i = 0; i < cmd->words_count; i++) {
		const struct privent *e;
		for (e = curtain_privtab; e->name; e++)
			if (strcmp(e->name, cmd->words[i]) == 0)
				break;
		if (!e->name) {
			COMMAND_ERROR(sec, cmd, "unknown privilege: %s", cmd->words[i]);
			continue;
		}
		curtain_priv(section_slot(sec), e->priv, cmd->curtain_flags);
	}
}

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
	{ "disk_basic", curtain_ioctls_disk_basic },
	{ "mdctl", curtain_ioctls_mdctl },
};

static void
perform_ioctl(struct config_section *sec, struct config_command *cmd)
{
	for (size_t i = 0; i < cmd->words_count; i++) {
		const char *word = cmd->words[i];
		if (word[0] >= '0' && word[0] <= '9') {
			unsigned long n;
			char *end;
			errno = 0;
			n = strtoul(word, &end, 0);
			if (errno || *end) {
				COMMAND_ERROR(sec, cmd, "invalid ioctl: %s", word);
				continue;
			}
			curtain_ioctl(section_slot(sec), n, cmd->curtain_flags);
		} else {
			const unsigned long *bundle;
			bundle = NULL;
			for (size_t j = 0; j < nitems(ioctls_bundles); j++)
				if (strcmp(ioctls_bundles[j].name, word) == 0) {
					bundle = ioctls_bundles[j].ioctls;
					break;
				}
			if (!bundle) {
				COMMAND_ERROR(sec, cmd, "unknown ioctl bundle: %s", word);
				continue;
			}
			curtain_ioctls(section_slot(sec), bundle, cmd->curtain_flags);
		}
	}
}

static void
perform_sockaf(struct config_section *sec, struct config_command *cmd)
{
	for (size_t i = 0; i < cmd->words_count; i++) {
		const struct sockafent *e;
		for (e = curtain_sockaftab; e->name; e++)
			if (strcmp(e->name, cmd->words[i]) == 0)
				break;
		if (!e->name) {
			COMMAND_ERROR(sec, cmd, "unknown address family: %s", cmd->words[i]);
			continue;
		}
		curtain_sockaf(section_slot(sec), e->sockaf, cmd->curtain_flags);
	}
}

static void
perform_socklvl(struct config_section *sec, struct config_command *cmd)
{
	for (size_t i = 0; i < cmd->words_count; i++) {
		const struct socklvlent *e;
		for (e = curtain_socklvltab; e->name; e++)
			if (strcmp(e->name, cmd->words[i]) == 0)
				break;
		if (!e->name) {
			COMMAND_ERROR(sec, cmd, "unknown socket level: %s", cmd->words[i]);
			continue;
		}
		curtain_socklvl(section_slot(sec), e->socklvl, cmd->curtain_flags);
	}
}

static void
perform_fibnum(struct config_section *sec, struct config_command *cmd)
{
	for (size_t i = 0; i < cmd->words_count; i++) {
		long n;
		char *end;
		errno = 0;
		n = strtol(cmd->words[i], &end, 0);
		if (errno || *end) {
			COMMAND_ERROR(sec, cmd, "invalid fibnum: %s", cmd->words[i]);
			continue;
		}
		curtain_fibnum(section_slot(sec), n, cmd->curtain_flags);
	}
}

struct unveil_ctx {
	struct config_section *sec;
	struct config_command *cmd;
	unveil_perms uperms;
	bool create;
	void *setmode;
	char pending[PATH_MAX];
};

static int
do_unveil(struct unveil_ctx *ctx, const char *path)
{
	size_t len;
	int flags, r;
	bool is_dir;
	flags = ctx->cmd->curtain_flags;
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
	if (ctx->uperms & UPERM_CREATE && !is_dir)
		flags |= CURTAIN_PATH_NOFOLLOW;

	r = curtain_path(section_slot(ctx->sec), path, flags, ctx->uperms);
	if (ctx->create) {
		if (!is_dir) {
			struct stat st;
			r = stat(path, &st);
		}
		if (r < 0) {
			if (errno == ENOENT && !*ctx->pending)
				memcpy(ctx->pending, path, len + 1);
		} else {
			ctx->create = false;
			*ctx->pending = '\0';
		}
	}
	return (r);
}

static int
do_unveil_callback(void *ctx, char *path)
{
	do_unveil(ctx, path);
	return (0);
}

static void
do_unveils(struct unveil_ctx *ctx, const char *pattern)
{
	char path[PATH_MAX];
	int r;
	const char *error;
	r = pathexp(pattern, path, sizeof path, &error, do_unveil_callback, ctx);
	if (r < 0)
		COMMAND_ERROR(ctx->sec, ctx->cmd, "path expansion: %s", error);
}

static void
do_unveil_pending(struct unveil_ctx *ctx)
{
	char *path, *next, delim;
	struct stat st;
	bool created;
	int r;
	path = ctx->pending;
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
			r = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, DEFFILEMODE);
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
		COMMAND_DIAG(1, ctx->sec, ctx->cmd, "created path: %s\n", path);
		r = stat(path, &st);
		if (r >= 0)
			r = chmod(path, getmode(ctx->setmode, st.st_mode));
	}
	if (r < 0)
		warn("%s", path);
	else
		r = do_unveil(ctx, path);
	*next = delim;
}

static void
perform_unveil(struct config_section *sec, struct config_command *cmd)
{
	struct unveil_ctx ctx;
	const char **words, **words_end, **patterns, **patterns_end;
	int r;
	ctx = (struct unveil_ctx){
		.sec = sec,
		.cmd = cmd,
		.create = false,
		.setmode = NULL,
		.pending = "",
		.uperms = UPERM_READ,
	};
	words = cmd->words;
	words_end = &cmd->words[cmd->words_count];
	patterns = words;
	while (words < words_end && strcmp(*words, ":") != 0)
		words++;
	patterns_end = words;
	if (words < words_end) {
		ctx.uperms = UPERM_NONE;
		if (++words != words_end) {
			r = curtain_parse_unveil_perms(&ctx.uperms, *words);
			if (r < 0) {
				COMMAND_ERROR(sec, cmd, "invalid unveil permissions");
				return;
			}
			words++;
		}
	}
	if (words < words_end) {
		ctx.create = true;
		ctx.setmode = setmode(*words);
		if (!ctx.setmode) {
			if (errno == EINVAL || errno == ERANGE) {
				COMMAND_ERROR(sec, cmd, "invalid creation mode");
				return;
			} else
				err(errno == ENOMEM ? EX_TEMPFAIL : EX_OSERR, "setmode");
		}
		words++;
	}
	if (words < words_end) {
		COMMAND_ERROR(sec, cmd, "unexpected word");
		free(ctx.setmode);
		return;
	}

	while (patterns != patterns_end)
		do_unveils(&ctx, *patterns++);
	if (*ctx.pending)
		do_unveil_pending(&ctx);
	free(ctx.setmode);
}


static void
config_sweep(struct curtain_config *cfg)
{
	if (cfg->tags_dropped) {
		tags_sweep(cfg);
		cfg->tags_dropped = false;
	}
}

static bool
guard_match(struct config_guard *guard)
{
	switch (guard->type) {
	case CONFIG_GUARD_TAG:
		return (guard->tag->enabled);
	case CONFIG_GUARD_NOT:
		return (!(guard_match(guard->child)));
	case CONFIG_GUARD_AND:
		for (struct config_guard *child = guard->child; child; child = child->next)
			if (!guard_match(child))
				return (false);
		return (true);
	case CONFIG_GUARD_OR:
		for (struct config_guard *child = guard->child; child; child = child->next)
			if (guard_match(child))
				return (true);
		return (false);
	}
}

static void
block_match(struct config_section *sec, struct config_block *blk, bool matched)
{
	matched = matched && (blk->guard ? guard_match(blk->guard) : true);
	if (sec->cfg->verbosity >= (matched ? 3 : 4)) {
		COMMAND_DIAG_1(0, sec, blk, "%s section: ", matched ? "matched" : "skipped", "");
		fputs("[", stderr);
		if (blk->guard)
			guard_dump(blk->guard, true, stderr);
		fputs("]\n", stderr);
	}
	if (matched != blk->matched) {
		COMMAND_DIAG(4, sec, blk, "marking section dirty");
		sec->slot_synced = false;
		blk->matched = matched;
	}
	if (matched) {
		for (struct config_merge *mrg = blk->merges; mrg; mrg = mrg->next) {
			COMMAND_DIAG(2, sec, blk, "merging tag: %s", mrg->tag->name);
			tag_merge(sec->cfg, mrg->tag);
		}
		for (struct config_include *inc = blk->new_includes, *next; inc; inc = next) {
			COMMAND_DIAG(2, sec, blk, "including path: %s", inc->path);
			next = inc->next;
			inc->next = sec->cfg->incs_pending;
			sec->cfg->incs_pending = inc;
		}
		blk->new_includes = NULL;
	}
	for (struct config_block *subblk = blk->subblocks; subblk; subblk = subblk->next)
		block_match(sec, subblk, matched);
}

static void
config_match(struct curtain_config *cfg)
{
	for (struct config_section *sec = cfg->sections; sec; sec = sec->next)
		block_match(sec, &sec->block, true);
}

static void
config_fill(struct curtain_config *cfg)
{
	for (struct config_section *sec = cfg->sections; sec; sec = sec->next)
		if (!sec->slot_synced) {
			if (sec->slot_owned) {
				COMMAND_DIAG(3, sec, &sec->block, "dropping slot");
				curtain_drop(sec->slot);
				sec->slot = NULL;
				sec->slot_filled = sec->slot_owned = false;
			} else if (sec->slot_filled)
				continue;
			for (struct config_command *cmd = sec->commands; cmd; cmd = cmd->next)
				if (cmd->block->matched) {
					COMMAND_DIAG(4, sec, cmd, "perform");
					cmd->perform(sec, cmd);
				}
			sec->slot_filled = sec->slot;
			sec->slot_synced = true;
		}
}


struct directive_ctx {
	const struct config_directive *dir;
	int flags;
	struct directive_word {
		struct directive_word *next;
		char *str;
		size_t len;
	} *head, **link;
	struct config_guard *guard;
};

struct config_directive {
	const char name[14];
	bool raw_words;
	bool need_explicit_flags;
	int extra_flags;
	void (*perform)(struct config_section *, struct config_command *);
	void (*parse)(struct config_parser *, struct directive_ctx *);
};

static void
parse_merge(struct config_parser *par, struct directive_ctx *ctx)
{
	struct config_block *blk = par->current_block;
	for (struct directive_word *word = ctx->head; word; word = word->next) {
		struct config_merge *mrg;
		mrg = emalloc(sizeof *blk->merges);
		*mrg = (struct config_merge){
			.next = blk->merges,
			.tag = tag_get(par->cfg, word->str),
		};
		blk->merges = mrg;
	}
}

static int
do_include_callback(void *ctx1, char *path)
{
	struct config_parser *par = ctx1;
	struct config_block *blk = par->current_block;
	struct config_include *inc;
	if (path[0] != '/') {
		PARSE_ERROR(par, "include path must be absolute");
		return (0);
	}
	inc = emalloc(sizeof *inc + strlen(path) + 1);
	*inc = (struct config_include){ .next = blk->new_includes };
	strcpy(inc->path, path);
	blk->new_includes = inc;
	return (0);
}

static void
parse_include(struct config_parser *par, struct directive_ctx *ctx)
{
	for (struct directive_word *word = ctx->head; word; word = word->next) {
		char path[PATH_MAX];
		const char *error;
		int r;
		r = pathexp(word->str, path, sizeof path, &error, do_include_callback, par);
		if (r < 0)
			PARSE_ERROR(par, "path expansion: %s", error);
	}
}

static const struct config_directive directives[] = {
	{ .name = "diag", .perform = perform_diag },
	{ .name = "tmpdir", .perform = perform_tmpdir },
	{ .name = "merge", .parse = parse_merge },
	{ .name = "push", .parse = parse_merge },
	{ .name = "include", .parse = parse_include, .raw_words = true },
	{ .name = "default", .perform = perform_default, .need_explicit_flags = true },
	{ .name = "ability", .perform = perform_ability },
	{ .name = "sysctl", .perform = perform_sysctl },
	{ .name = "priv", .perform = perform_priv },
	{ .name = "ioctl", .perform = perform_ioctl },
	{ .name = "ioctls", .perform = perform_ioctl },
	{ .name = "sockaf", .perform = perform_sockaf },
	{ .name = "socklvl", .perform = perform_socklvl },
	{ .name = "fibnum", .perform = perform_fibnum },
	{ .name = "path", .perform = perform_unveil, .raw_words = true },
	{ .name = "unveil", .perform = perform_unveil, .raw_words = true,
	  .extra_flags = CURTAIN_PATH_NOSTAT | CURTAIN_PATH_NOLIST },
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
	{ "nofollow",	CURTAIN_PATH_NOFOLLOW },
	{ "nostat",	CURTAIN_PATH_NOSTAT },
	{ "nolist",	CURTAIN_PATH_NOLIST },
};

static const struct config_directive *
find_directive(const char *name)
{
	for (const struct config_directive *dir = directives;
	    dir < &directives[nitems(directives)];
	    dir++)
		if (strcmp(dir->name, name) == 0)
			return (dir);
	return (NULL);
}

static void
parse_directive_3(struct config_parser *par, struct directive_ctx *ctx)
{
	size_t count, size, index;
	struct directive_word *word;
	struct config_section *sec;
	struct config_block *saved_block;

	for (count = size = 0, word = ctx->head; word; word = word->next) {
		word->str[word->len] = '\0';
		if (!ctx->dir->raw_words)
			word->len = unescape(word->str) - word->str;
		count++;
		size += word->len + 1;
	}

	sec = section_get(par);
	saved_block = par->current_block;

	if (ctx->guard) {
		block_make(par, ctx->guard);
		ctx->guard = NULL;
	}

	if (ctx->dir->parse) {
		ctx->dir->parse(par, ctx);

	} else {
		struct config_command *cmd;
		char *q;
		cmd = command_make(par, count, size);
		q = (char *)&cmd->words[count];
		cmd->perform = ctx->dir->perform;
		cmd->curtain_flags = ctx->dir->extra_flags | ctx->flags;
		for (index = 0, word = ctx->head; word; word = word->next) {
			cmd->words[index++] = q;
			memcpy(q, word->str, word->len + 1);
			q += word->len + 1;
			assert(word->str[word->len] == '\0');
		}

		*sec->commands_tail = cmd;
		sec->commands_tail = &cmd->next;
	}

	par->current_block = saved_block;
}

static struct config_guard *parse_guard_or(struct config_parser *);

static void
parse_directive_2(struct config_parser *par, char *p, struct directive_ctx *ctx)
{
	while (*(p = skip_spaces(p)) == '[') {
		par->cursor = ++p;
		ctx->guard = parse_guard_or(par);
		p = par->cursor;
		if (*p++ != ']') {
			PARSE_ERROR(par, "expected closing bracket");
			goto error;
		}
		*ctx->link = NULL;
		parse_directive_3(par, ctx);
		ctx->guard = NULL;
		*(ctx->link = &ctx->head) = NULL;
		if (!*(p = skip_spaces(p)))
			return;
	}

	if (*p) {
		/* recurse to make a linked list of words on the stack */
		char *q;
		struct directive_word w;
		q = skip_word(p, "");
		if (q == p) {
			PARSE_ERROR(par, "invalid word");
			goto error;
		}
		w.str = p;
		w.len = q - p;
		*ctx->link = &w;
		ctx->link = &w.next;
		parse_directive_2(par, q, ctx);
		return;
	}

	par->cursor = p;
	*ctx->link = NULL;
	parse_directive_3(par, ctx);
	return;
error:
	if (ctx->guard)
		guard_free(ctx->guard);
}

static void
parse_directive_1(struct config_parser *par, const struct config_directive *dir, int flags)
{
	struct directive_ctx ctx = {
		.dir = dir,
		.flags = flags,
		.head = NULL,
		.link = &ctx.head,
	};
	return (parse_directive_2(par, par->cursor, &ctx));
}

static void
parse_directive(struct config_parser *par)
{
	const struct config_directive *dir;
	char *name, *name_end, *p, c;
	int unsafety;
	int flags;
	bool explicit_flags;

	p = par->cursor;
	name = p = skip_spaces(p);
	name_end = p = skip_word(p, "-!:");

	flags = 0;
	explicit_flags = false;
	while (*p == '-') {
		char *q;
		bool found;
		q = skip_word(++p, "-!:");
		c = *q;
		*q = '\0';
		found = false;
		for (size_t i = 0; i < nitems(directive_flags); i++)
			if (strcmp(directive_flags[i].name, p) == 0) {
				found = true;
				explicit_flags = true;
				flags |= directive_flags[i].flags;
				break;
			}
		if (!found) {
			PARSE_ERROR(par, "unknown directive flag: %s", p);
			return;
		}
		*q = c;
		p = q;
	}

	unsafety = 0;
	while (*p == '!')
		p++, unsafety++;
	if (unsafety > par->cfg->unsafety)
		return;

	if (*p == ':') /* intended for argv directives */
		p++;

	par->cursor = p;
	c = *name_end;
	*name_end = '\0';
	if ((dir = find_directive(name))) {
		if (dir->need_explicit_flags && !explicit_flags) {
			PARSE_ERROR(par, "expected explicit flags");
			return;
		}
		*name_end = c;
		parse_directive_1(par, dir, flags);
		return;
	}
	PARSE_ERROR(par, "unknown directive: %s", name);
}

/* [a !b c, d e, f, g h (i, j)] -> (a && !b && c) || (d && e) || f || (g && h && (i || j)) */

static struct config_guard *
parse_guard_term(struct config_parser *par)
{
	struct config_guard *guard;
	char *p, c, *name, *name_end;
	bool negated;
	p = par->cursor;

	negated = false;
	while (*(p = skip_spaces(p)) == '!')
		p++, negated = !negated;

	if (*p == '(') {
		par->cursor = ++p;
		guard = parse_guard_or(par);
		p = par->cursor;
		if (*(p = skip_spaces(p)) == ')') {
			p++;
		} else {
			PARSE_ERROR(par, "expected closing parenthesis");
			return (NULL);
		}

	} else {
		name_end = p = skip_word((name = p), ",:()[]");
		if (name == name_end)
			return (NULL);
		c = *name_end;
		*name_end = '\0';
		unescape(name);
		guard = guard_make_tag(tag_get(par->cfg, name));
		*name_end = c;
	}

	if (negated)
		guard = guard_make_child(CONFIG_GUARD_NOT, guard);
	par->cursor = p;
	return (guard);
}

static struct config_guard *
parse_guard_and(struct config_parser *par)
{
	struct config_guard *and_guard, *term_guard;
	and_guard = NULL;
	while ((term_guard = parse_guard_term(par)))
		if (and_guard) {
			assert(!and_guard->next);
			if (and_guard->type != CONFIG_GUARD_AND)
				and_guard = guard_make_child(CONFIG_GUARD_AND, and_guard);
			term_guard->next = and_guard->child;
			and_guard->child = term_guard;
		} else
			and_guard = term_guard;
	return (and_guard);
}

static struct config_guard *
parse_guard_or(struct config_parser *par)
{
	struct config_guard *or_guard, *and_guard;
	or_guard = NULL;
	while ((and_guard = parse_guard_and(par))) {
		while (*(par->cursor = skip_spaces(par->cursor)) == ',')
			par->cursor++;
		if (or_guard) {
			assert(!or_guard->next);
			if (or_guard->type != CONFIG_GUARD_OR)
				or_guard = guard_make_child(CONFIG_GUARD_OR, or_guard);
			and_guard->next = or_guard->child;
			or_guard->child = and_guard;
		} else
			or_guard = and_guard;
	}
	return (or_guard);
}

static void
parse_section(struct config_parser *par)
{
	struct config_block *blk;
	char *p;

	par->current_section = NULL;
	section_get(par);
	blk = par->current_block;

	par->cursor++;
	blk->guard = parse_guard_or(par);

	p = par->cursor;
	if (*(p = skip_spaces(p)) == ':') {
		p++;
		while (*(p = skip_spaces(p))) {
			struct config_merge *mrg;
			char *q, c;
			q = skip_word(p, ",:()]");
			if (p == q)
				break;
			c = *q;
			*q = '\0';
			mrg = emalloc(sizeof *blk->merges);
			*mrg = (struct config_merge){
				.next = blk->merges,
				.tag = tag_get(par->cfg, p),
			};
			blk->merges = mrg;
			*q = c;
			p = q;
		}
		par->cursor = p;
	}
	if (*p++ != ']') {
		PARSE_ERROR(par, "expected closing bracket");
		/* disable section */
		if (blk->guard)
			guard_free(blk->guard);
		blk->guard = guard_make_child(CONFIG_GUARD_OR, NULL); /* false when no arguments */
		return;
	}
	if (*(p = skip_spaces(p))) {
		PARSE_ERROR(par, "unexpected characters at end of line");
		return;
	}
}


static void
parse_line(struct config_parser *par)
{
next:	switch (*par->cursor) {
	case '\0':
	case '#':
		return;
	SPACE_CASES
		par->cursor++;
		goto next;
	case '[':
		parse_section(par);
		return;
	case '\\':
	case '/':
	case '.':
	case '{':
	case '$':
	case '~':
	case '%': {
		static const struct config_directive *unveil_dir = NULL;
		if (!unveil_dir)
			unveil_dir = find_directive("path");
		parse_directive_1(par, unveil_dir, 0);
		return;
	}
	case '@': /* old syntax */
		par->cursor++;
		/* FALLTHROUGH */
	default:
		parse_directive(par);
		return;
	}
}

static void
parse_config(struct config_parser *par)
{
	size_t size;
	while ((par->line = fgetln(par->file, &size))) {
		if (!size || par->line[size - 1] != '\n') {
			PARSE_ERROR(par, "unterminated line");
			break;
		}
		par->line[size - 1] = '\0';
		par->cursor = par->line;
		par->line_no++;
		parse_line(par);
	}
	if (ferror(par->file))
		PARSE_ERROR(par, "%m");
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
process_file_at(struct curtain_config *cfg,
    const char *base_path, int base_fd, const char *sub_path)
{
	char path[PATH_MAX];
	struct config_parser par = {
		.cfg = cfg,
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
	if (par.cfg->verbosity >= 1)
		warnx("parsing file: %s", par.file_name);
	parse_config(&par);
	saved_errno = errno;
	fclose(par.file);
	errno = saved_errno;
	if (par.errors) {
		cfg->errors = true;
		return (-1);
	}
	return (0);
}

static int
process_file(struct curtain_config *cfg, const char *path)
{
	return (process_file_at(cfg, "", AT_FDCWD, path));
}

static void
process_dir_tag(struct curtain_config *cfg, struct config_tag *tag,
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
process_dir(struct curtain_config *cfg, const char *base, bool do_all_tags)
{
	int dir_fd, r;
	dir_fd = open(base, O_SEARCH | O_DIRECTORY | O_CLOEXEC);
	if (dir_fd < 0) {
		if (errno != ENOENT)
			warn("%s", base);
		return;
	}

	for (struct config_tag *tag = cfg->tags_current;
	    tag != (do_all_tags ? NULL : cfg->tags_visited);
	    tag = tag->next)
		if (tag->enabled)
			process_dir_tag(cfg, tag, base, dir_fd);

	r = close(dir_fd);
	if (r < 0)
		warn("%s", base);
}

static void
process_includes(struct curtain_config *cfg)
{
	struct config_include *inc;
	bool visited;
	for (inc = cfg->incs_current, visited = false; inc; inc = inc->next) {
		if (inc == cfg->incs_visited)
			visited = true;
		assert(*inc->path);
		if (inc->path[strlen(inc->path) - 1] == '/')
			process_dir(cfg, inc->path, !visited);
		else if (!visited)
			process_file(cfg, inc->path);
	}
}

void
curtain_config_load(struct curtain_config *cfg)
{
	unsigned pass_no = 0;
	do {
		pass_no++;
		CONFIG_DIAG(1, cfg, "loading pass %u", pass_no);

		cfg->tags_current = cfg->tags_pending;
		cfg->incs_current = cfg->incs_pending;

		process_includes(cfg);

		cfg->tags_visited = cfg->tags_current;
		cfg->incs_visited = cfg->incs_current;

		config_sweep(cfg);
		config_match(cfg);

	} while (cfg->tags_current != cfg->tags_pending ||
	         cfg->incs_current != cfg->incs_pending);

	CONFIG_DIAG(1, cfg, "filling slots");
	config_fill(cfg);
	CONFIG_DIAG(2, cfg, "done filling slots");
}

int
curtain_config_directive(struct curtain_config *cfg, struct curtain_slot *slot,
    const char *directive)
{
	struct config_section *sec;
	struct config_parser par = {
		.cfg = cfg,
		.file_name = "(argv)",
	};
	par.line = par.cursor = estrdup(directive);
	sec = section_get(&par);
	if (!sec->slot)
		sec->slot = slot;
	parse_directive(&par);
	free(par.line);
	return (par.errors ? -1 : 0);
}

void
curtain_config_setups(struct curtain_config *cfg)
{
	int r;
	if (cfg->setup_separate_tmpdir == CONFIG_SETUP_WANT) {
		r = curtain_config_setup_tmpdir(cfg);
		if (r == 0)
			cfg->setup_separate_tmpdir = CONFIG_SETUP_DONE;
	}
}

int
curtain_config_apply(struct curtain_config *cfg)
{
	curtain_config_load(cfg);
	curtain_config_setups(cfg);
	CONFIG_DIAG(2, cfg, "applying slots");
	return (curtain_apply());
}


static void
curtain_config_init(struct curtain_config *cfg, unsigned flags)
{
	char path[PATH_MAX];
	const char *home;
	bool tainted = issetugid() != 0;

	*cfg = (struct curtain_config){
		.on_exec_only = flags & CURTAIN_CONFIG_ON_EXEC_ONLY,
	};

	if (tainted || !(cfg->old_tmpdir = getenv("TMPDIR")))
		cfg->old_tmpdir = _PATH_TMP;

	if (!(flags & CURTAIN_CONFIG_NO_STD_INCS)) {
		if (!tainted && (home = getenv("HOME"))) {
			pathfmt(path, "%s/.curtain.d/", home);
			include_add(cfg, path);
			pathfmt(path, "%s/.curtain.conf", home);
			include_add(cfg, path);
		}
		include_add(cfg, _PATH_ETC "/curtain.d/");
		include_add(cfg, _PATH_ETC "/curtain.conf");
		include_add(cfg, _PATH_ETC "/defaults/curtain.conf");
	}
}

struct curtain_config *
curtain_config_new(unsigned flags)
{
	struct curtain_config *cfg;
	cfg = emalloc(sizeof *cfg);
	curtain_config_init(cfg, flags);
	return (cfg);
}

void
curtain_config_free(struct curtain_config *cfg)
{
	for (struct config_section *sec = cfg->sections, *next; sec; sec = next) {
		next = sec->next;
		section_free(sec);
	}
	for (struct config_include *inc = cfg->incs_pending, *next; inc; inc = next) {
		next = inc->next;
		free(inc);
	}
	for (struct config_tag *tag = cfg->tags_pending, *next; tag; tag = next) {
		next = tag->next;
		free(tag);
	}
	free(cfg);
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
curtain_config_tags_from_env(struct curtain_config *cfg, const char *env_var_name)
{
	char *p, *q, c;
	if (!env_var_name)
		env_var_name = "CURTAIN_TAGS";
	if (issetugid() || !(p = getenv(env_var_name)))
		return;
	q = p;
	do {
		if (!*q || is_space(*q)) {
			if (p != q) {
				c = *q, *q = '\0';
				tag_push(cfg, p);
				*q = c;
			}
			if (!*q)
				break;
			p = ++q;
		} else
			q++;
	} while (true);
}

void
curtain_config_tags_clear(struct curtain_config *cfg)
{
	for (struct config_tag *tag = cfg->tags_pending; tag; tag = tag->next)
		tag->enabled = false;
	cfg->tags_dropped = true;
}

void
curtain_config_tag_push(struct curtain_config *cfg, const char *name)
{
	struct config_tag *tag;
	tag = tag_push(cfg, name);
	tag->locked = true;
}

void
curtain_config_tag_drop(struct curtain_config *cfg, const char *name)
{
	struct config_tag *tag;
	tag = tag_get(cfg, name);
	if (tag->enabled)
		cfg->tags_dropped = true;
	tag->enabled = false;
	tag->locked = false;
}

void
curtain_config_tag_block(struct curtain_config *cfg, const char *name)
{
	struct config_tag *tag;
	tag = tag_get(cfg, name);
	if (tag->enabled)
		cfg->tags_dropped = true;
	tag->enabled = false;
	tag->locked = true;
}

