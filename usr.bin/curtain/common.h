#ifndef	_CURTAIN_COMMON_H
#define	_CURTAIN_COMMON_H

#include <stdbool.h>
#include <string.h>
#include <curtain.h>
#include <sys/unveil.h>

struct config {
	struct config_tag *tags_pending, *tags_current, *tags_visited;
	unsigned unsafe_level;
	bool verbose;
};

struct config_tag {
	struct config_tag *chain;
	char name[];
};

int parse_unveil_perms(unveil_perms *, const char *);

struct config_tag *config_tag_push_mem(struct config *, const char *buf, size_t len);

static inline struct config_tag *
config_tag_push(struct config *cfg, const char *name)
{
	return (config_tag_push_mem(cfg, name, strlen(name)));
}

void config_load_tags(struct config *);


bool is_tmpdir(const char *path);
void protect_shared_dir(struct curtain_slot *, const char *tmpdir);


extern const struct privent {
	const char *name;
	int priv;
} privtab[];

extern const struct sysfilent {
	const char *name;
	int sysfil;
} sysfiltab[];

#endif
