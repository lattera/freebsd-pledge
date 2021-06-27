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
	bool need_reprotect;
};

struct config_tag {
	struct config_tag *chain;
	char name[];
};

int cwd_is_within(const char *path);

int parse_unveil_perms(unveil_perms *, const char *);

void config_init(struct config *);

struct config_tag *config_tag_push_mem(struct config *, const char *buf, size_t len);

static inline struct config_tag *
config_tag_push(struct config *cfg, const char *name)
{
	return (config_tag_push_mem(cfg, name, strlen(name)));
}

void config_load_tags(struct config *);


extern const struct privent {
	const char *name;
	int priv;
} privtab[];

extern const struct sysfilent {
	const char *name;
	int sysfil;
} sysfiltab[];

extern const struct socklvlent {
	const char *name;
	int socklvl;
} socklvltab[];

extern const struct sockafent {
	const char *name;
	int sockaf;
} sockaftab[];


#endif
