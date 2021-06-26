#ifndef	_CURTAIN_COMMON_H
#define	_CURTAIN_COMMON_H

#include <stdbool.h>

struct config {
	const char **tags_base, **tags_last, **tags_fill, **tags_end;
	unsigned unsafe_level;
	bool skip_default_tag;
};

void load_tags(struct config *);

extern const struct privent {
	const char *name;
	int priv;
} privtab[];

extern const struct sysfilent {
	const char *name;
	int sysfil;
} sysfiltab[];

#endif
