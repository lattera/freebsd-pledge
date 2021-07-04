#ifndef	_CURTAIN_COMMON_H
#define	_CURTAIN_COMMON_H

#include <stdbool.h>

struct curtain_config_tag {
	struct curtain_config_tag *chain;
	char name[];
};

int curtain_cwd_is_within(const char *path);


extern const struct privent {
	const char *name;
	int priv;
} curtain_privtab[];

extern const struct sysfilent {
	const char *name;
	int sysfil;
} curtain_sysfiltab[];

extern const struct socklvlent {
	const char *name;
	int socklvl;
} curtain_socklvltab[];

extern const struct sockafent {
	const char *name;
	int sockaf;
} curtain_sockaftab[];

#endif
