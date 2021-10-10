#ifndef	_CURTAIN_COMMON_H
#define	_CURTAIN_COMMON_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include <sys/curtain_ability.h>

struct curtain_config {
	struct curtain_config_tag *tags_pending, *tags_current, *tags_visited;
	const char *old_tmpdir;
	int unsafety;
	int verbosity;
	bool on_exec_only;
};

struct curtain_config_tag {
	struct curtain_config_tag *chain;
	bool blocked;
	char name[];
};

int curtain_cwd_is_within(const char *path);


extern const struct privent {
	const char *name;
	int priv;
} curtain_privtab[];

extern const struct abilityent {
	const char *name;
	enum curtain_ability ability;
} curtain_abilitytab[];

extern const struct socklvlent {
	const char *name;
	int socklvl;
} curtain_socklvltab[];

extern const struct sockafent {
	const char *name;
	int sockaf;
} curtain_sockaftab[];

#endif
