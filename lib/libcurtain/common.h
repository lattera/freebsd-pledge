#ifndef	_CURTAIN_COMMON_H
#define	_CURTAIN_COMMON_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include <sys/curtain_ability.h>

struct curtain_config {
	struct config_tag *tags_pending, *tags_current, *tags_visited, *tags_enabled, *tags_blocked;
	struct config_section *sections;
	const char *old_tmpdir;
	int unsafety;
	int verbosity;
	bool on_exec_only;
	bool tags_dropped;
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
