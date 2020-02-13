#ifndef	_SYS_PLEDGE_SET_H
#define	_SYS_PLEDGE_SET_H

#include <sys/types.h>
#include <sys/stdint.h>

/* XXX TODO: turn into a real option */
#define	PLEDGE

enum pledge_promise {
	PLEDGE_NULL = 0,
	/*
	 * PLEDGE_CAPSICUM (usable with pledge("capsicum")) can be used by a
	 * pledged application to enable all syscalls that Capsicum would
	 * generally allow.  Whatever security checks are needed to make those
	 * syscalls safe for a sandboxed application (correctly designed to use
	 * FDs as capabilities) will be done even if Capsicum's capability mode
	 * isn't enabled.  This may be useful when spawning a Capsicumized
	 * child process with inherited pledges.
	 *
	 * Using this pledge does not change in any way the general rule that
	 * pledge() and Capsicum restrictions stack (i.e., an operation must be
	 * allowed by both pledge() and Capsicum if both are used together), it
	 * is merely a way to explicitly make pledge() less restrictive so that
	 * it may work better with Capsicum.
	 */
	PLEDGE_CAPSICUM,
	PLEDGE_ERROR,
	PLEDGE_STDIO,
	PLEDGE_UNVEIL,
	PLEDGE_RPATH,
	PLEDGE_WPATH,
	PLEDGE_CPATH,
	PLEDGE_DPATH,
	PLEDGE_TMPPATH,
	PLEDGE_FLOCK,
	PLEDGE_FATTR,
	PLEDGE_CHOWN,
	PLEDGE_PROC,
	PLEDGE_EXEC,
	PLEDGE_ID,
	PLEDGE_TTY,
	PLEDGE_SETTIME,
	PLEDGE_INET,
	PLEDGE_UNIX,
	PLEDGE_DNS,
	PLEDGE_COUNT /* must come last */
};

#ifdef PLEDGE

typedef uint32_t pledge_flags_t; /* should generally not be used directly */

typedef struct {
	pledge_flags_t pflags;
} pledge_set_t;

static inline void
pledge_set_init(pledge_set_t *pl) {
	pl->pflags = ~(pledge_flags_t)0;
}

static inline int
pledge_set_test(const pledge_set_t *pl, enum pledge_promise pr) {
	return pl->pflags & ((pledge_flags_t)1 << pr);
}

#endif

#endif
