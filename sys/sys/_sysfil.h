#ifndef _SYS_SYSFILSET_H_
#define	_SYS_SYSFILSET_H_

#include <sys/types.h>
#include <sys/_bitset.h>

#define	SYSFILSET_BITS	128

/*
 * A sysfilset_t is a bitmap indexed by a value made up of an optional general
 * sysfil category value optionally OR'd with SYSFIL_CAPSICUM.
 */
BITSET_DEFINE(_sysfilset, SYSFILSET_BITS);
typedef struct _sysfilset sysfilset_t;

#define	SYSFILSET_INITIALIZER	BITSET_T_INITIALIZER(0)
#define	SYSFILSET_MATCH(s, i)	BIT_ISSET(SYSFILSET_BITS, i, s)
#define	SYSFILSET_EQUAL(s, ss)	(BIT_CMP(SYSFILSET_BITS, s, ss) == 0)
#define	SYSFILSET_MASK(t, s)	BIT_AND(SYSFILSET_BITS, t, s)
#define	SYSFILSET_MERGE(t, s)	BIT_OR(SYSFILSET_BITS, t, s)

/*
 * Set bit c and c + 1 for syscall category c.  This will match both the
 * Capsicum and non-Capsicum subsets.
 */
#define SYSFILSET_FILL(s, i) do { \
	BIT_SET(SYSFILSET_BITS, (i) & ~SYSFIL_CAPSICUM, (s)); \
	BIT_SET(SYSFILSET_BITS, (i) |  SYSFIL_CAPSICUM, (s)); \
} while (0)

#define	SYSFILSET_FILL_ALL(s)	BIT_FILL(SYSFILSET_BITS, s);

#define	SYSFILSET_IS_RESTRICTED(s) \
	(!BIT_ISFULLSET(SYSFILSET_BITS, s))
/*
 * Every odd (if counting them from zero) bit positions set.  This matches the
 * subset of every syscall category that is enabled for Capsicum.
 */
#define	SYSFILSET_LITERAL_CAPSICUM \
	(sysfilset_t)BITSET_T_INITIALIZER( \
		BITSET_ASET(__bitset_words(SYSFILSET_BITS), 0xaaaaaaaaaaaaaaaaULL))

#define	SYSFILSET_IS_CAPSICUM(s) ({ \
	sysfilset_t __sysfilset_cap = SYSFILSET_LITERAL_CAPSICUM; \
	sysfilset_t __sysfilset_tmp = *s; \
	BIT_ANDNOT(SYSFILSET_BITS, &__sysfilset_tmp, &__sysfilset_cap); \
	BIT_EMPTY(SYSFILSET_BITS, &__sysfilset_tmp); \
})

#endif
