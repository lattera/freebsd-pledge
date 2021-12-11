#ifndef	_SYS_UNVEIL_H_
#define	_SYS_UNVEIL_H_

#include <sys/types.h>
#include <sys/_unveil.h>

#define	UPERM_NONE		(0)
#define	UPERM_EXPOSE		(1 <<  0)
#define	UPERM_TRAVERSE		(1 <<  1)
#define	UPERM_SEARCH		(1 <<  2)
#define	UPERM_STATUS		(1 <<  3)
#define	UPERM_INSPECT		(UPERM_EXPOSE | UPERM_SEARCH | UPERM_STATUS)
#define	UPERM_LIST		(1 <<  4)
#define	UPERM_BROWSE		(1 <<  8)
#define	UPERM_READ		(1 <<  9)
#define	UPERM_WRITE		(1 << 10)
#define	UPERM_CREATE		(1 << 11)
#define	UPERM_DELETE		(1 << 12)
#define	UPERM_EXECUTE		(1 << 13)
#define	UPERM_SETATTR		(1 << 14)
#define	UPERM_APPEND		(1 << 15)
#define	UPERM_BIND		(1 << 16)
#define	UPERM_CONNECT		(1 << 17)
#define	UPERM_UNIX		(UPERM_BIND | UPERM_CONNECT)
#define	UPERM_TMPDIR		(1 << 24)
#define	UPERM_TMPDIR_CHILD	(1 << 25)
#define	UPERM_DEVFS		(1 << 26)
#define	UPERM_ALL		(-1)

static const unveil_perms uperms_inheritable =
    UPERM_BROWSE | UPERM_READ | UPERM_APPEND | UPERM_WRITE | UPERM_CREATE | UPERM_DELETE |
    UPERM_EXECUTE | UPERM_SETATTR | UPERM_BIND | UPERM_CONNECT |
    UPERM_DEVFS;

static const unveil_perms uperms_searchable = uperms_inheritable | UPERM_TMPDIR;
static const unveil_perms uperms_exposable = uperms_searchable & ~UPERM_DEVFS;

static inline unveil_perms
uperms_expand(unveil_perms uperms)
{
	if (uperms & uperms_searchable)
		uperms |= UPERM_SEARCH;
	if (uperms & uperms_exposable)
		uperms |= UPERM_EXPOSE;
	if (uperms & UPERM_WRITE)
		uperms |= UPERM_APPEND;
	if (uperms & (UPERM_BROWSE | UPERM_READ))
		uperms |= UPERM_STATUS | UPERM_BROWSE | UPERM_LIST;
	if (uperms & UPERM_SEARCH)
		uperms |= UPERM_TRAVERSE;
	if (uperms & UPERM_READ && uperms & UPERM_WRITE &&
	    uperms & UPERM_CREATE && uperms & UPERM_DELETE)
		uperms |= UPERM_TMPDIR;
	return (uperms);
}

static inline unveil_perms
uperms_inherit_1(unveil_perms uperms)
{
	return ((uperms & uperms_inheritable) |
	    (uperms & UPERM_TMPDIR ? UPERM_TMPDIR_CHILD : UPERM_NONE));
}

static inline unveil_perms
uperms_inherit(unveil_perms uperms)
{
	return (uperms_expand(uperms_inherit_1(uperms)));
}

#endif
