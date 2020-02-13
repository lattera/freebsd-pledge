#ifndef	_SYS_SYSFIL_H_
#define	_SYS_SYSFIL_H_

#include <sys/types.h>

/*
 * Each syscall has a filter bitmap associated with it.  Each bit that is set
 * allows this syscall to be used when the user also has this filter bit set in
 * its credentials bitmap.
 */

typedef u_int32_t sysfil_t;

/*
 * Used internally when there should be at least one bit set.
 */
#define	SYF_DEFAULT		0x00000001
/*
 * A system call is permitted in capability mode.
 */
#define	SYF_CAPENABLED		0x00000002
/*
 * Note that not all pledge(2) promises are included here, only those that
 * directly correspond to a set of syscalls to be filtered.
 */
#define	SYF_PLEDGE_ALWAYS	0x00000004
#define	SYF_PLEDGE_STDIO	0x00000008
#define	SYF_PLEDGE_SETTIME	0x00000010
#define	SYF_PLEDGE_PROC		0x00000020
#define	SYF_PLEDGE_ID		0x00000040
#define	SYF_PLEDGE_UNVEIL	0x00000080
#define	SYF_PLEDGE_EXEC		0x00000100
#define	SYF_PLEDGE_RPATH	0x00000200
#define	SYF_PLEDGE_WPATH	0x00000400
#define	SYF_PLEDGE_CPATH	0x00000800
#define	SYF_PLEDGE_TMPPATH	0x00001000
#define	SYF_PLEDGE_DPATH	0x00002000
#define	SYF_PLEDGE_TTY		0x00004000
#define	SYF_PLEDGE_FATTR	0x00008000
#define	SYF_PLEDGE_CHOWN	0x00010000
#define	SYF_PLEDGE_INET		0x00020000
#define	SYF_PLEDGE_UNIX		0x00040000
#define	SYF_PLEDGE_DNS		0x00080000
#define	SYF_PLEDGE_FLOCK	0x00100000
#define	SYF_PLEDGE_YPACTIVE	0x00200000

#endif
