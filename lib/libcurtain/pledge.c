#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <paths.h>
#include <pwd.h>
#include <grp.h>
#include <nsswitch.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <resolv.h>

#include <curtain.h>
#include <pledge.h>

enum promise_type {
	PROMISE_ERROR,
	PROMISE_TRAP,
	PROMISE_BASIC, /* same as PROMISE_STDIO but without the unveils */
	PROMISE_STDIO,
	PROMISE_UNVEIL,
	PROMISE_RPATH,
	PROMISE_WPATH,
	PROMISE_CPATH,
	PROMISE_DPATH,
	PROMISE_TMPPATH,
	PROMISE_FLOCK,
	PROMISE_FATTR,
	PROMISE_CHOWN,
	PROMISE_ID,
	PROMISE_PROC,
	PROMISE_REAP,
	PROMISE_THREAD,
	PROMISE_EXEC,
	PROMISE_PROT_EXEC,
	PROMISE_TTY,
	PROMISE_PTS,
	PROMISE_RLIMIT,
	PROMISE_SCHED,
	PROMISE_SETTIME,
	PROMISE_FFCLOCK,
	PROMISE_MLOCK,
	PROMISE_AIO,
	PROMISE_EXTATTR,
	PROMISE_ACL,
	PROMISE_MAC,
	PROMISE_CPUSET,
	PROMISE_SYSVIPC,
	PROMISE_POSIXIPC,
	PROMISE_POSIXRT,
	PROMISE_CHROOT,
	PROMISE_JAIL,
	PROMISE_PS,
	PROMISE_FSUGID,
	PROMISE_SYSFLAGS,
	PROMISE_SENDFILE,
	PROMISE_NET,
	PROMISE_UNIX,
	PROMISE_INET,
	PROMISE_MCAST,
	PROMISE_SETFIB,
	PROMISE_ROUTE,
	PROMISE_RECVFD,
	PROMISE_SENDFD,
	PROMISE_DNS,
	PROMISE_GETPW,
	PROMISE_SSL,
	PROMISE_CRYPTODEV,
	PROMISE_MOUNT,
	PROMISE_QUOTA,
	PROMISE_FH,
	PROMISE_ANY_SOCKAF,
	PROMISE_ANY_PRIV,
	PROMISE_ANY_IOCTL,
	PROMISE_ANY_SOCKOPT,
	PROMISE_ANY_SYSCTL,
	PROMISE_AUDIO,
	PROMISE_COUNT /* must be last */
};

#define	PROMISE_NAME_SIZE 16
static const struct promise_name {
	const char name[PROMISE_NAME_SIZE];
} names_table[PROMISE_COUNT] = {
	[PROMISE_ERROR] =		{ "error" },
	[PROMISE_TRAP] =		{ "trap" },
	[PROMISE_BASIC] =		{ "basic" },
	[PROMISE_STDIO] =		{ "stdio" },
	[PROMISE_UNVEIL] =		{ "unveil" },
	[PROMISE_RPATH] =		{ "rpath" },
	[PROMISE_WPATH] =		{ "wpath" },
	[PROMISE_CPATH] =		{ "cpath" },
	[PROMISE_DPATH] =		{ "dpath" },
	[PROMISE_TMPPATH] =		{ "tmppath" },
	[PROMISE_FLOCK] =		{ "flock" },
	[PROMISE_FATTR] =		{ "fattr" },
	[PROMISE_CHOWN] =		{ "chown" },
	[PROMISE_ID] =			{ "id" },
	[PROMISE_PROC] =		{ "proc" },
	[PROMISE_REAP] =		{ "reap" },
	[PROMISE_THREAD] =		{ "thread" },
	[PROMISE_EXEC] =		{ "exec" },
	[PROMISE_PROT_EXEC] =		{ "prot_exec" },
	[PROMISE_TTY] =			{ "tty" },
	[PROMISE_PTS] =			{ "pts" },
	[PROMISE_RLIMIT] =		{ "rlimit" },
	[PROMISE_SCHED] =		{ "sched" },
	[PROMISE_SETTIME] =		{ "settime" },
	[PROMISE_FFCLOCK] =		{ "ffclock" },
	[PROMISE_MLOCK] =		{ "mlock" },
	[PROMISE_AIO] =			{ "aio" },
	[PROMISE_EXTATTR] =		{ "extattr" },
	[PROMISE_ACL] =			{ "acl" },
	[PROMISE_MAC] =			{ "mac" },
	[PROMISE_CPUSET] =		{ "cpuset" },
	[PROMISE_SYSVIPC] =		{ "sysvipc" },
	[PROMISE_POSIXIPC] =		{ "posixipc" },
	[PROMISE_POSIXRT] =		{ "posixrt" },
	[PROMISE_CHROOT] =		{ "chroot" },
	[PROMISE_JAIL] =		{ "jail" },
	[PROMISE_PS] =			{ "ps" },
	[PROMISE_FSUGID] =		{ "fsugid" },
	[PROMISE_SYSFLAGS] =		{ "sysflags" },
	[PROMISE_SENDFILE] =		{ "sendfile" },
	[PROMISE_UNIX] =		{ "unix" },
	[PROMISE_INET] =		{ "inet" },
	[PROMISE_MCAST] =		{ "mcast" },
	[PROMISE_SETFIB] =		{ "setfib" },
	[PROMISE_ROUTE] =		{ "route" },
	[PROMISE_RECVFD] =		{ "recvfd" },
	[PROMISE_SENDFD] =		{ "sendfd" },
	[PROMISE_DNS] =			{ "dns" },
	[PROMISE_GETPW] =		{ "getpw" },
	[PROMISE_SSL] =			{ "ssl" },
	[PROMISE_CRYPTODEV] =		{ "cryptodev" },
	[PROMISE_MOUNT] =		{ "mount" },
	[PROMISE_QUOTA] =		{ "quota" },
	[PROMISE_FH] =			{ "fh" },
	[PROMISE_ANY_SOCKAF] =		{ "any_sockaf" },
	[PROMISE_ANY_PRIV] =		{ "any_priv" },
	[PROMISE_ANY_IOCTL] =		{ "any_ioctl" },
	[PROMISE_ANY_SOCKOPT] =		{ "any_sockopt" },
	[PROMISE_ANY_SYSCTL] =		{ "any_sysctl" },
	[PROMISE_AUDIO] =		{ "audio" },
};

static const enum promise_type depends_table[][2] = {
	{ PROMISE_PTS, PROMISE_TTY },
	{ PROMISE_DNS, PROMISE_INET },
	{ PROMISE_DNS, PROMISE_ROUTE }, /* XXX */
	{ PROMISE_INET, PROMISE_NET },
	{ PROMISE_UNIX, PROMISE_NET },
};

static const struct promise_ability {
	enum promise_type promise;
	enum curtain_ability ability;
} abilities_table[] = {
	{ PROMISE_BASIC,		CURTAINABL_STDIO },
	{ PROMISE_STDIO,		CURTAINABL_STDIO },
	{ PROMISE_RPATH,		CURTAINABL_VFS_READ },
	{ PROMISE_WPATH,		CURTAINABL_VFS_WRITE },
	{ PROMISE_CPATH,		CURTAINABL_VFS_CREATE },
	{ PROMISE_CPATH,		CURTAINABL_VFS_DELETE },
	{ PROMISE_DPATH,		CURTAINABL_VFS_FIFO },
	{ PROMISE_DPATH,		CURTAINABL_MAKEDEV },
	{ PROMISE_FLOCK,		CURTAINABL_FLOCK },
	{ PROMISE_FATTR,		CURTAINABL_FATTR },
	{ PROMISE_FATTR,		CURTAINABL_CHFLAGS },
	{ PROMISE_CHOWN,		CURTAINABL_CHOWN },
	{ PROMISE_ID,			CURTAINABL_ID },
	{ PROMISE_ID,			CURTAINABL_ANY_ID },
	{ PROMISE_PROC,			CURTAINABL_PROC },
	{ PROMISE_PROC,			CURTAINABL_SCHED },
	{ PROMISE_REAP,			CURTAINABL_PROC },
	{ PROMISE_REAP,			CURTAINABL_REAP },
	{ PROMISE_THREAD,		CURTAINABL_THREAD },
	{ PROMISE_THREAD,		CURTAINABL_SCHED },
	{ PROMISE_EXEC,			CURTAINABL_EXEC },
	{ PROMISE_PROT_EXEC,		CURTAINABL_PROT_EXEC },
	{ PROMISE_TTY,			CURTAINABL_TTY },
	{ PROMISE_PTS,			CURTAINABL_TTY },
	{ PROMISE_RLIMIT,		CURTAINABL_RLIMIT },
	{ PROMISE_SCHED,		CURTAINABL_SCHED },
	{ PROMISE_SETTIME,		CURTAINABL_SETTIME },
	{ PROMISE_FFCLOCK,		CURTAINABL_FFCLOCK },
	{ PROMISE_MLOCK,		CURTAINABL_MLOCK },
	{ PROMISE_AIO,			CURTAINABL_AIO },
	{ PROMISE_EXTATTR,		CURTAINABL_EXTATTR },
	{ PROMISE_ACL,			CURTAINABL_ACL },
	{ PROMISE_MAC,			CURTAINABL_MAC },
	{ PROMISE_CPUSET,		CURTAINABL_CPUSET },
	{ PROMISE_SYSVIPC,		CURTAINABL_SYSVIPC },
	{ PROMISE_POSIXIPC,		CURTAINABL_POSIXIPC },
	{ PROMISE_POSIXRT,		CURTAINABL_POSIXRT },
	{ PROMISE_CHROOT,		CURTAINABL_CHROOT },
	{ PROMISE_JAIL,			CURTAINABL_JAIL },
	{ PROMISE_PS,			CURTAINABL_PS },
	{ PROMISE_FSUGID,		CURTAINABL_FSUGID },
	{ PROMISE_FSUGID,		CURTAINABL_FMODE_SPECIAL },
	{ PROMISE_SYSFLAGS,		CURTAINABL_SYSFLAGS },
	{ PROMISE_SENDFILE,		CURTAINABL_SENDFILE },
	{ PROMISE_UNIX,			CURTAINABL_VFS_SOCK },
	{ PROMISE_INET,			CURTAINABL_NET_CLIENT },
	{ PROMISE_INET,			CURTAINABL_NET_SERVER },
	{ PROMISE_RECVFD,		CURTAINABL_RECVFD },
	{ PROMISE_SENDFD,		CURTAINABL_SENDFD },
	{ PROMISE_MOUNT,		CURTAINABL_MOUNT },
	{ PROMISE_QUOTA,		CURTAINABL_QUOTA },
	{ PROMISE_FH,			CURTAINABL_FH },
	{ PROMISE_ANY_SOCKAF,		CURTAINABL_ANY_SOCKAF },
	{ PROMISE_ANY_PRIV,		CURTAINABL_ANY_PRIV },
	{ PROMISE_ANY_IOCTL,		CURTAINABL_ANY_IOCTL },
	{ PROMISE_ANY_SOCKOPT,		CURTAINABL_ANY_SOCKOPT },
	{ PROMISE_ANY_SYSCTL,		CURTAINABL_ANY_SYSCTL },
};

static const struct promise_ioctl {
	enum promise_type promise;
	const unsigned long *ioctls;
} ioctls_table[] = {
	{ PROMISE_TTY, curtain_ioctls_tty_basic },
	{ PROMISE_PTS, curtain_ioctls_tty_pts },
	{ PROMISE_NET, curtain_ioctls_net_basic },
	{ PROMISE_ROUTE, curtain_ioctls_net_route },
	{ PROMISE_AUDIO, curtain_ioctls_oss },
	{ PROMISE_CRYPTODEV, curtain_ioctls_cryptodev },
};

static const struct promise_sockaf {
	enum promise_type promise;
	int af;
} sockafs_table[] = {
	{ PROMISE_UNIX, AF_UNIX },
#ifdef AF_INET
	{ PROMISE_INET, AF_INET },
#endif
#ifdef AF_INET6
	{ PROMISE_INET, AF_INET6 },
#endif
};

static const struct promise_sockopt {
	enum promise_type promise;
	int level, optname;
} sockopts_table[] = {
	{ PROMISE_STDIO, SOL_SOCKET, SO_ERROR },
	{ PROMISE_STDIO, SOL_SOCKET, SO_NOSIGPIPE },
	{ PROMISE_NET,  SOL_SOCKET, SO_REUSEADDR },
	{ PROMISE_NET,  SOL_SOCKET, SO_REUSEPORT },
	{ PROMISE_NET,  SOL_SOCKET, SO_REUSEPORT_LB },
	{ PROMISE_NET,  SOL_SOCKET, SO_KEEPALIVE },
	{ PROMISE_NET,  SOL_SOCKET, SO_LINGER },
	{ PROMISE_NET,  SOL_SOCKET, SO_SNDBUF },
	{ PROMISE_NET,  SOL_SOCKET, SO_RCVBUF },
	{ PROMISE_NET,  SOL_SOCKET, SO_SNDLOWAT },
	{ PROMISE_NET,  SOL_SOCKET, SO_RCVLOWAT },
	{ PROMISE_NET,  SOL_SOCKET, SO_SNDTIMEO },
	{ PROMISE_NET,  SOL_SOCKET, SO_RCVTIMEO },
	{ PROMISE_NET,  SOL_SOCKET, SO_TIMESTAMP },
	{ PROMISE_NET,  SOL_SOCKET, SO_BINTIME },
	{ PROMISE_NET,  SOL_SOCKET, SO_ACCEPTCONN },
	{ PROMISE_NET,  SOL_SOCKET, SO_DOMAIN },
	{ PROMISE_NET,  SOL_SOCKET, SO_TYPE },
	{ PROMISE_NET,  SOL_SOCKET, SO_PROTOCOL },
	{ PROMISE_NET,  SOL_SOCKET, SO_PROTOTYPE },
#ifdef AF_INET
	{ PROMISE_INET, IPPROTO_IP, IP_RECVDSTADDR },
	{ PROMISE_INET, IPPROTO_IP, IP_TOS },
	{ PROMISE_INET, IPPROTO_IP, IP_TTL },
	{ PROMISE_INET, IPPROTO_IP, IP_MINTTL },
	{ PROMISE_INET, IPPROTO_IP, IP_DONTFRAG },
	{ PROMISE_INET, IPPROTO_IP, IP_PORTRANGE },
	{ PROMISE_MCAST, IPPROTO_IP, IP_MULTICAST_TTL },
	{ PROMISE_MCAST, IPPROTO_IP, IP_MULTICAST_IF },
	{ PROMISE_MCAST, IPPROTO_IP, IP_MULTICAST_LOOP },
	{ PROMISE_MCAST, IPPROTO_IP, IP_ADD_MEMBERSHIP },
	{ PROMISE_MCAST, IPPROTO_IP, IP_DROP_MEMBERSHIP },
	{ PROMISE_MCAST, IPPROTO_IP, IP_BLOCK_SOURCE },
	{ PROMISE_MCAST, IPPROTO_IP, IP_UNBLOCK_SOURCE },
	{ PROMISE_MCAST, IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP },
	{ PROMISE_MCAST, IPPROTO_IP, IP_DROP_SOURCE_MEMBERSHIP },
#endif
#ifdef AF_INET6
	{ PROMISE_INET, IPPROTO_IPV6, IPV6_UNICAST_HOPS },
	{ PROMISE_INET, IPPROTO_IPV6, IPV6_PORTRANGE },
	{ PROMISE_INET, IPPROTO_IPV6, IPV6_TCLASS },
	{ PROMISE_INET, IPPROTO_IPV6, IPV6_V6ONLY },
	{ PROMISE_MCAST, IPPROTO_IPV6, IPV6_MULTICAST_IF },
	{ PROMISE_MCAST, IPPROTO_IPV6, IPV6_MULTICAST_HOPS },
	{ PROMISE_MCAST, IPPROTO_IPV6, IPV6_MULTICAST_LOOP },
	{ PROMISE_MCAST, IPPROTO_IPV6, IPV6_JOIN_GROUP },
	{ PROMISE_MCAST, IPPROTO_IPV6, IPV6_LEAVE_GROUP },
#endif
#if defined(AF_INET) || defined(AF_INET6)
	{ PROMISE_INET, IPPROTO_TCP, TCP_NODELAY },
	{ PROMISE_INET, IPPROTO_TCP, TCP_MAXSEG },
	{ PROMISE_INET, IPPROTO_TCP, TCP_NOPUSH },
	{ PROMISE_INET, IPPROTO_TCP, TCP_KEEPINIT },
	{ PROMISE_INET, IPPROTO_TCP, TCP_KEEPIDLE },
	{ PROMISE_INET, IPPROTO_TCP, TCP_KEEPINTVL },
	{ PROMISE_INET, IPPROTO_TCP, TCP_KEEPCNT },
	{ PROMISE_INET, IPPROTO_TCP, TCP_INFO },
	{ PROMISE_MCAST, SOL_SOCKET, SO_BROADCAST },
#endif
	{ PROMISE_SETFIB, SOL_SOCKET, SO_SETFIB },
	{ PROMISE_MAC, SOL_SOCKET, SO_LABEL },
	{ PROMISE_MAC, SOL_SOCKET, SO_PEERLABEL },
};

static const struct promise_sysctl {
	enum promise_type promise;
	const char *sysctl;
} sysctls_table[] = {
#ifdef AF_INET6
	{ PROMISE_INET, "net.inet6.ip6.addrctlpolicy" },
#endif
	{ PROMISE_ROUTE, "net.routetable" },
};

static const char *const root_path = "/";
static const char *const tmp_path = _PATH_TMP;

static const struct promise_unveil {
	const char *path;
	unveil_perms uperms;
	enum promise_type promise;
} unveils_table[] = {
#define	N UPERM_NONE
#define	R UPERM_READ
#define	W UPERM_WRITE /* NOTE: UPERM_SETATTR not implied here */
#define	X UPERM_EXECUTE
#define	A UPERM_SETATTR
#define	T UPERM_TMPDIR
	/*
	 * NOTE: On this implementation, open(2) with O_CREAT does not need
	 * the UPERM_CREATE unveil permission if the file already exists.
	 */
	{ _PATH_ETC "/malloc.conf", R,			PROMISE_STDIO },
	{ _PATH_LIBMAP_CONF, R,				PROMISE_STDIO },
	{ _PATH_VARRUN "/ld-elf.so.hints", R,		PROMISE_STDIO },
	{ _PATH_ETC "/localtime", R,			PROMISE_STDIO },
	{ "/usr/share/zoneinfo/", R,			PROMISE_STDIO },
	{ "/usr/share/nls/", R,				PROMISE_STDIO },
	{ _PATH_LOCALBASE "/share/nls/", R,		PROMISE_STDIO },
	{ _PATH_DEVNULL, R|W,				PROMISE_STDIO },
	{ _PATH_DEV "/random", R,			PROMISE_STDIO },
	{ _PATH_DEV "/urandom", R,			PROMISE_STDIO },
	{ "/libexec/ld-elf.so.1", X,			PROMISE_EXEC },
	{ _PATH_NS_CONF, R,				PROMISE_DNS },
	{ _PATH_RESCONF, R,				PROMISE_DNS },
	{ _PATH_HOSTS, R,				PROMISE_DNS },
	{ _PATH_SERVICES, R,				PROMISE_DNS },
	{ _PATH_SERVICES_DB, R,				PROMISE_DNS },
	{ _PATH_PROTOCOLS, R,				PROMISE_DNS },
	{ _PATH_TTY, R|W|A,				PROMISE_TTY },
	{ _PATH_DEV, UPERM_DEVFS,			PROMISE_PTS },
	{ _PATH_NS_CONF, R,				PROMISE_GETPW },
	{ _PATH_MP_DB, R,				PROMISE_GETPW },
	{ _PATH_SMP_DB, R,				PROMISE_GETPW },
	{ _PATH_GROUP, R,				PROMISE_GETPW },
	{ _PATH_DEV "/crypto", R|W,			PROMISE_CRYPTODEV },
	{ _PATH_ETC "/ssl/", R,				PROMISE_SSL },
	{ _PATH_ETC "/ssl/private/", N,			PROMISE_SSL },
	{ _PATH_LOCALBASE "/etc/ssl/", R,		PROMISE_SSL },
	{ _PATH_LOCALBASE "/etc/ssl/private/", N,	PROMISE_SSL },
	{ _PATH_DEV "/sndstat", R|W,                    PROMISE_AUDIO },
	{ _PATH_DEV "/mixer", R|W,                      PROMISE_AUDIO },
	{ _PATH_DEV "/dsp", R|W,                        PROMISE_AUDIO },
	{ tmp_path, T,					PROMISE_TMPPATH },
#undef	T
#undef	A
#undef	X
#undef	W
#undef	R
#undef	N
};


struct promise_mode {
	enum curtain_state state, unveil_state;
};

static bool has_pledges_on[CURTAIN_ON_COUNT];
static bool has_customs_on[CURTAIN_ON_COUNT];
static struct curtain_slot *always_slot;
static struct curtain_slot *unveil_traverse_slot;
static struct curtain_slot *root_slot_on[CURTAIN_ON_COUNT];
static struct curtain_slot *promise_slots[PROMISE_COUNT];
static struct curtain_slot *promise_unveil_slots[PROMISE_COUNT];
static bool promise_slots_needed_on[PROMISE_COUNT][CURTAIN_ON_COUNT];
static bool promise_unveil_slots_needed_on[PROMISE_COUNT][CURTAIN_ON_COUNT];
static struct curtain_slot *custom_slot_on[CURTAIN_ON_COUNT];


static int
parse_promises(struct promise_mode modes[], const char *promises_str)
{
	const char *p = promises_str;
	do {
		/* skip spaces */
		while (*p == ' ')
			p++;
		if (!*p) /* whole string processed */
			break;
		/* get next promise name */
		char name[PROMISE_NAME_SIZE] = { '\0' }, *q = name;
		do {
			if (q == &name[sizeof name])
				goto inval; /* name too long */
			*q++ = *p++;
		} while (*p && *p != ' ');
		/* search for name in table */
		enum promise_type type = 0;
		do {
			if (type >= PROMISE_COUNT)
				goto inval; /* not found */
			if (memcmp(name, names_table[type].name, sizeof name) == 0)
				break;
			type++;
		} while (true);
		/* found */
		modes[type].state = modes[type].unveil_state = CURTAIN_ENABLED;
	} while (true);
	return (0);
inval:	errno = EINVAL;
	return (-1);
}


static unveil_perms
uperms_for_promises(const struct promise_mode modes[])
{
	unveil_perms uperms = UPERM_NONE;
	if (modes[PROMISE_RPATH].state >= CURTAIN_ENABLED) uperms |= UPERM_READ;
	if (modes[PROMISE_WPATH].state >= CURTAIN_ENABLED) uperms |= UPERM_WRITE;
	if (modes[PROMISE_CPATH].state >= CURTAIN_ENABLED) uperms |= UPERM_CREATE | UPERM_DELETE;
	if (modes[PROMISE_EXEC].state  >= CURTAIN_ENABLED) uperms |= UPERM_EXECUTE;
	if (modes[PROMISE_FATTR].state >= CURTAIN_ENABLED) uperms |= UPERM_SETATTR;
	if (modes[PROMISE_UNIX].state  >= CURTAIN_ENABLED) uperms |= UPERM_UNIX;
	return (uperms);
}

static void
abilities_for_uperms(struct curtain_slot *slot, unveil_perms uperms, unsigned flags)
{
	if (uperms & UPERM_READ)
		curtain_ability(slot, CURTAINABL_VFS_READ, flags);
	if (uperms & UPERM_WRITE)
		curtain_ability(slot, CURTAINABL_VFS_WRITE, flags);
	if (uperms & UPERM_CREATE)
		curtain_ability(slot, CURTAINABL_VFS_CREATE, flags);
	if (uperms & UPERM_DELETE)
		curtain_ability(slot, CURTAINABL_VFS_DELETE, flags);
	if (uperms & UPERM_EXECUTE)
		curtain_ability(slot, CURTAINABL_EXEC, flags);
	if (uperms & UPERM_SETATTR)
		curtain_ability(slot, CURTAINABL_FATTR, flags);
	if (uperms & UPERM_UNIX)
		curtain_ability(slot, CURTAINABL_VFS_SOCK, flags);
	if (uperms & UPERM_TMPDIR) {
		curtain_ability(slot, CURTAINABL_VFS_READ, flags);
		curtain_ability(slot, CURTAINABL_VFS_WRITE, flags);
		curtain_ability(slot, CURTAINABL_VFS_CREATE, flags);
		curtain_ability(slot, CURTAINABL_VFS_DELETE, flags);
	}
}


static bool
prepare_promise_slot(enum curtain_on on, bool needed_on[CURTAIN_ON_COUNT], struct curtain_slot **slot,
    enum curtain_state state)
{
	bool must_fill, needed;
	if ((needed_on[on] = state >= CURTAIN_RESERVED)) {
		if ((must_fill = !*slot))
			*slot = curtain_slot_neutral();
	} else
		must_fill = false;
	if (*slot) {
		needed = false;
		for (enum curtain_on on1 = 0; on1 < CURTAIN_ON_COUNT; on1++)
			if (needed_on[on1])
				needed = true;
		if (needed) {
			curtain_state(*slot, on, state);
		} else {
			/*
			 * Drop slots disabled both on-self and on-exec to
			 * close the cached O_PATH FDs for dropped promises.
			 */
			curtain_drop(*slot);
			*slot = NULL;
		}
	}
	return (must_fill);
}

static void
do_promises_slots(enum curtain_on on, struct promise_mode modes[])
{
	bool fill[PROMISE_COUNT], fill_unveils[PROMISE_COUNT];
	bool tainted, changed;
	unsigned flags;

#define	FOREACH_ARRAY(ent, tab) \
	for (__typeof(&(tab)[0]) (ent) = (tab); (ent) < &(tab)[nitems(tab)]; (ent)++)

	do { /* enable promises that enabled promises depend on */
		changed = false;
		FOREACH_ARRAY(e, depends_table) {
			if (modes[(*e)[1]].state < modes[(*e)[0]].state) {
				modes[(*e)[1]].state = modes[(*e)[0]].state;
				changed = true;
			}
			if (modes[(*e)[1]].unveil_state < modes[(*e)[0]].unveil_state) {
				modes[(*e)[1]].unveil_state = modes[(*e)[0]].unveil_state;
				changed = true;
			}
		}
	} while (changed);

	/*
	 * Initialize promise slots on first use.  Abilities and unveils are
	 * separated because unveil() needs to deal with them differently when
	 * it's called before pledge().
	 */

	for (enum promise_type promise = 0; promise < PROMISE_COUNT; promise++) {
		fill[promise] = prepare_promise_slot(on,
		    promise_slots_needed_on[promise], &promise_slots[promise],
		    modes[promise].state);
		fill_unveils[promise] = prepare_promise_slot(on,
		    promise_unveil_slots_needed_on[promise], &promise_unveil_slots[promise],
		    modes[promise].unveil_state);
	}

	flags = CURTAIN_PASS;

	tainted = issetugid() != 0;
	FOREACH_ARRAY(e, unveils_table) {
		if (fill_unveils[e->promise]) {
			const char *path = e->path;
			if (!tainted && path == tmp_path) {
				char *tmpdir;
				if ((tmpdir = getenv("TMPDIR")))
					path = tmpdir;
			}
			curtain_unveil(promise_unveil_slots[e->promise], path,
			    CURTAIN_UNVEIL_INHERIT, e->uperms);
		}
		if (fill[e->promise])
			abilities_for_uperms(promise_slots[e->promise], e->uperms, flags);
	}

	FOREACH_ARRAY(e, abilities_table)
		if (fill[e->promise])
			curtain_ability(promise_slots[e->promise], e->ability, flags);

	FOREACH_ARRAY(e, ioctls_table)
		if (fill[e->promise])
			curtain_ioctls(promise_slots[e->promise], e->ioctls, flags);

	FOREACH_ARRAY(e, sockafs_table)
		if (fill[e->promise])
			curtain_sockaf(promise_slots[e->promise], e->af, flags);

	FOREACH_ARRAY(e, sockopts_table)
		if (fill[e->promise])
			curtain_sockopt(promise_slots[e->promise], e->level, e->optname, flags);

	FOREACH_ARRAY(e, sysctls_table)
		if (fill[e->promise])
			curtain_sysctl(promise_slots[e->promise], e->sysctl, flags);

	if (fill[PROMISE_ERROR])
		curtain_default(promise_slots[PROMISE_ERROR], CURTAIN_DENY);
	if (fill[PROMISE_TRAP])
		curtain_default(promise_slots[PROMISE_TRAP], CURTAIN_TRAP);

	if (!always_slot) {
		always_slot = curtain_slot_neutral();
		/*
		 * Always allow to reduce curtain/unveil permissions later on.
		 * This is different from the "unveil" promise which is handled
		 * specially in do_pledge().
		 */
		curtain_ability(always_slot, CURTAINABL_CURTAIN, flags);
		/*
		 * Always keep the root directory chdir()-able (but not
		 * necessarily stat()-able or readable).  This is sufficient to
		 * let child processes do their own unveils on it (which is
		 * necessary to set new permissions that will inherit to all
		 * reachable paths).
		 *
		 * In addition, it lets all programs do a chdir("/").  Which is
		 * something that a lot of daemon programs do and they might
		 * not expect the call to fail (which could lead to security
		 * issues if the program isn't in the directory that it expects).
		 */
		curtain_unveil(always_slot, root_path, flags, UPERM_SEARCH);
	}
	curtain_enable(always_slot, on);
}


static void unveil_enable_delayed(enum curtain_on);

static int
do_pledge(struct promise_mode *modes_on[CURTAIN_ON_COUNT])
{
	for (enum curtain_on on = 0; on < CURTAIN_ON_COUNT; on++) {
		unveil_perms wanted_uperms;
		if (!modes_on[on])
			continue;
		has_pledges_on[on] = true;
		do_promises_slots(on, modes_on[on]);
		wanted_uperms = uperms_for_promises(modes_on[on]);
		if (custom_slot_on[on]) {
			curtain_unveils_limit(custom_slot_on[on], wanted_uperms);
			unveil_enable_delayed(on); /* see do_unveil_both() */
		}
		if (!has_customs_on[on] ||
		    modes_on[on][PROMISE_UNVEIL].state >= CURTAIN_RESERVED) {
			if (!root_slot_on[on])
				root_slot_on[on] = curtain_slot_neutral();
			curtain_state(root_slot_on[on], on,
			    has_customs_on[on] ? CURTAIN_RESERVED : CURTAIN_ENABLED);
		}
		if (root_slot_on[on])
			/* XXX problem when / isn't inspectable */
			curtain_unveil(root_slot_on[on], root_path, 0, wanted_uperms);
	}
	return (curtain_enforce());
}

int
pledge(const char *promises_str, const char *execpromises_str)
{
	struct promise_mode self_modes[PROMISE_COUNT] = { 0 };
	struct promise_mode exec_modes[PROMISE_COUNT] = { 0 };
	struct promise_mode *modes_on[CURTAIN_ON_COUNT] = { 0 };
	int r;
	if (promises_str) {
		r = parse_promises(self_modes, promises_str);
		if (r < 0)
			return (-1);
		modes_on[CURTAIN_ON_SELF] = self_modes;
	}
	if (execpromises_str) {
		r = parse_promises(exec_modes, execpromises_str);
		if (r < 0)
			return (-1);
		modes_on[CURTAIN_ON_EXEC] = exec_modes;
	}
	return (do_pledge(modes_on));
}


/*
 * Most of the complexity here is to deal with the case where unveil() is
 * called before pledge().  On OpenBSD, pledges and unveils can be set up
 * independently.  Not so in this implementation.
 */

static void
unveil_enable_delayed(enum curtain_on on)
{
	if (custom_slot_on[on]) {
		curtain_enable(custom_slot_on[on], on);
		has_customs_on[on] = true;
	}
}

static void
do_unveil_init_on(enum curtain_on on)
{
	if (!unveil_traverse_slot) {
		unveil_traverse_slot = curtain_slot_neutral();
		curtain_unveil(unveil_traverse_slot, "/", 0, UPERM_BROWSE);
	}
	if (!custom_slot_on[on])
		custom_slot_on[on] = curtain_slot_neutral();
	curtain_enable(custom_slot_on[on], on);
	if (!has_pledges_on[on] && !has_customs_on[on]) {
		struct promise_mode modes[PROMISE_COUNT];
		/*
		 * unveil() was called before pledge().  Enable abilities for
		 * all promises and reserve their unveils.
		 */
		for (enum promise_type i = 0; i < PROMISE_COUNT; i++)
			modes[i] = (struct promise_mode){
				.state = CURTAIN_ENABLED,
				.unveil_state = CURTAIN_RESERVED,
			};
		do_promises_slots(on, modes);
	}
	if (root_slot_on[on])
		curtain_disable(root_slot_on[on], on);
	has_customs_on[on] = true;
}

static int
do_unveil(bool *do_on, const char *path, unveil_perms uperms)
{
	enum curtain_on on;
	struct curtain_slot *slotv[CURTAIN_ON_COUNT];
	unveil_perms interm_upermsv[CURTAIN_ON_COUNT], final_upermsv[CURTAIN_ON_COUNT];
	size_t nslot;
	bool unveil_traverse;
	int r;

	for (on = 0; on < CURTAIN_ON_COUNT; on++)
		if (do_on[on])
			do_unveil_init_on(on);
		else if (!custom_slot_on[on])
			custom_slot_on[on] = curtain_slot_neutral();

	if (!path) /* unveil(NULL, NULL) */
		return (curtain_enforce());

	/*
	 * Temporarily enable hard permissions to search directories so that
	 * curtain_unveil() can traverse the path.
	 */
	if ((unveil_traverse = has_customs_on[CURTAIN_ON_SELF])) {
		curtain_state(unveil_traverse_slot, CURTAIN_ON_SELF, CURTAIN_ENABLED);
		curtain_engage();
	}

	nslot = 0;
	for (on = 0; on < CURTAIN_ON_COUNT; on++) {
		interm_upermsv[nslot] = UPERM_TRAVERSE;
		final_upermsv[nslot] = uperms;
		slotv[nslot++] = custom_slot_on[on];
	}

	r = curtain_unveil_multi(slotv, nslot, path, 0, interm_upermsv, final_upermsv);

	/* Drop temporary soft permissions to search paths. */
	if (unveil_traverse)
		curtain_state(unveil_traverse_slot, CURTAIN_ON_SELF, CURTAIN_NEUTRAL);
	if (r < 0) {
		if (unveil_traverse)
			curtain_engage();
		return (r);
	}

	return (curtain_engage());
}

static int
unveil_parse_perms(unveil_perms *uperms, const char *s)
{
	*uperms = UPERM_NONE;
	while (*s)
		switch (*s++) {
		case 'b': *uperms |= UPERM_BROWSE; break;
		case 'r': *uperms |= UPERM_READ; break;
		case 'm': *uperms |= UPERM_WRITE; break;
		case 'w': *uperms |= UPERM_WRITE | UPERM_SETATTR | UPERM_UNIX; break;
		case 'a': *uperms |= UPERM_SETATTR; break;
		case 'c': *uperms |= UPERM_CREATE | UPERM_DELETE; break;
		case 'x': *uperms |= UPERM_EXECUTE; break;
		case 'i': *uperms |= UPERM_INSPECT; break;
		case 't': *uperms |= UPERM_TMPDIR; break;
		case 'u': *uperms |= UPERM_UNIX; break;
		default:
			return (-1);
		}
	return (0);
}

static int
unveil_on(enum curtain_on on, const char *path, const char *perms)
{
	bool do_on[CURTAIN_ON_COUNT] = { 0 };
	do_on[on] = true;
	unveil_perms uperms;
	int r;
	if ((perms == NULL) != (path == NULL))
		return ((errno = EINVAL), -1);
	if (!path && !has_customs_on[on])
		return (0);
	if (perms) {
		r = unveil_parse_perms(&uperms, perms);
		if (r < 0)
			return ((errno = EINVAL), -1);
	} else
		uperms = UPERM_NONE;
	return (do_unveil(do_on, path, uperms));
}

int
unveil_self(const char *path, const char *perms)
{ return (unveil_on(CURTAIN_ON_SELF, path, perms)); }

int
unveil_exec(const char *path, const char *perms)
{ return (unveil_on(CURTAIN_ON_EXEC, path, perms)); }

int
unveil(const char *path, const char *perms)
{
	bool do_on[CURTAIN_ON_COUNT] = { 0 };
	unveil_perms uperms;
	int r;
	if ((perms == NULL) != (path == NULL))
		return ((errno = EINVAL), -1);
	if (!path) {
		/*
		 * On OpenBSD, unveil(NULL, NULL) without any prior unveils
		 * just forbids further use of unveil() (equivalent of doing a
		 * pledge() without "unveil").  Since this implementation never
		 * disables unveil(), just do nothing in this case.
		 */
		bool has_custom = false;
		for (enum curtain_on on = 0; on < CURTAIN_ON_COUNT; on++)
			if (has_customs_on[on]) {
				has_custom = true;
				break;
			}
		if (!has_custom)
			return (0);
	}
	if (perms) {
		r = unveil_parse_perms(&uperms, perms);
		if (r < 0)
			return ((errno = EINVAL), -1);
	} else
		uperms = UPERM_NONE;
	/*
	 * On OpenBSD, unveils are discarded on exec if the process does not
	 * have on-exec pledges (which then allows it to run setuid binaries
	 * or do its own unveiling, for example).
	 *
	 * To implement this, delay enabling the on-exec slot for unveils added
	 * with unveil() until an on-exec pledge() or an unveilexec() is
	 * explicitly done.  If the current process already had inherited
	 * on-exec unveils, they will be left unmodified and an exec will
	 * revert the process' unveils to those initially inherited unveils.
	 * Otherwise, the process will be unrestricted on exec as on OpenBSD.
	 */
	do_on[CURTAIN_ON_SELF] = true;
	do_on[CURTAIN_ON_EXEC] = has_pledges_on[CURTAIN_ON_EXEC] ||
	                         has_customs_on[CURTAIN_ON_EXEC];
	return (do_unveil(do_on, path, uperms));
}

int
unveil_freeze(void)
{
	bool do_on[CURTAIN_ON_COUNT] = { 0 };
	do_on[CURTAIN_ON_SELF] = true;
	do_on[CURTAIN_ON_EXEC] = has_pledges_on[CURTAIN_ON_EXEC] ||
	                         has_customs_on[CURTAIN_ON_EXEC];
	return (do_unveil(do_on, NULL, UPERM_NONE));
}
