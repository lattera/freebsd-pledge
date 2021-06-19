#include <curtain.h>
#include <sys/param.h>

#include <termios.h>
#include <sys/ttycom.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <sys/sockio.h>

const unsigned long curtain_ioctls_tty_basic[] = {
	TIOCSBRK,
	TIOCCBRK,
	TIOCSDTR,
	TIOCCDTR,
	TIOCGPGRP,
	TIOCSPGRP, /* XXX */
	TIOCGETA,
	TIOCSETA,
	TIOCSETAW,
	TIOCSETAF,
	TIOCSTOP,
	TIOCSTART,
	TIOCSCTTY,
	TIOCDRAIN,
	TIOCEXCL,
	TIOCNXCL,
	TIOCFLUSH,
	TIOCGWINSZ,
	TIOCSWINSZ,
	-1
};

const unsigned long curtain_ioctls_net_basic[] = {
	-1
};

const unsigned long curtain_ioctls_net_route[] = {
	SIOCGIFDESCR,
	SIOCGIFFLAGS,
	SIOCGIFMETRIC,
	SIOCGIFCONF,
	SIOCGIFFIB,
	SIOCGIFMTU,
	SIOCGIFMETRIC,
	SIOCGIFCAP,
	SIOCGIFGROUP,
	SIOCGIFINDEX,
	SIOCGIFSTATUS,
#ifdef AF_INET
	SIOCGIFADDR,
	SIOCGIFBRDADDR,
	SIOCGIFDSTADDR,
	SIOCGIFNETMASK,
	SIOCGIFALIAS,
#endif
#ifdef AF_INET6
	SIOCGIFAFLAG_IN6,
	SIOCGIFALIFETIME_IN6,
	SIOCGDEFIFACE_IN6,
	SIOCGIFINFO_IN6,
#endif
	-1
};
