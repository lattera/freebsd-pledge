#include <curtain.h>
#include <sys/param.h>

#include <sys/ttycom.h>
#include <termios.h>

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
