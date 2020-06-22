#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/capsicum.h>

int
main()
{
	int r;
	r = pledge("error stdio", "");
	if (r < 0)
		err(1, "pledge");
	/* this is allowed by pledge("stdio") but not Capsicum */
	r = access("/etc/malloc.conf", R_OK);
	if (r < 0 && errno != ENOENT)
		err(1, "access");
	r = cap_enter();
	if (r < 0)
		err(1, "cap_enter");
	r = write(STDOUT_FILENO, "ok!\n", 4);
	if (r < 0)
		err(1, "write");
	r = access("/etc/malloc.conf", R_OK);
	if (!(r < 0 && errno == ECAPMODE))
		errx(1, "access() shouldn't have worked!");
	r = flock(STDIN_FILENO, LOCK_SH);
	if (!(r < 0 && errno == ECAPMODE))
		errx(1, "flock() shouldn't have worked!");
	return 0;
}
