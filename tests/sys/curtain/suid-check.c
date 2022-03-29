#include <unistd.h>
#include <fcntl.h>
#include <sysexits.h>

int
main()
{
	int r, e;
	e = 30;
	if (geteuid())
		e += 1;
	r = open("/etc/rc", O_RDONLY);
	if (r < 0)
		e += 2;
	else
		close(r);
	return (e);
}
