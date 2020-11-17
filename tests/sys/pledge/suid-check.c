#include <unistd.h>
#include <fcntl.h>
#include <sysexits.h>

int
main()
{
	int r, e;
	e = 0;
	if (geteuid())
		e |= 1;
	r = open("/etc", O_DIRECTORY|O_RDONLY);
	if (r < 0)
		e |= 2;
	else
		close(r);
	return (e);
}
