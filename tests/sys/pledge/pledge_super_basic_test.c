#include <stdio.h>
#include <unistd.h>
#include <err.h>

int
main()
{
	int r;
	r = pledge("stdio", "");
	if (r < 0)
		err(1, "pledge");
	r = write(STDOUT_FILENO, "ok!\n", 4);
	if (r < 0)
		err(1, "write");
	_exit(0);
	err(1, "_exit");
	return 0;
}
