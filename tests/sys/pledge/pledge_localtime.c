#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <time.h>
#include <pledge.h>

int
main()
{
	int r;
	r = pledge("stdio", "");
	if (r < 0)
		err(1, "pledge");
	time_t now;
	struct tm *loc;
	time(&now);
	loc = localtime(&now);
	if (!loc)
		err(1, "localtime");
	return 0;
}
