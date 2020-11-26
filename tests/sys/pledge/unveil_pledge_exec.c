#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "util.h"

int
main()
{
	const char *p0 = "/usr/bin/false", *p1 = "/usr/bin/true";
	EXPECT(pledge("error stdio rpath exec", NULL));
	EXPECT(unveilcurr(p1, "x"));
	EXPECT(unveilcurr(NULL, NULL));
	REJECT(execl(p0, "false", (char *)NULL));
	EXPECT(execl(p1, "true", (char *)NULL));
	return (0);
}
