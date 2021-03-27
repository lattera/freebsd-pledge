#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <pledge.h>

#include "util.h"

int
main()
{
	const char *p0 = "/usr/bin/false", *p1 = "/usr/bin/true";
	EXPECT(pledge("error stdio rpath exec", NULL));
	EXPECT(unveil(p1, "x"));
	EXPECT(unveil(NULL, NULL));
	REJECT(execl(p0, "false", (char *)NULL));
	EXPECT(execl(p1, "true", (char *)NULL));
	return (0);
}
