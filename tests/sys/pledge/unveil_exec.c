#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "util.h"

int
main()
{
	const char *p0 = "/usr/bin/false", *p1 = "/usr/bin/true";
	EXPECT(unveil("/", "r"));
	EXPECT(unveil("/libexec", "x"));
	REJECT(execl(p0, "false", (char *)NULL));
	EXPECT(unveil(p1, "x"));
	EXPECT(unveil(NULL, NULL));
	EXPECT(execl(p1, "true", (char *)NULL));
	return (0);
}
