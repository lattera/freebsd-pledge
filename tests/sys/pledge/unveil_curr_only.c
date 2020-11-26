#include <stdio.h>
#include <unistd.h>
#include <err.h>

#include "util.h"

int
main()
{
	EXPECT(pledge("stdio exec", NULL));
	EXPECT(unveilcurr("/", "x"));
	EXPECT(unveilcurr(NULL, NULL));
	EXPECT(execlp("test", "test", "-r", "/etc/rc", NULL));
	return (1);
}
