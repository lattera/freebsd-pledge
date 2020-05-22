#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "util.h"

int
main()
{
	EXPECT(unveil("/etc", "r"));
	EXPECT(pledge("stdio rpath", NULL));
	REJECT(open("/tmp", O_RDONLY));
	return (0);
}
