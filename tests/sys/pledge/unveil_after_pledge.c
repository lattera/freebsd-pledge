#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "util.h"

int
main()
{
	EXPECT(pledge("stdio rpath", NULL));
	EXPECT(unveil("/etc", "r"));
	REJECT(open("/tmp", O_RDONLY));
	return (0);
}
