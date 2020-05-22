#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "util.h"

int
main()
{
	EXPECT(unveil("/etc", "r"));
	EXPECT(unveil(NULL, NULL));
	REJECT(chdir("/"));
	REJECT(chdir("/."));
	REJECT(chdir("/tmp"));
	REJECT(chdir("/tmp/."));
	EXPECT(chdir("/etc"));
	EXPECT(chdir("/etc/."));
	EXPECT(chdir("/etc/defaults"));
	EXPECT(chdir("/etc/defaults/."));
	EXPECT(chdir(".."));
	REJECT(chdir(".."));
	EXPECT(chdir("/./etc/./defaults/.././defaults"));
	REJECT(chdir("/etc/.."));
	REJECT(chdir("/etc/../tmp"));
	return (0);
}
