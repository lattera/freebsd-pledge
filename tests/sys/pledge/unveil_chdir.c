#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "util.h"

static int
tryread(const char *path)
{
	int r;
	r = open(path, O_RDONLY|O_DIRECTORY);
	if (r < 0)
		return (r);
	close(r);
	return (0);
}

int
main()
{
	EXPECT(unveil("/etc", "r"));
	EXPECT(unveil("/var", "i"));
	EXPECT(unveil(NULL, NULL));
	REJECT(tryread("/"));
	EXPECT(chdir("/"));
	REJECT(tryread("/."));
	EXPECT(chdir("/."));
	REJECT(tryread("/var"));
	EXPECT(chdir("/var"));
	REJECT(tryread("/var/."));
	EXPECT(chdir("/var/."));
	EXPECT(tryread("/etc"));
	EXPECT(chdir("/etc"));
	EXPECT(tryread("/etc/."));
	EXPECT(chdir("/etc/."));
	EXPECT(tryread("/etc/defaults"));
	EXPECT(chdir("/etc/defaults"));
	EXPECT(tryread("/etc/defaults/."));
	EXPECT(chdir("/etc/defaults/."));
	EXPECT(tryread(".."));
	EXPECT(chdir(".."));
	REJECT(tryread(".."));
	EXPECT(chdir(".."));
	EXPECT(tryread("/./etc/./defaults/.././defaults"));
	EXPECT(chdir("/./etc/./defaults/.././defaults"));
	REJECT(tryread("/etc/.."));
	EXPECT(chdir("/etc/.."));
	REJECT(tryread("/etc/../var"));
	EXPECT(chdir("/etc/../var"));
	return (0);
}
