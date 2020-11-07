#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <assert.h>

#include "util.h"

static char *cleanup_path = NULL;
static void
cleanup(void)
{
	if (cleanup_path)
		EXPECT(unlink(cleanup_path));
}

int
main()
{
	int fd;
	char *p;
	struct stat st;

	EXPECT(pledge("error stdio fattr rpath cpath wpath", NULL));

	p = getenv("TMPDIR");
	if (!p || !*p)
		p = "/tmp";
	EXPECT(asprintf(&p, "%s/%s.XXXXXXXXXXXX", p, getprogname()));
	EXPECT((fd = mkstemp(p)));
	cleanup_path = p;
	atexit(cleanup);
	EXPECT(stat(p, &st));

	EXPECT(pledge("error stdio fattr rpath cpath", NULL));
	EXPECT(chmod(p, 0));
	EXPECT(chmod(p, 0600));
	EXPECT(fchmod(fd, 0));
	EXPECT(fchmod(fd, 0600));

	EXPECT(pledge("error stdio rpath cpath", NULL));
	REJECT(chmod(p, 0));
	REJECT(fchmod(fd, 0));

	EXPECT(unlink(cleanup_path));
	cleanup_path = NULL;

	EXPECT(pledge("error stdio", NULL));
	EXPECT(close(fd));
	exit(0);
}
