#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <assert.h>
#include <pledge.h>

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

	EXPECT(pledge("error stdio fattr tmppath", NULL));

	p = getenv("TMPDIR");
	if (!p || !*p)
		p = "/tmp";
	EXPECT(asprintf(&p, "%s/%s.XXXXXXXXXXXX", p, getprogname()));
	EXPECT((fd = mkstemp(p)));

	cleanup_path = p;
	atexit(cleanup);

	EXPECT(stat(p, &st));

	EXPECT(chown(p, st.st_uid, st.st_gid));
	EXPECT(fchown(fd, st.st_uid, st.st_gid));

	REJECT( chown(p,  7, st.st_gid));
	REJECT(fchown(fd, 7, st.st_gid));
	REJECT( chown(p,  st.st_uid, 13));
	REJECT(fchown(fd, st.st_uid, 13));

	/* TODO: try different IDs, should always be forbidden */

	EXPECT(close(fd));

	exit(0);
}
