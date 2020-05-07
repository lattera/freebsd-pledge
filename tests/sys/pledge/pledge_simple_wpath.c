#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>

static char *cleanup_path = NULL;
static void
cleanup(void)
{
	int r;
	if (cleanup_path) {
		r = unlink(cleanup_path);
		if (r < 0 && errno != ENOENT)
			warn("unlink: %s", cleanup_path);
	}
}

int
main()
{
	int r, fd;
	char *p;
	r = pledge("error stdio rpath wpath cpath", NULL);
	if (r < 0)
		err(1, "pledge");
	p = getenv("TMPDIR");
	if (!p || !*p)
		p = "/tmp";
	r = asprintf(&p, "%s/%s.XXXXXXXXXXXX", p, getprogname());
	if (r < 0)
		err(1, "asprintf");
	p = mktemp(p);
	if (!p)
		err(1, "mktemp");
	cleanup_path = p;
	atexit(cleanup);

	r = pledge("error stdio wpath cpath", NULL);
	if (r < 0)
		err(1, "pledge");
	fd = open(p, O_WRONLY|O_CREAT, 0644);
	if (fd < 0)
		err(1, "open");
	r = close(fd);
	if (r < 0)
		err(1, "close");

	r = unlink(p);
	if (r < 0)
		err(1, "unlink");
	cleanup_path = NULL;

	r = pledge("error stdio wpath", NULL);
	r = open(p, O_WRONLY|O_CREAT, 0644);
	if (!(r < 0))
		errx(1, "open shouldn't have worked!");

	exit(0);
}
