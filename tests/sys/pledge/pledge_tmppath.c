#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <assert.h>

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

#define EXPECT(expr) do { \
	if ((expr) < 0) \
		err(1, "%s", #expr); \
} while (0)

int
main()
{
	int r, fd;
	char *p, buf[128];
	struct stat s;

	r = pledge("error stdio tmppath", NULL);
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

	EXPECT((fd = open(p, O_RDWR|O_CREAT, 0644)));
#if 0
	EXPECT(access(p, R_OK));
#endif
	EXPECT(stat(p, &s));
	EXPECT(write(fd, "test\n", 5));
	EXPECT(close(fd));
#if 0
	EXPECT(access(p, R_OK));
#endif
	EXPECT(stat(p, &s));

	EXPECT((fd = open(p, O_RDWR, 0644)));
#if 0
	EXPECT(access(p, R_OK));
#endif
	EXPECT(stat(p, &s));
	EXPECT(read(fd, buf, 5));
	assert(0 == memcmp("test\n", buf, 5));
	EXPECT(close(fd));

	EXPECT(unlink(p));
	cleanup_path = NULL;

	exit(0);
}
