#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <err.h>
#include <errno.h>

#include "util.h"

static void
try_stuff(bool should_work, int fl, int fds[])
{
	void *p;

	TRY_BOOL((p = mmap(NULL, PAGE_SIZE, PROT_EXEC, fl, fds[0], 0)) != MAP_FAILED, should_work);
	if (should_work) {
		EXPECT(mprotect(p, PAGE_SIZE, PROT_EXEC));
		EXPECT(munmap(p, PAGE_SIZE));
	}

	EXPECT_BOOL((p = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_MAX(PROT_READ|PROT_EXEC), fl, fds[1], 0)) != MAP_FAILED);
	TRY(mprotect(p, PAGE_SIZE, PROT_EXEC), should_work);
	EXPECT(munmap(p, PAGE_SIZE));

	TRY_BOOL((p = mmap(NULL, PAGE_SIZE, PROT_EXEC, MAP_ANON | fl, -1, 0)) != MAP_FAILED, should_work);
	if (should_work) {
		EXPECT(mprotect(p, PAGE_SIZE, PROT_EXEC));
		EXPECT(munmap(p, PAGE_SIZE));
	}

	TRY_BOOL((p = mmap(NULL, PAGE_SIZE, PROT_EXEC | PROT_READ, MAP_ANON | fl, -1, 0)) != MAP_FAILED, should_work);
	if (should_work) {
		EXPECT(mprotect(p, PAGE_SIZE, PROT_EXEC));
		EXPECT(munmap(p, PAGE_SIZE));
	}

	EXPECT_BOOL((p = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_MAX(PROT_READ|PROT_EXEC), MAP_ANON | fl, -1, 0)) != MAP_FAILED);
	TRY(mprotect(p, PAGE_SIZE, PROT_EXEC), should_work);
	EXPECT(munmap(p, PAGE_SIZE));

	EXPECT_PTR((p = aligned_alloc(PAGE_SIZE, PAGE_SIZE)));
	TRY(mprotect(p, PAGE_SIZE, PROT_EXEC), should_work);
	free(p);
}

int
main()
{
	int fds[2];

	EXPECT((fds[0] = open("/bin/sh", O_EXEC)));
	EXPECT((fds[1] = open("/bin/sh", O_RDONLY)));

	EXPECT(pledge("error stdio prot_exec", NULL));

	try_stuff(true, MAP_SHARED, fds);
	try_stuff(true, MAP_PRIVATE, fds);

	EXPECT(pledge("error stdio", NULL));

	try_stuff(false, MAP_SHARED, fds);
	try_stuff(false, MAP_PRIVATE, fds);

	EXPECT(close(fds[0]));
	EXPECT(close(fds[1]));

	return (0);
}
