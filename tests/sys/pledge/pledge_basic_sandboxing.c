#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <stdbool.h>
#include <fcntl.h>

#define TRY(expr, should_work) do { \
	if ((expr) < 0) { \
		if (should_work) \
			err(1, "%s", #expr); \
	} else { \
		if (!should_work) \
			errx(1, "%s: %s", #expr, "shouldn't have worked"); \
	} \
} while (0)

#define EXPECT(expr) TRY(expr, true)
#define REJECT(expr) TRY(expr, false)

int main() {
	EXPECT(pledge("error stdio rpath", NULL));
	EXPECT(getpid());
	int fd;
	EXPECT((fd = dup(STDIN_FILENO)));
	EXPECT(close(fd));
	EXPECT((fd = open("/etc/rc", O_RDONLY)));
	EXPECT(close(fd));
	EXPECT(pledge("error stdio", NULL));
	REJECT((fd = open("/etc/rc", O_RDONLY)));
	return 0;
}
