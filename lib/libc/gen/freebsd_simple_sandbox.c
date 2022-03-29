#include <stdlib.h>
#include <stdbool.h>
#include <err.h>
#include <errno.h>
#include <dlfcn.h>
#include <unistd.h>

int
freebsd_simple_sandbox(const char *tag)
{
	bool tainted = issetugid() != 0;
	bool debug;
	void *dl_handle;
	int (*func)(const char *);
	int r;

	if (!tainted && getenv("FREEBSD_SIMPLE_SANDBOX_DISABLED")) {
		errno = 0;
		return (1);
	}

	debug = !tainted && getenv("FREEBSD_SIMPLE_SANDBOX_DEBUG") != NULL;
	if (debug)
		warnx("%s: pid %d, tag \"%s\"", __func__, getpid(), tag);

	dl_handle = dlopen("libcurtain.so", RTLD_LAZY | RTLD_LOCAL);
	if (dl_handle == NULL) {
		if (debug)
			warnx("%s: dlopen: %s", __func__, dlerror());
		errno = 0;
		return (1);
	}

	func = (int (*)(const char *))dlfunc(dl_handle, "curtain_simple_sandbox");
	if (func == NULL) {
		warnx("%s: dlfunc: %s", __func__, dlerror());
		errno = 0;
		return (-1);
	}

	r = func(tag);

	dlclose(dl_handle);

	return (r);
}
