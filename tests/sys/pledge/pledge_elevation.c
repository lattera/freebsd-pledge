#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <stdbool.h>

static void
try(const char *promises, bool should_work)
{
	int r;
	r = pledge(promises, NULL);
	if (r < 0) {
		if (should_work)
			err(1, "pledge(\"%s\") should have worked!", promises);
	} else {
		if (!should_work)
			err(1, "pledge(\"%s\") shouldn't have worked!", promises);
	}
}

int
main()
{
	try("error stdio proc", true);
	try("error stdio proc", true);
	try("error stdio proc id", true);
	try("stdio proc flock", true);
	try("stdio proc id", false); /* "error" should now be off */
	try("stdio proc", true);
	try("error stdio proc", false);
	try("stdio id", false); /* above shouldn't have done anything */
	try("stdio", true);
	try("stdio proc", false);
	return 0;
}
