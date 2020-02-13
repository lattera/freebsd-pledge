#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sysexits.h>
#include <err.h>

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-p promises] cmd [arg ...]\n", getprogname());
	exit(EX_USAGE);
}

int
main(int argc, char *argv[])
{
	int ch, r;
	char *promises = NULL;

	r = pledge("stdio exec", NULL);
	if (r < 0)
		err(EX_NOPERM, "pledge");

	while ((ch = getopt(argc, argv, "p:")) != -1)
		switch (ch) {
		case 'p':
			promises = optarg;
			break;
		default:
			usage();
		}
	argv += optind;
	argc -= optind;

	if (!argc)
		usage();

	r = pledge(NULL, promises);
	if (r < 0)
		err(EX_NOPERM, "pledge");

	execvp(argv[0], argv);
	err(EX_OSERR, "execvp");
}
