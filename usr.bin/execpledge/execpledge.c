#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sysexits.h>
#include <string.h>
#include <err.h>

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-p promises] [-u unveil ...] cmd [arg ...]\n", getprogname());
	exit(EX_USAGE);
}

int
main(int argc, char *argv[])
{
	int ch, r;
	char *promises = NULL;

	r = pledge("stdio exec unveil", NULL);
	if (r < 0)
		err(EX_NOPERM, "pledge");

	while ((ch = getopt(argc, argv, "p:u:")) != -1)
		switch (ch) {
		case 'p':
			promises = optarg;
			break;
		case 'u': {
			char *perms;
			if ((perms = strrchr(optarg, ':')))
				*perms++ = '\0';
			else
				perms = __DECONST(char *, "rx");
			r = unveil(optarg, perms);
			if (r < 0)
				err(EX_OSERR, "unveil %s", optarg);
			break;
		}
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
