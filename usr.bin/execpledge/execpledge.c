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

	while ((ch = getopt(argc, argv, "p:u:")) != -1)
		switch (ch) {
		case 'p': {
			char *p;
			promises = optarg;
			for (p = promises; *p; p++)
				if (*p == ',')
					*p = ' ';
			break;
		}
		case 'u': {
			char *perms;
			if ((perms = strrchr(optarg, ':')))
				*perms++ = '\0';
			else
				perms = __DECONST(char *, "rx");
			r = unveilexec(optarg, perms);
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

	r = pledge("stdio exec", promises);
	if (r < 0)
		err(EX_NOPERM, "pledge");

	execvp(argv[0], argv);
	err(EX_OSERR, "execvp");
}
