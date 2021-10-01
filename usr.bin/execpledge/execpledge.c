#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sysexits.h>
#include <string.h>
#include <err.h>
#include <pledge.h>

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

	while ((ch = getopt(argc, argv, "p:u:")) != -1)
		switch (ch) {
		case 'p': {
			char *p;
			for (p = optarg; *p; p++)
				if (*p == ',')
					*p = ' ';
			r = pledge(NULL, optarg);
			if (r < 0)
				err(EX_NOPERM, "pledge");
			break;
		}
		case 'u': {
			char *perms;
			if ((perms = strrchr(optarg, ':')))
				*perms++ = '\0';
			else
				perms = __DECONST(char *, "rx");
			r = unveil_exec(optarg, perms);
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
	execvp(argv[0], argv);
	err(EX_OSERR, "%s", argv[0]);
}
