#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <string.h>
#include <netdb.h>

static void
herr(int eval, const char *str) {
	herror(str);
	exit(eval);
}

int main() {
	int r;
	r = pledge("stdio dns", "");
	if (r < 0)
		err(1, "pledge");

	struct hostent *he;
	he = gethostbyname("localhost");
	if (!he)
		herr(1, "gethostbyname");
	if (strcmp(he->h_name, "localhost") != 0)
		errx(1, "gethostbyname didn't work for localhost");

	struct servent *se;
	se = getservbyname("ssh", "tcp");
	if (!se)
		herr(1, "getservbyname");
	if (strcmp(se->s_name, "ssh") != 0)
		errx(1, "getservbyname didn't work for ssh");

	struct protoent *pe;
	pe = getprotobyname("tcp");
	if (!pe)
		herr(1, "getprotobyname");
	if (strcmp(pe->p_name, "tcp") != 0)
		errx(1, "getprotobyname didn't work for tcp");

	return 0;
}
