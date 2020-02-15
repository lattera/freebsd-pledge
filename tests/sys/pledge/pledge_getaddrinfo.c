#include <stdio.h>
#include <unistd.h>
#include <err.h>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

int main() {
	int e, r;
	struct addrinfo* ai;

	r = pledge("stdio dns", "");
	if (r < 0)
		err(1, "pledge");

	e = getaddrinfo("localhost", NULL, NULL, &ai);
	if (e)
		errx(1, "getaddrinfo: %s", gai_strerror(e));

	freeaddrinfo(ai);

	/* TODO: more */

	return 0;
}
