#include <stdio.h>
#include <unistd.h>
#include <err.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

int
main()
{
	int r;
	r = pledge("stdio dns", "");
	if (r < 0)
		err(1, "pledge");

	r = res_init();
	if (r < 0)
		err(1, "res_init");

	/* TODO: more */

	return 0;
}
