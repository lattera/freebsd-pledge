#include <stdio.h>
#include <unistd.h>
#include <err.h>

int main() {
	int r;
	r = pledge("stdio exec", "stdio rpath");
	if (r < 0)
		err(1, "pledge");
	execlp("true", "true", NULL);
	err(1, "execlp");
	return 0;
}
