#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common.h"

int
curtain_cwd_is_within(const char *path)
{
	int check_fd, up_fd;
	struct stat check_st, up_st;
	dev_t last_dev;
	ino_t last_ino;
	bool has_last;
	int r;
	check_fd = open(path, O_SEARCH|O_DIRECTORY);
	if (check_fd < 0)
		return (-1);
	r = fstat(check_fd, &check_st);
	if (r < 0)
		return (-1);
	up_fd = open(".", O_SEARCH|O_DIRECTORY);
	if (up_fd < 0) {
		close(check_fd);
		return (-1);
	}
	has_last = false;
	do {
		r = fstat(up_fd, &up_st);
		if (r < 0)
			break;
		if (has_last &&
		    up_st.st_dev == last_dev &&
		    up_st.st_ino == last_ino)
			break;
		if (up_st.st_dev == check_st.st_dev &&
		    up_st.st_ino == check_st.st_ino) {
			r = 1;
			break;
		}
		r = openat(up_fd, "..", O_SEARCH|O_DIRECTORY);
		if (r < 0)
			break;
		close(up_fd);
		up_fd = r;
		has_last = true;
		last_dev = up_st.st_dev;
		last_ino = up_st.st_ino;
	} while (true);
	close(up_fd);
	close(check_fd);
	return (r);
}

