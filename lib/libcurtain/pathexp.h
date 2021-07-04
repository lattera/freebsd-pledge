#ifndef _PATHEXP_H_
#define _PATHEXP_H_

#include <stdbool.h>

int pathexp(const char *pat, char *exp, size_t exp_size,
    const char **err, int (*callback)(void *, char *), void *callback_data);

#endif
