#ifndef _PLEDGE_H_
#define	_PLEDGE_H_

#include <sys/unveil.h>

int	pledge(const char *, const char *);
int	unveil(const char *, const char *);
int	unveilself(const char *, const char *);
int	unveilexec(const char *, const char *);

#endif /* !_PLEDGE_H_ */
