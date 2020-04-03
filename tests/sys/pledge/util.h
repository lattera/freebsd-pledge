#include <err.h>
#include <stdbool.h>

#define TRY(expr, should_work) do { \
	if ((expr) < 0) { \
		if (should_work) \
			err(1, "%s", #expr); \
	} else { \
		if (!should_work) \
			errx(1, "%s: %s", #expr, "shouldn't have worked"); \
	} \
} while (0)

#define EXPECT(expr) TRY(expr, true)
#define REJECT(expr) TRY(expr, false)
