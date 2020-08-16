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


#define TRY_BOOL(expr, should_work) do { \
	if (!(expr)) { \
		if (should_work) \
			err(1, "%s", #expr); \
	} else { \
		if (!should_work) \
			errx(1, "%s: %s", #expr, "shouldn't have worked"); \
	} \
} while (0)

#define EXPECT_BOOL(expr) TRY_BOOL(expr, true)
#define REJECT_BOOL(expr) TRY_BOOL(expr, false)


#define TRY_PTR(expr, should_work) do { \
	if ((expr) == NULL) { \
		if (should_work) \
			err(1, "%s", #expr); \
	} else { \
		if (!should_work) \
			errx(1, "%s: %s", #expr, "shouldn't have worked"); \
	} \
} while (0)

#define EXPECT_PTR(expr) TRY_PTR(expr, true)
#define REJECT_PTR(expr) TRY_PTR(expr, false)
