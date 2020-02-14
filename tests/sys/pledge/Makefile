# $FreeBSD$

TESTSDIR=	${TESTSBASE}/sys/pledge

PLAIN_TESTS_C+= pledge_super_basic_test
PLAIN_TESTS_C+= pledge_elevation
PLAIN_TESTS_C+= pledge_basic_sandboxing
PLAIN_TESTS_C+= pledge_violation_signal
PLAIN_TESTS_C+= pledge_capsicum_stack
PLAIN_TESTS_C+= pledge_simple_wpath

WARNS?=		3

.include <bsd.test.mk>
