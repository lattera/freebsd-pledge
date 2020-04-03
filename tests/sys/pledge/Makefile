# $FreeBSD$

PACKAGE=        tests

TESTSDIR=	${TESTSBASE}/sys/pledge

ATF_TESTS_SH+=		execpledge_various

PLAIN_TESTS_C+= pledge_super_basic_test
PLAIN_TESTS_C+= pledge_elevation
PLAIN_TESTS_C+= pledge_basic_sandboxing
PLAIN_TESTS_C+= pledge_violation_signal
PLAIN_TESTS_C+= pledge_capsicum_stack
PLAIN_TESTS_C+= pledge_simple_wpath
PLAIN_TESTS_C+= pledge_simple_exec
PLAIN_TESTS_C+= pledge_stdio_whitelist
PLAIN_TESTS_C+= pledge_resolv
PLAIN_TESTS_C+= pledge_netdb
PLAIN_TESTS_C+= pledge_localtime
PLAIN_TESTS_C+= pledge_tmppath
PLAIN_TESTS_C+= pledge_fcntl
PLAIN_TESTS_C+= pledge_getaddrinfo

PLAIN_TESTS_C+= unveil_simple0
PLAIN_TESTS_C+= unveil_simple1

WARNS?=		3

.include <bsd.test.mk>
