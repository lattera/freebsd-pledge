# $FreeBSD$

PACKAGE=        tests

TESTSDIR=	${TESTSBASE}/sys/curtain

BINDIR=			${TESTSDIR}
PROGS+=			suid-check
BINMODE.suid-check=	4555

ATF_TESTS_SH+=		execpledge_various
ATF_TESTS_SH+=		execpledge_hard_link
ATF_TESTS_SH+=		curtain_various

LIBADD=		curtain

ATF_TESTS_C+=	pledge_super_basic
ATF_TESTS_C+=	pledge_stdio_basic
ATF_TESTS_C+=	pledge_paths
ATF_TESTS_C+=	pledge_drop
ATF_TESTS_C+=	pledge_capsicum
ATF_TESTS_C+=	pledge_proc
ATF_TESTS_C+=	pledge_exec
ATF_TESTS_C+=	pledge_chown_same
ATF_TESTS_C+=	pledge_fattr
ATF_TESTS_C+=	pledge_netdb
ATF_TESTS_C+=	pledge_socket
ATF_TESTS_C+=	pledge_tty
LIBADD.pledge_tty+= util

ATF_TESTS_C+=	unveil_paths
ATF_TESTS_C+=	unveil_fork
ATF_TESTS_C+=	unveil_before_pledge
ATF_TESTS_C+=	unveil_pledge
ATF_TESTS_C+=	unveil_exec
ATF_TESTS_C+=	unveil_fattr
ATF_TESTS_C+=	unveil_emptypath

ATF_TESTS_C+=	prot_exec

ATF_TESTS_C+=	curtain_levels
ATF_TESTS_C+=	curtainctl_overflow

PLAIN_TESTS_C+=	openbsd-unveil-syscalls
WARNS.openbsd-unveil-syscalls=3

.include <bsd.test.mk>
