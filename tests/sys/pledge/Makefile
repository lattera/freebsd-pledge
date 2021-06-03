# $FreeBSD$

PACKAGE=        tests

TESTSDIR=	${TESTSBASE}/sys/pledge

BINDIR=			${TESTSDIR}
PROGS+=			suid-check
BINMODE.suid-check=	4555

ATF_TESTS_SH+=		execpledge_various
ATF_TESTS_SH+=		execpledge_hard_link
ATF_TESTS_SH+=		curtain_various

LIBADD=		curtain

ATF_TESTS_C+=	atf_pledge_super_basic
ATF_TESTS_C+=	atf_pledge_stdio_basic
ATF_TESTS_C+=	atf_pledge_paths
ATF_TESTS_C+=	atf_pledge_drop
ATF_TESTS_C+=	atf_pledge_capsicum
ATF_TESTS_C+=	atf_pledge_proc
ATF_TESTS_C+=	atf_pledge_exec
ATF_TESTS_C+=	atf_pledge_chown_same
ATF_TESTS_C+=	atf_pledge_prot_exec
ATF_TESTS_C+=	atf_pledge_netdb
ATF_TESTS_C+=	atf_pledge_socket

ATF_TESTS_C+=	atf_unveil_paths
ATF_TESTS_C+=	atf_unveil_fork
ATF_TESTS_C+=	atf_unveil_before_pledge
ATF_TESTS_C+=	atf_unveil_pledge
ATF_TESTS_C+=	atf_unveil_exec
ATF_TESTS_C+=	atf_unveil_fattr

PLAIN_TESTS_C+=	openbsd-unveil-syscalls
WARNS.openbsd-unveil-syscalls=3

.include <bsd.test.mk>
