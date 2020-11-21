# $FreeBSD$

PACKAGE=        tests

TESTSDIR=	${TESTSBASE}/sys/pledge

BINDIR=			${TESTSDIR}
PROGS+=			suid-check
BINMODE.suid-check=	4555

ATF_TESTS_SH+=		execpledge_various
ATF_TESTS_SH+=		execpledge_hard_link

PLAIN_TESTS_C+= pledge_super_basic_test
PLAIN_TESTS_C+= pledge_elevation
PLAIN_TESTS_C+= pledge_basic_sandboxing
PLAIN_TESTS_C+= pledge_violation_signal
PLAIN_TESTS_C+= pledge_sigtrap_uncatchable
PLAIN_TESTS_C+= pledge_capsicum_stack
PLAIN_TESTS_C+= pledge_simple_wpath
PLAIN_TESTS_C+= pledge_simple_exec
PLAIN_TESTS_C+= pledge_stdio_whitelist
PLAIN_TESTS_C+= pledge_drop
PLAIN_TESTS_C+= pledge_resolv
PLAIN_TESTS_C+= pledge_netdb
PLAIN_TESTS_C+= pledge_localtime
PLAIN_TESTS_C+= pledge_tmppath
PLAIN_TESTS_C+= pledge_fcntl
PLAIN_TESTS_C+= pledge_getaddrinfo
PLAIN_TESTS_C+= pledge_chown_own
PLAIN_TESTS_C+= pledge_fattr
PLAIN_TESTS_C+= pledge_prot_exec
PLAIN_TESTS_C+= pledge_proc_child
PLAIN_TESTS_C+= pledge_suid_exec

PLAIN_TESTS_C+= unveil_simple0
PLAIN_TESTS_C+= unveil_simple1
PLAIN_TESTS_C+= unveil_disable
PLAIN_TESTS_C+= unveil_subdir
PLAIN_TESTS_C+= unveil_openat
PLAIN_TESTS_C+= unveil_relpath
PLAIN_TESTS_C+= unveil_chdir
PLAIN_TESTS_C+= unveil_escape
PLAIN_TESTS_C+= unveil_fork
PLAIN_TESTS_C+= unveil_after_pledge
PLAIN_TESTS_C+= unveil_pledge_drop
PLAIN_TESTS_C+= pledge_after_unveil
PLAIN_TESTS_C+= unveil_pledge_limit
PLAIN_TESTS_C+= unveil_curr_only

PLAIN_TESTS_C+= unveilctl_sweep
PLAIN_TESTS_C+= unveilctl_restrict

PLAIN_TESTS_C+= sysfilctl_path_open

WARNS?=		3

.include <bsd.test.mk>
