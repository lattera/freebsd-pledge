# $FreeBSD$

.include <src.opts.mk>

PACKAGE=	runtime
PROG=		curtain
SRCS=		curtain.c
LIBADD=		curtain util
MAN=

.if ${MK_EXAMPLES} != "no"
FILESDIR=	${SHAREDIR}/examples/curtain
FILES=		home-sandbox.sh xdg-sandbox.sh
FILESMODE=	555
.endif

.include <bsd.prog.mk>
