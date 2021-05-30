# $FreeBSD$

.include <src.opts.mk>

PACKAGE=	runtime
PROG=		curtain
SRCS=		curtain.c pathexp.c
LIBADD=		curtain
MAN=
CFLAGS+=	-I${.CURDIR}

CONFGROUPS=	BASECONF X11CONF

BASECONFDIR=	/etc
BASECONF=	curtain.conf

X11CONFDIR=	/etc/curtain.d/@x11
X11CONF=	fontconfig.conf

CLEANFILES+=	sysfiltab.c
SRCS+=sysfiltab.c
SYSFIL_H=${SYSROOT:U${DESTDIR}}${INCLUDEDIR}/sys/sysfil.h
sysfiltab.c: mksysfiltab.awk ${SYSFIL_H}
	awk -f ${.CURDIR}/mksysfiltab.awk < ${SYSFIL_H} > ${.TARGET}

.include <bsd.prog.mk>
