# $FreeBSD$

.include <src.opts.mk>

PACKAGE=	runtime
PROG=		curtain
SRCS=		curtain.c pathexp.c
LIBADD=		curtain
MAN=
CFLAGS+=	-I${.CURDIR}

CONFGROUPS=	BASECONF GUICONF

BASECONFDIR=	/etc
BASECONF=	curtain.conf

GUICONFDIR=	/etc/curtain.d/@gui
GUICONF=	fontconfig.conf

CLEANFILES+=	sysfiltab.c
SRCS+=sysfiltab.c
SYSFIL_H=${SYSROOT:U${DESTDIR}}${INCLUDEDIR}/sys/sysfil.h
sysfiltab.c: mksysfiltab.awk ${SYSFIL_H}
	awk -f ${.CURDIR}/mksysfiltab.awk < ${SYSFIL_H} > ${.TARGET}

.include <bsd.prog.mk>
