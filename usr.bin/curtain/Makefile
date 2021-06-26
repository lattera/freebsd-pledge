# $FreeBSD$

.include <src.opts.mk>

PACKAGE=	runtime
PROG=		curtain
SRCS=		curtain.c config.c pathexp.c
LIBADD=		curtain util
MAN=
CFLAGS+=	-I${.CURDIR}

CONFGROUPS=	BASECONF GUICONF

BASECONFDIR=	/etc
BASECONF=	curtain.conf

GUICONFDIR=	/etc/curtain.d/_gui.d
GUICONF=	fontconfig.conf

.if ${MK_EXAMPLES} != "no"
FILESDIR=	${SHAREDIR}/examples/curtain
FILES=		curtain.conf.sample
.endif

CLEANFILES+=	sysfiltab.c privtab.c
SRCS+=sysfiltab.c privtab.c
SYSFIL_H=${SYSROOT:U${DESTDIR}}${INCLUDEDIR}/sys/sysfil.h
PRIV_H=${SYSROOT:U${DESTDIR}}${INCLUDEDIR}/sys/priv.h
sysfiltab.c: mksysfiltab.awk ${SYSFIL_H}
	awk -f ${.CURDIR}/mksysfiltab.awk < ${SYSFIL_H} > ${.TARGET}
privtab.c: mkprivtab.awk ${PRIV_H}
	awk -f ${.CURDIR}/mkprivtab.awk < ${PRIV_H} > ${.TARGET}

.include <bsd.prog.mk>
