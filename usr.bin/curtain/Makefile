# $FreeBSD$

.include <src.opts.mk>

PACKAGE=runtime
PROG=	curtain
SRCS=	curtain.c pathexp.c
LIBADD=	curtain
MAN=

CONFGROUPS=	BASECONF X11CONF

BASECONFDIR=	/etc
BASECONF=	curtain.conf

X11CONFDIR=	/etc/curtain.d/@x11
X11CONF=	fontconfig.conf

.include <bsd.prog.mk>
