LOCALBASE ?=	/usr/local

BINGRP =	auth
BINMODE =	550
BINDIR =	${LOCALBASE}/libexec/auth
PROG =		login_ykhmac

MANDIR =	${LOCALBASE}/man/man
MAN =		login_ykhmac.8

SRCS =		login_ykhmac.c ykhmac.c


CFLAGS +=	-pedantic -Wall -O0 -g -I/usr/local/include `pkg-config --cflags ykpers-1`


LDADD +=	-lyubikey `pkg-config --libs ykpers-1`


beforeinstall:
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m ${DIRMODE} \
		${DESTDIR}${BINDIR}

.include <bsd.prog.mk>
