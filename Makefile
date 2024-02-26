LOCALBASE ?=	/usr/local

BINGRP =	auth
BINMODE =	550
BINDIR =	${LOCALBASE}/libexec/auth
BINDIR_BASE =	/usr/libexec/auth
PROG =		login_ykhmac
PROG_BASE =	login_-ykhmac

MANDIR =	${LOCALBASE}/man/man
MAN =		login_ykhmac.8

SRCS =		login_ykhmac.c ykhmac.c


CFLAGS +=	-pedantic -Wall -O0 -g -I/usr/local/include `pkg-config --cflags ykpers-1`


LDADD +=	-lyubikey `pkg-config --libs ykpers-1`


beforeinstall:
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m ${DIRMODE} \
		${DESTDIR}${BINDIR}

afterinstall:
	${INSTALL} -o ${BINOWN} -g ${BINGRP} -m ${DIRMODE} \
		${PROG} ${DESTDIR}${BINDIR_BASE}/${PROG_BASE}

.include <bsd.prog.mk>
