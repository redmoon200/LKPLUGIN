# Copyright (c) 2026, redmoon200
# SPDX-License-Identifier: BSD-2-Clause
#
# Builds l7engine on FreeBSD/OPNsense (needs the ndpi and sqlite3 packages;
# libpcap and clang are part of the base system).

PROG=	l7engine
SRCS=	src/main.c src/config.c src/store.c src/policy.c

LOCALBASE?=	/usr/local
CC?=		cc
CFLAGS+=	-O2 -g -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare \
		-I${LOCALBASE}/include -I${LOCALBASE}/include/ndpi
LDFLAGS+=	-L${LOCALBASE}/lib
LIBS=		-lndpi -lsqlite3 -lpcap -lm -lpthread
OBJS=		${SRCS:.c=.o}

all: ${PROG}

${PROG}: ${OBJS}
	${CC} ${LDFLAGS} -o ${PROG} ${OBJS} ${LIBS}

.c.o:
	${CC} ${CFLAGS} -c -o $@ $<

# Robustness test: parsers under AddressSanitizer + UBSan with mutated packets
fuzz: tests/fuzz.c src/main.c src/config.c src/store.c src/policy.c src/l7.h
	${CC} -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer ${CFLAGS} ${LDFLAGS} 		-o fuzz tests/fuzz.c src/config.c src/store.c src/policy.c ${LIBS}

check: fuzz
	./fuzz 300000 1
	./fuzz 300000 2

clean:
	rm -f ${PROG} ${OBJS} fuzz

.PHONY: all clean fuzz check
