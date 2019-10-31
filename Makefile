
SHELL = /bin/sh

MAKEFILE := $(MAKEFILE_LIST)  # hint: make -pn -f /dev/null

.PHONY: phony

KEEPT_SRCS = keept.c crrbuf.c
KEEPT_OBJS = $(KEEPT_SRCS:%.c=%.o)

# hint: make CFLAGS='-std=c99 -O2 -DDBG'
CFLAGS = -std=c99 -O2

all: keept keept.1

keept: $(KEEPT_OBJS)
	$(CC) -o $@ $(KEEPT_OBJS) -lutil -lbsd

VS = keept 1.0
VD = 2019-01-14

keept.1: README $(MAKEFILE)
	sed -e 's/^  socket/  SOCKET/' -e 's/^  COMMAND.*/  COMMAND/' $< | \
	txt2man -t keept -s 1 -r '$(VS)' -v "User commands" -d "$(VD)" | \
	sed -e 's/SS  SOCKET/SS  socket/' -e '/SS  COMMAND/ s/$$/ [[ARG]...]/'\
	> $@.wip; test -s $@.wip && mv $@.wip $@

crrbuf-test: CFLAGS += -DTEST
crrbuf-test: crrbuf.c
	$(CC) $(CFLAGS) -o $@ $<

keept.o: crrbuf.h

%.o: %.c $(MAKEFILE)
	$(CC) $(CFLAGS) -o $@ -c $<

PREFIX ?= :
install: all phony
	sed '1,/^$@.sh:/d;/^#.#eos/q' $(MAKEFILE) | /bin/sh -s "$(PREFIX)"

install.sh:
	test -n "$1" || exit 1 # embedded shell script; not to be made directly
	set -euf
	test "$1" != : || { exec >&2; echo
		echo 'Usage: make install PREFIX=prefix'; echo
		printf "Installs 'keept' to prefix/bin/. and"
		echo " 'keept.1' to prefix/share/man/man1/."; echo
		exit 1
	}
	case $1 in /*) ;; *) exec >&2; echo
		echo "make install: '$1' is not absolute path"; echo; exit 1
	esac
	set -x
	mkdir "$1"/bin/ || : try to continue :
	cp keept "$1"/bin/. && : : : : : : : : : :
	mkdir "$1"/share/man/man1/ || : try to continue :
	cp keept.1 "$1"/share/man/man1/. && : : : : : : : : : :
	exit 0
#	#eos
	exit 1 # not reached

clean:	phony
	rm -f crrbuf-test $(KEEPT_OBJS) keept.1.wip

distclean: clean
	rm -f keept keept.1

.SUFFIXES:
# used by gnu make, probably ignored by other makes
MAKEFLAGS += --no-builtin-rules --warn-undefined-variables

# SPDX-License-Identifier: BSD-2-Clause

# Local variables:
# mode: makefile
# End:
