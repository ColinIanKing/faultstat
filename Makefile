#
# Copyright (C) 2014-2020 Canonical, Ltd.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#

VERSION=0.01.04
#

CFLAGS += -Wall -Wextra -DVERSION='"$(VERSION)"' -O2

#
# Pedantic flags
#
ifeq ($(PEDANTIC),1)
CFLAGS += -Wabi -Wcast-qual -Wfloat-equal -Wmissing-declarations \
	-Wmissing-format-attribute -Wno-long-long -Wpacked \
	-Wredundant-decls -Wshadow -Wno-missing-field-initializers \
	-Wno-missing-braces -Wno-sign-compare -Wno-multichar
endif

BINDIR=/usr/bin
MANDIR=/usr/share/man/man8
BASHDIR=/usr/share/bash-completion/completions

OBJS = faultstat.o 

faultstat: $(OBJS) Makefile
	$(CC) $(CFLAGS) $(OBJS) -lm -lncursesw -o $@ $(LDFLAGS)

faultstat.8.gz: faultstat.8
	gzip -c $< > $@

dist:
	rm -rf faultstat-$(VERSION)
	mkdir faultstat-$(VERSION)
	cp -rp Makefile faultstat.c faultstat.8 COPYING faultstat.spec \
		snapcraft.yaml .travis.yml bash-completion faultstat-$(VERSION)
	tar -Jcf faultstat-$(VERSION).tar.xz faultstat-$(VERSION)
	rm -rf faultstat-$(VERSION)

clean:
	rm -f faultstat faultstat.o faultstat.8.gz
	rm -f faultstat-$(VERSION).tar.xz
	rm -f $(OBJS)

install: faultstat faultstat.8.gz
	mkdir -p ${DESTDIR}${BINDIR}
	cp faultstat ${DESTDIR}${BINDIR}
	mkdir -p ${DESTDIR}${MANDIR}
	cp faultstat.8.gz ${DESTDIR}${MANDIR}
	mkdir -p ${DESTDIR}${BASHDIR}
	cp bash-completion/faultstat ${DESTDIR}${BASHDIR}
