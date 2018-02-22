# Makefile for libnss-radius

#### Start of system configuration section. ####

CC = gcc
INSTALL = /usr/bin/install
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644

prefix = ""
exec_prefix = ${prefix}

# Where the installed binary goes.
bindir = ${exec_prefix}/bin
binprefix =

sysconfdir = /etc

# mandir = /usr/local/src/less-394/debian/less/usr/share/man
manext = 1
manprefix =

#### End of system configuration section. ####

all:	libnss_radius libnss_radius_test 

libnss_radius:	libnss_radius.c
	${CC} -fPIC -Wall -shared -o libnss_radius.so.2 -Wl,-soname,libnss_radius.so.2 libnss_radius.c

test:	libnss_radius_test.c
	${CC} -fPIC -Wall -o libnss_radius_test libnss_radius_test.c

install:	
	# remeber  /lib/libnss_compat.so.2 -> libnss_compat-2.3.6.so
	${INSTALL_DATA} libnss_radius.so.2 ${prefix}/lib/libnss_radius-2.3.6.so
	${INSTALL_DATA} libnss-radius.3 ${prefix}/usr/share/man/man3
	cd ${prefix}/lib && ln -fs libnss_radius-2.3.6.so libnss_radius.so.2

clean:
	rm -f libnss_radius.so.2 libnss_radius_test
	rm -rf debian/libnss-radius
	rm -f build-stamp
	rm -rf BUILD BUILDROOT RPMS SRPMS SOURCES SPECS

rpm: libnss_ato
	rm -rf BUILD BUILDROOT RPMS SRPMS SOURCES SPECS
	rpmbuild -ba rpm/libnss-radius.spec --define "_topdir $$(pwd)"
