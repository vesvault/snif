SUBDIRS = lib

SNIFD_CFILES = snifd/listen.c \
snifd/sock.c \
snifd/port.c \
snifd/host.c \
snifd/map.c \
snifd/buf.c \
snifd/ctl.c \
snifd/cln.c \
snifd/srv.c \
snifd/fifo.c \
snifd/abuse.c \
snifd/watch.c \
snifd/fwd.c \
snifd/proxy.c \
snifd/util.c \
snifd/jTree.c \
snifd/help.c \
snifd/snifd.c

SNIFD_HFILES = snifd/listen.h \
snifd/sock.h \
snifd/port.h \
snifd/host.h \
snifd/map.h \
snifd/buf.h \
snifd/ctl.h \
snifd/cln.h \
snifd/srv.h \
snifd/fifo.h \
snifd/abuse.h \
snifd/watch.h \
snifd/fwd.h \
snifd/proxy.h \
snifd/util.h \
snifd/jTree.h \
snifd/help.h

bin_PROGRAMS = snifd/snifd
dist_bin_SCRIPTS = bin/snif-conn bin/snif-relay
snifd_snifd_LDADD = lib/libsnif.la -lssl -lcrypto

snifd_snifd_SOURCES = $(SNIFD_CFILES) $(SNIFD_HFILES)

dist_man_MANS = snifd/snifd.8 bin/snif-conn.1

# Files consumed by install-data-hook must ship in the dist tarball.
EXTRA_DIST = etc/snif.conf etc/systemd/snif-conn.service

snifd_etcdir = /etc/snif

install-data-hook:
	[ -d $(snifd_etcdir) ] || ( ( useradd -U snif || true ) && mkdir -m 02750 $(snifd_etcdir) && chown snif:snif $(snifd_etcdir) )
	cp -n etc/snif.conf $(snifd_etcdir)/
	[ -d /lib/systemd/system ] && cp etc/systemd/* /lib/systemd/system || true
