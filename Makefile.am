LIB_CFILES = lib/cert.c \
lib/conn.c

LIB_HFILES = lib/cert.h \
lib/conn.h

SNIFD_CFILES = snifd/listen.c \
snifd/sock.c \
snifd/port.c \
snifd/host.c \
snifd/buf.c \
snifd/ctl.c \
snifd/cln.c \
snifd/srv.c \
snifd/fifo.c \
snifd/abuse.c \
snifd/watch.c \
snifd/fwd.c \
snifd/util.c \
snifd/jTree.c \
snifd/help.c \
snifd/snifd.c

SNIFD_HFILES = snifd/listen.h \
snifd/sock.h \
snifd/port.h \
snifd/host.h \
snifd/buf.h \
snifd/ctl.h \
snifd/cln.h \
snifd/srv.h \
snifd/fifo.h \
snifd/abuse.h \
snifd/watch.h \
snifd/fwd.h \
snifd/util.h \
snifd/jTree.h \
snifd/help.h

bin_PROGRAMS = snifd/snifd
bin_SCRIPTS = bin/snif-conn
snifd_snifd_LDADD = -lcrypto -lcurl -lssl

snifd_snifd_SOURCES = $(LIB_CFILES) $(SNIFD_CFILES) $(LIB_HFILES) $(SNIFD_HFILES)

snifd_etcdir = /etc/snif
snifd_etc_DATA = etc/snif.conf

install-data-hook:
	useradd snif || true
	chown snif:snif $(snifd_etcdir)
	chmod 0770 $(snifd_etcdir)
	[ -d /lib/systemd/system ] && cp etc/systemd/* /lib/systemd/system || true
