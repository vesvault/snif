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
dist_bin_SCRIPTS = bin/snif-conn
snifd_snifd_LDADD = lib/libsnif.la -lssl -lcrypto

snifd_snifd_SOURCES = $(SNIFD_CFILES) $(SNIFD_HFILES)

dist_man_MANS = snifd/snifd.8 bin/snif-conn.1

# Files consumed by install-data-hook must ship in the dist tarball.
EXTRA_DIST = etc/snif.conf etc/systemd/snif-conn.service

snifd_etcdir = /etc/snif
systemdunitdir = /lib/systemd/system

# Only a root install without DESTDIR makes the snif user, chowns to it, puts
# units in the system and reloads systemd. A staged (DESTDIR) install gets the
# units; an unprivileged one, such as Homebrew's, does none of these.
ROOT_INSTALL = [ -z "$(DESTDIR)" ] && [ "$$(id -u)" = 0 ]
SNIF_OWNS = $(ROOT_INSTALL) && id -u snif >/dev/null 2>&1

# libsnif, snifd and snif-conn, then this hook: the snif user, /etc/snif with
# snif.conf, and the snif-conn unit. A relay takes snif-relay, snif-tunnel and
# their units from the ca-proxy install. An existing snif.conf is kept; the
# unit is replaced.
install-data-hook:
	if $(ROOT_INSTALL) && ! id -u snif >/dev/null 2>&1; then \
	    if command -v useradd >/dev/null; then \
		useradd -r -M -d /var/lib/snif -s "$$(command -v nologin || echo /bin/false)" \
		    $$(getent group snif >/dev/null && echo '-g snif' || echo -U) snif; \
	    else echo "No useradd here: make the snif user and group by hand." >&2; fi; \
	fi
	if [ ! -d "$(DESTDIR)$(snifd_etcdir)" ]; then \
	    $(MKDIR_P) "$(DESTDIR)$(snifd_etcdir)" || exit 1; \
	    if $(SNIF_OWNS); then chown snif:snif $(snifd_etcdir) || exit 1; fi; \
	    chmod 02750 "$(DESTDIR)$(snifd_etcdir)"; \
	fi
	[ -e "$(DESTDIR)$(snifd_etcdir)/snif.conf" ] || \
	    $(INSTALL_DATA) $(srcdir)/etc/snif.conf "$(DESTDIR)$(snifd_etcdir)/"
	if [ -n "$(DESTDIR)" ] || { $(ROOT_INSTALL) && [ -d $(systemdunitdir) ]; }; then \
	    $(MKDIR_P) "$(DESTDIR)$(systemdunitdir)" && \
	    $(INSTALL_DATA) $(srcdir)/etc/systemd/snif-conn.service "$(DESTDIR)$(systemdunitdir)/"; \
	fi
	if $(ROOT_INSTALL) && [ -d /run/systemd/system ]; then systemctl daemon-reload || true; fi
