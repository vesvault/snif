dist_bin_SCRIPTS = bin/snifdog

dist_man_MANS = snifdog.8

snifdoglibdir = /usr/share/snifdog/lib/Snif/CT
dist_snifdoglib_DATA = lib/Snif/CT/CertSpotter.pm lib/Snif/CT/CrtSh.pm

snifdog_etcdir = /etc/snif

snifdog_basedir = /var/lib/snif/snifdog
dist_snifdog_base_DATA = README

systemdunitdir = /lib/systemd/system
crondir = /etc/cron.d

EXTRA_DIST = DESIGN.md etc/snifdog.conf etc/systemd/snifdog.service etc/systemd/snifdog@.service \
	etc/cron.d/snifdog mkdirs test/state.t

# The state directories and the units are made or replaced. The example
# snifdog.conf and the cron.d entry go in only on a first install, when no
# configuration exists: an operator who moved snifdog.conf into snifdog.d,
# or chose the watch units and removed the cron entry, keeps that choice.
# Only a root install without DESTDIR makes the snif user, chowns to it and
# reloads systemd. A staged (DESTDIR) install, e.g. for a package, gets
# everything else.
ROOT_INSTALL = [ -z "$(DESTDIR)" ] && [ "$$(id -u)" = 0 ]
SNIF_OWNS = $(ROOT_INSTALL) && id -u snif >/dev/null 2>&1

install-data-hook:
	if $(ROOT_INSTALL) && ! id -u snif >/dev/null 2>&1; then \
	    if command -v useradd >/dev/null; then \
		useradd -r -M -d /var/lib/snif -s "$$(command -v nologin || echo /bin/false)" \
		    $$(getent group snif >/dev/null && echo '-g snif' || echo -U) snif; \
	    else echo "No useradd here: make the snif user and group by hand." >&2; fi; \
	fi
	if [ ! -e "$(DESTDIR)$(snifdog_etcdir)/snifdog.conf" ] && \
	    ! ls "$(DESTDIR)$(snifdog_etcdir)"/snifdog.d/*.conf >/dev/null 2>&1; then \
	    $(MKDIR_P) "$(DESTDIR)$(snifdog_etcdir)" && \
	    $(INSTALL_DATA) $(srcdir)/etc/snifdog.conf "$(DESTDIR)$(snifdog_etcdir)/" && \
	    if [ -n "$(DESTDIR)" ] || [ -d $(crondir) ]; then \
		$(MKDIR_P) "$(DESTDIR)$(crondir)" && \
		$(INSTALL_DATA) $(srcdir)/etc/cron.d/snifdog "$(DESTDIR)$(crondir)/"; \
	    fi; \
	fi
	[ -d "$(DESTDIR)$(snifdog_etcdir)/snifdog.d" ] || mkdir -m 0755 "$(DESTDIR)$(snifdog_etcdir)/snifdog.d"
	[ -d "$(DESTDIR)$(snifdog_basedir)/pins" ] || mkdir -m 02775 "$(DESTDIR)$(snifdog_basedir)/pins"
	[ -d "$(DESTDIR)$(snifdog_basedir)/var" ] || mkdir -m 02755 "$(DESTDIR)$(snifdog_basedir)/var"
	[ -d "$(DESTDIR)$(snifdog_basedir)/evidence" ] || mkdir -m 02755 "$(DESTDIR)$(snifdog_basedir)/evidence"
	chmod 02775 "$(DESTDIR)$(snifdog_basedir)"
	if $(SNIF_OWNS); then chown -R snif:snif $(snifdog_basedir); fi
	if [ -n "$(DESTDIR)" ] || [ -d $(systemdunitdir) ]; then \
	    $(MKDIR_P) "$(DESTDIR)$(systemdunitdir)" && \
	    $(INSTALL_DATA) $(srcdir)/etc/systemd/snifdog.service $(srcdir)/etc/systemd/snifdog@.service "$(DESTDIR)$(systemdunitdir)/"; \
	fi
	if $(ROOT_INSTALL) && [ -d /run/systemd/system ]; then systemctl daemon-reload || true; fi
