dist_bin_SCRIPTS = bin/snifdog

dist_man_MANS = snifdog.8

snifdoglibdir = /usr/share/snifdog/lib/Snif/CT
dist_snifdoglib_DATA = lib/Snif/CT/CertSpotter.pm lib/Snif/CT/CrtSh.pm

snifdog_etcdir = /etc/snif

snifdog_basedir = /var/lib/snif/snifdog
dist_snifdog_base_DATA = README

systemdunitdir = /lib/systemd/system
crondir = /etc/cron.d
snifdog_sharedir = /usr/share/snifdog

EXTRA_DIST = DESIGN.md etc/snifdog.conf etc/systemd/snifdog.service etc/systemd/snifdog@.service \
	etc/cron.d/snifdog mkdirs test/state.t

# The state directories and the units are made or replaced, and no unit is
# enabled. The example configuration and cron entry go to
# /usr/share/snifdog/, never to /etc: nothing runs until an operator writes
# a configuration in /etc/snif/snifdog.d/ and enables snifdog@<base>, or
# runs make install-cron. A configuration or cron entry that an older install
# put in /etc is left as it is.
# snifdog runs as its own user, snifdog, and owns its state, which no group
# can write: what it watches cannot change its pins. On a relay host it is
# in group snif, the CA proxy's read-only group (ca-proxy/README, "Users and
# groups"), for snif.conf, its configurations and etc/*.domains; csr/ is
# readable by all. A standalone watcher gets a group of its own.
# Only a root install without DESTDIR makes the snifdog user, chowns to it
# and reloads systemd. A staged (DESTDIR) install, e.g. for a package, gets
# everything else.
ROOT_INSTALL = [ -z "$(DESTDIR)" ] && [ "$$(id -u)" = 0 ]
SNIFDOG_OWNS = $(ROOT_INSTALL) && id -u snifdog >/dev/null 2>&1

install-data-hook:
	if $(ROOT_INSTALL) && ! id -u snifdog >/dev/null 2>&1; then \
	    if command -v useradd >/dev/null; then \
		useradd -r -M -d $(snifdog_basedir) -s "$$(command -v nologin || echo /bin/false)" \
		    $$(getent group snif >/dev/null && echo '-g snif' || echo -U) snifdog || exit 1; \
	    else echo "No useradd here: make the snifdog user by hand, in group snif on a relay host." >&2; fi; \
	fi
	$(MKDIR_P) "$(DESTDIR)$(snifdog_sharedir)" "$(DESTDIR)$(snifdog_etcdir)"
	$(INSTALL_DATA) $(srcdir)/etc/snifdog.conf "$(DESTDIR)$(snifdog_sharedir)/snifdog.conf.example"
	$(INSTALL_DATA) $(srcdir)/etc/cron.d/snifdog "$(DESTDIR)$(snifdog_sharedir)/cron.d-snifdog.example"
	[ -d "$(DESTDIR)$(snifdog_etcdir)/snifdog.d" ] || mkdir -m 0755 "$(DESTDIR)$(snifdog_etcdir)/snifdog.d"
	[ -d "$(DESTDIR)$(snifdog_basedir)/pins" ] || mkdir -m 0755 "$(DESTDIR)$(snifdog_basedir)/pins"
	[ -d "$(DESTDIR)$(snifdog_basedir)/var" ] || mkdir -m 0755 "$(DESTDIR)$(snifdog_basedir)/var"
	[ -d "$(DESTDIR)$(snifdog_basedir)/evidence" ] || mkdir -m 0755 "$(DESTDIR)$(snifdog_basedir)/evidence"
	chmod -R g-ws,o-w "$(DESTDIR)$(snifdog_basedir)"
	if $(SNIFDOG_OWNS); then chown -R snifdog: $(snifdog_basedir); fi
	if [ -n "$(DESTDIR)" ] || [ -d $(systemdunitdir) ]; then \
	    $(MKDIR_P) "$(DESTDIR)$(systemdunitdir)" && \
	    $(INSTALL_DATA) $(srcdir)/etc/systemd/snifdog.service $(srcdir)/etc/systemd/snifdog@.service "$(DESTDIR)$(systemdunitdir)/"; \
	fi
	if $(ROOT_INSTALL) && [ -d /run/systemd/system ]; then systemctl daemon-reload || true; fi

# The cron entry, instead of the snifdog@ units: it goes in where absent, and
# an existing one is kept. It runs nothing without a cron daemon, which is
# reported.
install-cron:
	if [ -e "$(DESTDIR)$(crondir)/snifdog" ]; then \
	    echo "$(crondir)/snifdog exists: kept"; \
	else \
	    $(MKDIR_P) "$(DESTDIR)$(crondir)" && \
	    $(INSTALL_DATA) $(srcdir)/etc/cron.d/snifdog "$(DESTDIR)$(crondir)/" || exit 1; \
	fi
	if [ -z "$(DESTDIR)" ]; then \
	    PATH="$$PATH:/usr/sbin:/sbin"; \
	    command -v cron >/dev/null || command -v crond >/dev/null || \
		echo "No cron daemon here: $(crondir)/snifdog runs nothing until one is installed" >&2; \
	fi

.PHONY: install-cron
