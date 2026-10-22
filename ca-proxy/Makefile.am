bin_SCRIPTS = bin/snif-relay bin/snif-tunnel bin/snif-certd bin/snif-arc bin/snif-apnsd bin/snif-syncd

snifd_ca_basedir = /var/lib/snif/ca-proxy
snifd_ca_base_DATA = README

snifd_ca_etcdir = /etc/snif/ca-proxy
snifd_ca_logdir = /var/log/snif
systemdunitdir = /lib/systemd/system
crondir = /etc/cron.d
logrotatedir = /etc/logrotate.d

# The relay side of SNIF: snif-relay, which runs snifd from the top-level
# install with this tree's pipes, snif-tunnel, which carries a cluster
# peer's pipe over ssh, and the CA proxy daemons. The hook adds the snif user, the CA proxy tree with its runtime directories
# and pipes (mkdirs), etc/ and log/, and the units.
# - Code is replaced: inc/, public_html/ and secure_html/, unless the tree
#   links them elsewhere (a release root), and the units.
# - etc/ holds the secrets and per-domain settings, so its example files are
#   copied only where absent; state and logs are kept.
# - The daily snif-arc cron entry, which lets certificates renew, and the
#   logrotate entry for the daemons' logs go in where absent.
# - Only a root install without DESTDIR makes the snif user, chowns to it
#   and reloads systemd. A staged (DESTDIR) install, e.g. for a package,
#   gets everything else.
ROOT_INSTALL = [ -z "$(DESTDIR)" ] && [ "$$(id -u)" = 0 ]
SNIF_OWNS = $(ROOT_INSTALL) && id -u snif >/dev/null 2>&1

install-data-hook:
	if $(ROOT_INSTALL) && ! id -u snif >/dev/null 2>&1; then \
	    if command -v useradd >/dev/null; then \
		useradd -r -M -d /var/lib/snif -s "$$(command -v nologin || echo /bin/false)" \
		    $$(getent group snif >/dev/null && echo '-g snif' || echo -U) snif; \
	    else echo "No useradd here: make the snif user and group by hand." >&2; fi; \
	fi
	$(MKDIR_P) "$(DESTDIR)$(snifd_ca_etcdir)" "$(DESTDIR)$(snifd_ca_logdir)"
	if $(SNIF_OWNS); then chown snif:snif $(snifd_ca_etcdir) $(snifd_ca_logdir) $(snifd_ca_basedir); fi
	chmod 02770 "$(DESTDIR)$(snifd_ca_etcdir)" "$(DESTDIR)$(snifd_ca_logdir)"
	chmod 02775 "$(DESTDIR)$(snifd_ca_basedir)"
	[ -e "$(DESTDIR)$(snifd_ca_etcdir)/snif.snif.xyz.domains" ] || \
	    $(INSTALL_DATA) $(srcdir)/etc/snif.snif.xyz.domains "$(DESTDIR)$(snifd_ca_etcdir)/"
	[ -e "$(DESTDIR)$(snifd_ca_etcdir)/snif.xyz.tsig" ] || \
	    $(INSTALL) -m 0640 $(srcdir)/etc/snif.xyz.tsig "$(DESTDIR)$(snifd_ca_etcdir)/"
	for d in inc public_html secure_html; do \
	    [ -L "$(DESTDIR)$(snifd_ca_basedir)/$$d" ] || cp -Ru $(srcdir)/$$d "$(DESTDIR)$(snifd_ca_basedir)/" || exit 1; \
	done
	[ -e "$(DESTDIR)$(snifd_ca_basedir)/etc" ] || ln -s $(snifd_ca_etcdir) "$(DESTDIR)$(snifd_ca_basedir)/etc"
	[ -e "$(DESTDIR)$(snifd_ca_basedir)/log" ] || ln -s $(snifd_ca_logdir) "$(DESTDIR)$(snifd_ca_basedir)/log"
	$(SHELL) $(srcdir)/mkdirs "$(DESTDIR)$(snifd_ca_basedir)"
	if $(SNIF_OWNS); then chown -R snif:snif $(snifd_ca_basedir); fi
	if [ -n "$(DESTDIR)" ] || [ -d $(systemdunitdir) ]; then \
	    $(MKDIR_P) "$(DESTDIR)$(systemdunitdir)" && \
	    $(INSTALL_DATA) $(srcdir)/etc/systemd/*.service "$(DESTDIR)$(systemdunitdir)/"; \
	fi
	if [ ! -e "$(DESTDIR)$(crondir)/snif-arc" ] && { [ -n "$(DESTDIR)" ] || [ -d $(crondir) ]; }; then \
	    $(MKDIR_P) "$(DESTDIR)$(crondir)" && \
	    $(INSTALL_DATA) $(srcdir)/etc/cron.d/snif-arc "$(DESTDIR)$(crondir)/"; \
	fi
	if [ ! -e "$(DESTDIR)$(logrotatedir)/snif" ] && { [ -n "$(DESTDIR)" ] || [ -d $(logrotatedir) ]; }; then \
	    $(MKDIR_P) "$(DESTDIR)$(logrotatedir)" && \
	    $(INSTALL_DATA) $(srcdir)/etc/logrotate.d/snif "$(DESTDIR)$(logrotatedir)/"; \
	fi
	if $(ROOT_INSTALL) && [ -d /run/systemd/system ]; then systemctl daemon-reload || true; fi
