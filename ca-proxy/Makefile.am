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
# peer's pipe over ssh, and the CA proxy daemons. The hook adds the users and
# groups, the CA proxy tree with its runtime directories and pipes (mkdirs),
# etc/ and log/, and the units.
# - Users and groups (README, "Users and groups"): the snif user runs the CA
#   proxy daemons and owns the tree and etc/; snifd runs snifd, in group snif
#   only; snif-apnsd runs snif-apnsd, in its own group and snif; snif-www is
#   the PHP's, in snif and snif-rw. Group snif reads /etc/snif and etc/,
#   snif-rw writes the tree, and snif-ctl is relay control: snifd's pipes.
#   Each install puts these users, and a cluster's snif-peer where it
#   exists, in their groups, and reports any other member of snif-rw or
#   snif-ctl. It removes no one.
# - Code is replaced: inc/, public_html/ and secure_html/, unless the tree
#   links them elsewhere (a release root), and the units.
# - etc/ holds the secrets and per-domain settings, so its example files are
#   copied only where absent; state and logs are kept. A secret there whose
#   owner or mode is not as below is reported, not changed: the keys are
#   0600 snif, the APNs key 0600 snif-apnsd, and the PHP's turnstile.secret
#   is group snif-rw.
# - The tree is chowned before mkdirs runs, so that mkdirs gives snifd's
#   pipes back to snifd.
# - The units include snif-arc.timer, which runs snif-arc daily and so lets
#   certificates renew; like the others it is not enabled. The logrotate
#   entry for the daemons' logs goes in where absent. The snif-arc cron
#   entry does not: make install-cron puts it in, for a host without
#   systemd. One an older install put in /etc/cron.d is kept and reported.
# - Only a root install without DESTDIR makes the users and groups, chowns
#   and reloads systemd. A staged (DESTDIR) install, e.g. for a package,
#   gets everything else.
ROOT_INSTALL = [ -z "$(DESTDIR)" ] && [ "$$(id -u)" = 0 ]
SNIF_OWNS = $(ROOT_INSTALL) && id -u snif >/dev/null 2>&1
NOLOGIN = "$$(command -v nologin || echo /bin/false)"
SECRETS = \( -name '*.tsig' -o -name '*.priv-ca' -o -name '*.key' ! -name 'apns*.key' \) \( -perm /077 -o ! -user snif \) \
	-o -name 'apns*.key' \( -perm /077 -o ! -user snif-apnsd \) \
	-o -name '*.secret' \( -perm /007 -o ! -group snif-rw \)

install-data-hook:
	if $(ROOT_INSTALL); then \
	    if ! command -v useradd >/dev/null; then \
		echo "No useradd here: make the snif, snifd, snif-apnsd and snif-www users and the snif, snif-rw and snif-ctl groups by hand (README)." >&2; \
	    else \
		id -u snif >/dev/null 2>&1 || \
		    useradd -r -M -d /var/lib/snif -s $(NOLOGIN) \
			$$(getent group snif >/dev/null && echo '-g snif' || echo -U) snif || exit 1; \
		for g in snif-rw snif-ctl; do getent group $$g >/dev/null || groupadd -r $$g || exit 1; done; \
		id -u snifd >/dev/null 2>&1 || \
		    useradd -r -M -d /nonexistent -s $(NOLOGIN) -g snif snifd || exit 1; \
		id -u snif-apnsd >/dev/null 2>&1 || \
		    useradd -r -M -d /nonexistent -s $(NOLOGIN) \
			$$(getent group snif-apnsd >/dev/null && echo '-g snif-apnsd' || echo -U) snif-apnsd || exit 1; \
		id -u snif-www >/dev/null 2>&1 || \
		    useradd -r -M -d /nonexistent -s $(NOLOGIN) -g snif snif-www || exit 1; \
		usermod -a -G snif-rw,snif-ctl snif && usermod -a -G snif snifd && \
		    usermod -a -G snif snif-apnsd && usermod -a -G snif,snif-rw snif-www || exit 1; \
		! id -u snif-peer >/dev/null 2>&1 || usermod -a -G snif,snif-rw,snif-ctl snif-peer || exit 1; \
		for g in snif-rw:snif,snif-www,snif-peer snif-ctl:snif,snif-peer; do \
		    for u in $$(getent group $${g%%:*} | cut -d: -f4 | tr , ' '); do \
			case ",$${g#*:}," in *",$$u,"*) ;; \
			    *) echo "$$u is in $${g%%:*}, which README, \"Users and groups\", does not list" >&2 ;; esac; \
		    done; \
		done; \
	    fi; \
	fi
	$(MKDIR_P) "$(DESTDIR)$(snifd_ca_etcdir)" "$(DESTDIR)$(snifd_ca_logdir)"
	if $(SNIF_OWNS); then \
	    chown snif:snif $(snifd_ca_etcdir) && chown snif:snif-rw $(snifd_ca_logdir) $(snifd_ca_basedir) || exit 1; \
	fi
	chmod 02750 "$(DESTDIR)$(snifd_ca_etcdir)"
	chmod 02770 "$(DESTDIR)$(snifd_ca_logdir)"
	chmod 02775 "$(DESTDIR)$(snifd_ca_basedir)"
	[ -e "$(DESTDIR)$(snifd_ca_etcdir)/snif.snif.xyz.domains" ] || \
	    $(INSTALL_DATA) $(srcdir)/etc/snif.snif.xyz.domains "$(DESTDIR)$(snifd_ca_etcdir)/"
	if [ ! -e "$(DESTDIR)$(snifd_ca_etcdir)/snif.xyz.tsig" ]; then \
	    $(INSTALL) -m 0600 $(srcdir)/etc/snif.xyz.tsig "$(DESTDIR)$(snifd_ca_etcdir)/" || exit 1; \
	    if $(SNIF_OWNS); then chown snif:snif $(snifd_ca_etcdir)/snif.xyz.tsig || exit 1; fi; \
	fi
	if $(SNIF_OWNS); then \
	    find $(snifd_ca_etcdir)/ -maxdepth 1 -type f \( $(SECRETS) \) | \
		sed 's/^/Owner or mode not as in README, "Users and groups": /' >&2; \
	fi
	for d in inc public_html secure_html; do \
	    [ -L "$(DESTDIR)$(snifd_ca_basedir)/$$d" ] || cp -Ru $(srcdir)/$$d "$(DESTDIR)$(snifd_ca_basedir)/" || exit 1; \
	done
	[ -e "$(DESTDIR)$(snifd_ca_basedir)/etc" ] || ln -s $(snifd_ca_etcdir) "$(DESTDIR)$(snifd_ca_basedir)/etc"
	[ -e "$(DESTDIR)$(snifd_ca_basedir)/log" ] || ln -s $(snifd_ca_logdir) "$(DESTDIR)$(snifd_ca_basedir)/log"
	if $(SNIF_OWNS); then chown -R snif:snif-rw $(snifd_ca_basedir) || exit 1; fi
	$(SHELL) $(srcdir)/mkdirs "$(DESTDIR)$(snifd_ca_basedir)"
	if [ -n "$(DESTDIR)" ] || [ -d $(systemdunitdir) ]; then \
	    $(MKDIR_P) "$(DESTDIR)$(systemdunitdir)" && \
	    $(INSTALL_DATA) $(srcdir)/etc/systemd/*.service $(srcdir)/etc/systemd/*.timer "$(DESTDIR)$(systemdunitdir)/"; \
	fi
	if [ -z "$(DESTDIR)" ] && [ -e $(crondir)/snif-arc ] && [ -d $(systemdunitdir) ]; then \
	    echo "$(crondir)/snif-arc is kept: it runs snif-arc as snif-arc.timer does, so keep one of the two" >&2; \
	fi
	if [ ! -e "$(DESTDIR)$(logrotatedir)/snif" ] && { [ -n "$(DESTDIR)" ] || [ -d $(logrotatedir) ]; }; then \
	    $(MKDIR_P) "$(DESTDIR)$(logrotatedir)" && \
	    $(INSTALL_DATA) $(srcdir)/etc/logrotate.d/snif "$(DESTDIR)$(logrotatedir)/"; \
	fi
	if $(ROOT_INSTALL) && [ -d /run/systemd/system ]; then systemctl daemon-reload || true; fi

# The cron entry, instead of snif-arc.timer, for a host without systemd: it
# goes in where absent, and an existing one is kept. It runs nothing without
# a cron daemon, and twice a day beside an enabled timer: both are reported.
install-cron:
	if [ -e "$(DESTDIR)$(crondir)/snif-arc" ]; then \
	    echo "$(crondir)/snif-arc exists: kept"; \
	else \
	    $(MKDIR_P) "$(DESTDIR)$(crondir)" && \
	    $(INSTALL_DATA) $(srcdir)/etc/cron.d/snif-arc "$(DESTDIR)$(crondir)/" || exit 1; \
	fi
	if [ -z "$(DESTDIR)" ]; then \
	    PATH="$$PATH:/usr/sbin:/sbin"; \
	    command -v cron >/dev/null || command -v crond >/dev/null || \
		echo "No cron daemon here: $(crondir)/snif-arc runs nothing until one is installed" >&2; \
	    ! systemctl is-enabled -q snif-arc.timer 2>/dev/null || \
		echo "snif-arc.timer is enabled too: disable it, or remove $(crondir)/snif-arc" >&2; \
	fi

.PHONY: install-cron
