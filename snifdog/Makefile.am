dist_bin_SCRIPTS = bin/snifdog

dist_man_MANS = snifdog.8

snifdoglibdir = /usr/share/snifdog/lib/Snif/CT
dist_snifdoglib_DATA = lib/Snif/CT/CertSpotter.pm lib/Snif/CT/CrtSh.pm

snifdog_etcdir = /etc/snif
dist_snifdog_etc_DATA = etc/snifdog.conf

snifdog_basedir = /var/lib/snif/snifdog
dist_snifdog_base_DATA = README

EXTRA_DIST = DESIGN.md etc/systemd/snifdog.service etc/systemd/snifdog@.service \
	etc/cron.d/snifdog mkdirs test/state.t

install-data-hook:
	[ -d $(snifdog_etcdir)/snifdog.d ] || mkdir -m 0755 $(snifdog_etcdir)/snifdog.d
	[ -d $(snifdog_basedir) ] || mkdir -m 02775 $(snifdog_basedir)
	[ -d $(snifdog_basedir)/pins ] || mkdir -m 02775 $(snifdog_basedir)/pins
	[ -d $(snifdog_basedir)/var ] || mkdir -m 02755 $(snifdog_basedir)/var
	[ -d $(snifdog_basedir)/evidence ] || mkdir -m 02755 $(snifdog_basedir)/evidence
	( id -u snif >/dev/null 2>&1 ) && chown -R snif:snif $(snifdog_basedir) || true
	[ -d /lib/systemd/system ] && cp etc/systemd/snifdog.service etc/systemd/snifdog@.service /lib/systemd/system || true
	[ -d /etc/cron.d ] && cp etc/cron.d/snifdog /etc/cron.d/snifdog || true
