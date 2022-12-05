bin_SCRIPTS = ../bin/snif-relay bin/snif-certd bin/snif-arc bin/snif-apnsd

snifd_ca_basedir = /var/lib/snif/ca-proxy
snifd_ca_base_DATA = README

snifd_ca_etcdir = /etc/snif/ca-proxy
snifd_ca_etc_DATA = etc/snif.snif.xyz.domains etc/snif.xyz.tsig

snifd_ca_logdir = /var/log/snif/
snifd_ca_log_DATA =

install-data-hook:
	chown snif:snif $(snifd_ca_basedir)
	chmod 02775 $(snifd_ca_basedir)
	chown snif:snif $(snifd_ca_etcdir)
	chmod 02770 $(snifd_ca_etcdir)
	chown snif:snif $(snifd_ca_logdir)
	chmod 02770 $(snifd_ca_logdir)
	cp -Ru inc $(snifd_ca_basedir)/
	cp -Ru public_html $(snifd_ca_basedir)/
	cp -Ru secure_html $(snifd_ca_basedir)/
	[ -L $(snifd_ca_basedir)/etc ] || ln -s $(snifd_ca_etcdir) $(snifd_ca_basedir)/etc
	[ -L $(snifd_ca_basedir)/log ] || ln -s $(snifd_ca_logdir) $(snifd_ca_basedir)/log
	[ -d $(snifd_ca_basedir)/csr ] || mkdir -m 02775 $(snifd_ca_basedir)/csr
	[ -d $(snifd_ca_basedir)/cfg ] || mkdir -m 02775 $(snifd_ca_basedir)/cfg
	[ -d $(snifd_ca_basedir)/auth ] || mkdir -m 02775 $(snifd_ca_basedir)/auth
	[ -d $(snifd_ca_basedir)/arc ] || mkdir -m 02755 $(snifd_ca_basedir)/arc
	[ -d $(snifd_ca_basedir)/var ] || mkdir -m 02755 $(snifd_ca_basedir)/var
	[ -d $(snifd_ca_basedir)/apns ] || mkdir -m 02775 $(snifd_ca_basedir)/apns
	[ -p $(snifd_ca_basedir)/var/snif-certd.ctl ] || mkfifo -m 0620 $(snifd_ca_basedir)/var/snif-certd.ctl
	[ -p $(snifd_ca_basedir)/var/snifd-in.ctl ] || mkfifo -m 0620 $(snifd_ca_basedir)/var/snifd-in.ctl
	[ -p $(snifd_ca_basedir)/var/snifd-out-apnsd.ctl ] || mkfifo -m 0640 $(snifd_ca_basedir)/var/snifd-out-apnsd.ctl
	chown -R snif $(snifd_ca_basedir)
	[ -d /lib/systemd/system ] && cp etc/systemd/* /lib/systemd/system || true
