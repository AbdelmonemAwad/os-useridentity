#!/bin/sh
# Copyright (C) 2026 Abdelmonem Awad <eg2@live.com>. BSD 2-Clause License.
#
# Run by pkg(8) before the files of os-useridentity are removed. The rc script that stops the collector
# and the scripts that forget the map and take the aliases out are packaged files: by post-deinstall
# they are gone. So the collector is stopped here, every mapping forgotten and the tables emptied while
# their aliases are there, the aliases taken out of Firewall: Aliases and XGS: Settings' cut list
# through OPNsense's own models - switched off instead where a rule or a setting still names one - and
# syslog-ng's source taken away, syslog-ng restarted so it lets its port go.
#
# pkg runs the old package's pre-deinstall in an upgrade too, where nothing is to go: the map, the
# aliases and the source stay, and the new package's post-install starts the collector again with the
# new code. PKG_UPGRADE is set in that case and no other.
if [ -n "${PKG_UPGRADE}" ]; then
	exit 0
fi

if [ -x /usr/local/etc/rc.d/useridentity ]; then
	/usr/local/etc/rc.d/useridentity onestop > /dev/null 2>&1 || true
fi
# daemon(8) first, which would start the collector again; the brackets keep the patterns from
# matching the shell that runs this text
/bin/pkill -f 'daemon: [u]seridentity\[' 2> /dev/null || true
/bin/pkill -f '/usr/local/opnsense/scripts/[u]seridentity/' 2> /dev/null || true

if [ -f /usr/local/sbin/configctl ]; then
	/usr/local/sbin/configctl useridentity flush > /dev/null 2>&1 || true
	/usr/local/sbin/configctl useridentity remove > /dev/null 2>&1 || true
fi

if [ -f /usr/local/etc/syslog-ng.conf.d/useridentity.conf ]; then
	rm -f /usr/local/etc/syslog-ng.conf.d/useridentity.conf
	[ -f /usr/local/sbin/configctl ] && /usr/local/sbin/configctl syslog restart > /dev/null 2>&1 || true
fi
