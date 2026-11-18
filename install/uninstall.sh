#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
# Remove the User Identity plugin: the collector stopped, its aliases taken out of Firewall: Aliases -
# switched off instead where a rule or a setting still names one - and out of XGS: Settings' cut list,
# syslog-ng's source taken away, its files, its state in /var/db/os-useridentity (the map with it), and
# the addresses its tables held. Kept: the settings in config.xml.

# the collector and the aliases first, while the files that stop and remove them are there
/usr/local/etc/rc.d/useridentity onestop > /dev/null 2>&1 || true
# a collector the rc script did not find - daemon(8) first, which would start it again - and what it
# started; the brackets keep the patterns from matching a shell that carries this text
/bin/pkill -f 'daemon: [u]seridentity\[' 2> /dev/null || true
/bin/pkill -f '/usr/local/opnsense/scripts/[u]seridentity/' 2> /dev/null || true
# every mapping forgotten and the tables emptied while their aliases are there, then the aliases out
configctl useridentity flush > /dev/null 2>&1 || true
configctl useridentity remove > /dev/null 2>&1 || true

# syslog-ng's source, which is not one of src/'s files: taken away, and syslog-ng restarted so it lets
# the port go and stops sending to a socket that is gone
if [ -f /usr/local/etc/syslog-ng.conf.d/useridentity.conf ]; then
    rm -f /usr/local/etc/syslog-ng.conf.d/useridentity.conf
    configctl syslog restart > /dev/null 2>&1 || true
fi

# the hook, the rc script and the minute's run, then everything else src/ lays down
rm -f /usr/local/etc/inc/plugins.inc.d/useridentity.inc
rm -f /usr/local/etc/rc.d/useridentity
rm -f /usr/local/etc/cron.d/useridentity
rm -rf /usr/local/share/os-useridentity
rm -f /usr/local/opnsense/service/conf/actions.d/actions_useridentity.conf
rm -rf /usr/local/opnsense/scripts/useridentity
# the menu file place-menu.sh wrote, which is not one of src/'s files
rm -f /usr/local/opnsense/mvc/app/models/OPNsense/UserIdentity/Menu/Menu.xml
rmdir /usr/local/opnsense/mvc/app/models/OPNsense/UserIdentity/Menu 2>/dev/null || true
rm -rf /usr/local/opnsense/mvc/app/models/OPNsense/UserIdentity
rm -rf /usr/local/opnsense/mvc/app/controllers/OPNsense/UserIdentity
rm -rf /usr/local/opnsense/mvc/app/views/OPNsense/UserIdentity
rm -rf /usr/local/opnsense/mvc/app/library/OPNsense/UserIdentity
# the map, the counts, the history and the alerts no one collected; the pidfiles and the socket if the
# collector had to be killed
rm -rf /var/db/os-useridentity
rm -f /var/run/useridentity.pid /var/run/useridentity.daemon.pid /var/run/useridentity.sock
service configd restart > /dev/null
# PHP keeps them in its own temporary directory on 26.7 (/var/lib/php/tmp); /tmp is where they were
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json \
    /tmp/opnsense_menu_cache.xml /tmp/opnsense_acl_cache.json
# the filter without the hook: the redirect gone; cron without the minute's run
configctl filter reload skip_alias > /dev/null 2>&1 || true
configctl cron restart > /dev/null 2>&1 || true
# The tables of the plugin's aliases that are gone, taken out of pf when no rule uses them: a table outlives
# its alias and goes on holding the addresses (os-blocklists, 2026-10-29). One whose alias is still in
# Firewall: Aliases - switched off, as something names it - is OPNsense's to keep.
/sbin/pfctl -v -s Tables 2> /dev/null | awk '$2 ~ /^uid_/ && $1 !~ /r/ { print $2 }' |
while read -r table; do
    grep -q "<name>${table}</name>" /conf/config.xml 2> /dev/null && continue
    /sbin/pfctl -t "${table}" -T kill > /dev/null 2>&1 || true
done

echo "User Identity removed; its settings stay in config.xml"
