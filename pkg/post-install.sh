#!/bin/sh
# Copyright (C) 2026 Abdelmonem Awad <eg2@live.com>. BSD 2-Clause License.
#
# Run by pkg(8) after the files of os-useridentity are in place, on install and on upgrade alike.
# tools/make-package.sh inlines it into the package manifest. The first blocks and the registration
# are what every OPNsense plugin runs; the chmod lines and syntax checks of install/install.sh are
# not repeated, for the reasons os-netreport's post-install gives. No package is needed beside it:
# py-ldap3, which asks the directory, is part of OPNsense's own core.

if [ -f /usr/local/etc/rc.d/configd ]; then
	/usr/local/etc/rc.d/configd restart
fi

install -d -o root -g wheel -m 0750 /var/db/os-useridentity

if [ -f /usr/local/opnsense/mvc/script/run_migrations.php ]; then
	/usr/local/opnsense/mvc/script/run_migrations.php OPNsense/UserIdentity
fi

if [ -x /usr/local/opnsense/scripts/firmware/register.php ]; then
	/usr/local/opnsense/scripts/firmware/register.php install os-useridentity > /dev/null 2>&1 || true
fi

if [ -f /usr/local/etc/rc.configure_plugins ]; then
	echo "Reloading plugin configuration"
	/usr/local/etc/rc.configure_plugins POST_INSTALL
fi

# The page's place in the menu: the XGS section where os-xgs-npu is installed, Firewall where it is
# not. The menu file is not one of the package's files; place-menu.sh writes it and says which it
# chose.
WHERE=
if [ -x /usr/local/opnsense/scripts/useridentity/place-menu.sh ]; then
	WHERE=$(/usr/local/opnsense/scripts/useridentity/place-menu.sh) || WHERE=
fi

# The page's Apply, as install/install.sh does it: off by default, so on a first install only the
# filter and cron take the plugin in; on an upgrade with the plugin on, its source, its aliases and
# the collector - started again, so it runs the new code.
STATE=
if [ -f /usr/local/sbin/configctl ]; then
	ON=
	if /usr/local/bin/python3 /usr/local/opnsense/scripts/useridentity/settings.py enabled 2> /dev/null | grep -q '"enabled": true'; then
		ON=yes
	fi
	if [ -z "${ON}" ]; then
		/usr/local/sbin/configctl useridentity stop > /dev/null 2>&1 || true
		/usr/local/sbin/configctl useridentity flush > /dev/null 2>&1 || true
	fi
	/usr/local/sbin/configctl useridentity apply > /dev/null 2>&1 || true
	if /usr/local/sbin/configctl useridentity source 2> /dev/null | grep -q '"changed": true'; then
		/usr/local/sbin/configctl syslog restart > /dev/null 2>&1 || true
	fi
	/usr/local/sbin/configctl filter reload skip_alias > /dev/null 2>&1 || true
	/usr/local/sbin/configctl cron restart > /dev/null 2>&1 || true
	/usr/local/sbin/configctl useridentity gone > /dev/null 2>&1 || true
	if [ -n "${ON}" ]; then
		/usr/local/sbin/configctl useridentity restart > /dev/null 2>&1 || true
		STATE=" (mapping)"
	else
		STATE=" (off until domain controllers and groups are named in Settings)"
	fi
fi

case "${WHERE}" in
xgs)	echo "User Identity installed: the page is at XGS > User Identity${STATE}" ;;
own)	echo "User Identity installed: the page is at Firewall > User Identity${STATE}" ;;
*)	echo "User Identity installed${STATE}; its menu file was not written: run /usr/local/opnsense/scripts/useridentity/place-menu.sh" ;;
esac
