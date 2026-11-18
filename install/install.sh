#!/bin/sh
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
# Install the User Identity plugin from a copy of this repository on the firewall:
#   sh install/install.sh
# Safe to run again after an update: settings in config.xml are kept. Off by default: once this has
# run, nothing is mapped until domain controllers and groups are named in Settings and applied.

set -e
HERE=$(cd "$(dirname "$0")/.." && pwd)

# Syntax first, on the tree about to be copied, so nothing with an error is ever copied - as
# os-blocklists found (2026-10-29). The Python is compiled into a directory of its own, removed after,
# not beside the tree's files.
for f in $(find "${HERE}/src" -name '*.php' -o -name '*.inc'); do
    php -l "$f" > /dev/null
done
PYC=$(mktemp -d -t os-useridentity-check)
trap 'rm -rf "${PYC}"' EXIT
for f in $(find "${HERE}/src" -name '*.py'); do
    PYTHONPYCACHEPREFIX="${PYC}" python3 -m py_compile "$f"
done
rm -rf "${PYC}"
trap - EXIT

# plugin files: src/ maps to /usr/local
# The public keys a release must be signed with for self-update.py to install it (its SIGNED
# RELEASES) are the set this tree holds and no other: the installed ones go first, so a key the tree
# dropped goes with this install.
rm -rf /usr/local/opnsense/scripts/useridentity/release-keys
cp -R "${HERE}/src/" /usr/local/
chmod 644 /usr/local/opnsense/scripts/useridentity/release-keys/*.pub
chmod 755 /usr/local/opnsense/scripts/useridentity/*.py /usr/local/opnsense/scripts/useridentity/aliases.php \
    /usr/local/opnsense/scripts/useridentity/place-menu.sh /usr/local/etc/rc.d/useridentity
chmod 644 /usr/local/opnsense/scripts/useridentity/i18n/ui/source.json /usr/local/opnsense/scripts/useridentity/menu/*.xml
chmod 644 /usr/local/etc/inc/plugins.inc.d/useridentity.inc /usr/local/etc/cron.d/useridentity \
    /usr/local/opnsense/service/conf/actions.d/actions_useridentity.conf

# The page's place in the menu: the XGS section where os-xgs-npu is installed, Firewall where it is
# not. place-menu.sh writes the menu file and says which it chose: "xgs" or "own".
WHERE=$(/usr/local/opnsense/scripts/useridentity/place-menu.sh)

install -d -o root -g wheel -m 0750 /var/db/os-useridentity
install -d -m 0755 /usr/local/share/os-useridentity

# reload configd actions, menu and ACL caches
service configd restart > /dev/null
# PHP keeps them in its own temporary directory on 26.7 (/var/lib/php/tmp); /tmp is where they were
rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json \
    /tmp/opnsense_menu_cache.xml /tmp/opnsense_acl_cache.json

# What the page's Apply does: off, the collector stopped and every mapping forgotten while the aliases
# are there; the aliases made to say what the settings say (and XGS: Settings' cut list where
# os-xgs-npu is installed); syslog-ng's source written or taken away - syslog-ng restarted only when it
# changed; the filter reloaded so the redirect and the tables are pf's; cron, so the minute's run is in
# it; the tables of aliases gone taken out of pf; then, on, the collector started.
ON=
if python3 /usr/local/opnsense/scripts/useridentity/settings.py enabled 2> /dev/null | grep -q '"enabled": true'; then
    ON=yes
fi
if [ -z "${ON}" ]; then
    configctl useridentity stop > /dev/null 2>&1 || true
    configctl useridentity flush > /dev/null 2>&1 || true
fi
configctl useridentity apply > /dev/null 2>&1 || true
if configctl useridentity source 2> /dev/null | grep -q '"changed": true'; then
    configctl syslog restart > /dev/null 2>&1 || true
fi
configctl filter reload skip_alias > /dev/null 2>&1 || true
configctl cron restart > /dev/null 2>&1 || true
configctl useridentity gone > /dev/null 2>&1 || true
if [ -n "${ON}" ]; then
    configctl useridentity restart > /dev/null 2>&1 || true
    STATE="mapping"
else
    STATE="off until domain controllers and groups are named in Settings"
fi

# What this install is, for the self-update: the commit, from a git checkout, or from the
# .source-commit stamp that an xgs-image-builder image or the self-update leaves in the tree.
# Without either it is recorded as unknown, and the self-update takes the latest release once.
REV=; RDATE=; RSRC=unknown
if [ -e "${HERE}/.git" ] && REV=$(git -C "${HERE}" rev-parse HEAD 2>/dev/null); then
    RDATE=$(git -C "${HERE}" log -1 --format=%cI 2>/dev/null); RSRC=git
elif [ -s "${HERE}/.source-commit" ]; then
    read -r REV RDATE _ < "${HERE}/.source-commit"; RSRC=stamp
else
    REV=
fi
case ${REV} in *[!0-9a-f]*) REV=; RDATE=; RSRC=unknown ;; esac
printf '{"commit": "%s", "date": "%s", "source": "%s", "installed_at": %s}\n' \
    "${REV}" "${RDATE}" "${RSRC}" "$(date +%s)" > /usr/local/share/os-useridentity/installed.json

if [ "${WHERE}" = xgs ]; then
    echo "User Identity installed: XGS > User Identity (${STATE})"
else
    echo "User Identity installed: Firewall > User Identity (${STATE})"
fi
