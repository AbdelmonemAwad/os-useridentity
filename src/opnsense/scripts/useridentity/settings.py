#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""User Identity's settings, read straight out of config.xml by element name: the plugin's own
(models/OPNsense/UserIdentity/UserIdentity.xml - the names here are not free), the System: Access:
Servers entry it names for the groups - with the realms its users are written with - and those that
are vouchers, the captive portal's zones, and the aliases and the XGS cut list it shares with OPNsense
and os-xgs-npu.

Nothing here writes. A config.xml that cannot be read gives the defaults with read False, and every
caller does nothing it would regret on them: the plugin is off by default.

    settings.py enabled    {"enabled": ..., "read": ...} - for the installer and the package's scripts
"""

import ipaddress
import json
import re
import sys
import xml.etree.ElementTree as ET

CONFIG = '/conf/config.xml'

LIFETIME = 480          # minutes a mapping lives without an event (settled point 7, until the lab's A5)
STALE = 5               # minutes: an event older than this when it arrives neither maps nor renews
PORT = 514              # the port the domain controllers send to, on the chosen interfaces
LOCAL_PORT = 5141       # syslog-ng's source on 127.0.0.1 (phase 0's A0: 5140 is os-xgs-npu's, 5141 free)
HISTORY_DAYS = 0
ALERT_SILENT = 0

PREFIX = 'uid_'
DESCRIPTION = 'User Identity: '


def _text(node, tag, default=''):
    if node is None:
        return default
    found = node.findtext(tag)
    return default if found is None else found.strip()


def _int(text, default, low, high):
    try:
        value = int(text)
    except (TypeError, ValueError):
        return default
    return value if low <= value <= high else default


def items(text):
    """The entries of a list field: separated by commas, semicolons or new lines, each stripped, empty
    ones dropped - a user's name may hold a space."""
    return [item.strip() for item in re.split(r'[,;\r\n]+', text or '') if item.strip()]


def ipv4(text):
    """The address when text is one IPv4 address, else None."""
    try:
        found = ipaddress.ip_address(text.strip())
    except ValueError:
        return None
    return str(found) if found.version == 4 else None


def address_key(text):
    """An address as one string whatever way it is written - 2001:DB8::40 and 2001:db8:0::40 alike - so a
    RADIUS client named in Settings and the directory FreeRADIUS names after it compare; anything that
    is no address, as it is, stripped."""
    text = str(text or '').strip()
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text


def realms(entry):
    """The names a user of the directory is written with besides its bare name, lower case: the domain
    its base DN names (DC=example,DC=test: example.test) and that domain's first label, 15 characters at
    most - the name Windows gives a domain for DOMAIN\\name unless it was given another. Empty when the
    entry is none, or its base DN names no domain."""
    labels = []
    for part in str((entry or {}).get('ldap_basedn') or '').split(','):
        attribute, sep, value = part.partition('=')
        if sep and attribute.strip().lower() == 'dc' and value.strip():
            labels.append(value.strip().lower())
    return {'.'.join(labels), labels[0][:15]} if labels else set()


def networks(text):
    """[network] of a list of addresses and networks, and [entry] of those that are neither."""
    good, bad = [], []
    for item in items(text):
        try:
            good.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            bad.append(item)
    return good, bad


def rows(root, path, kind):
    """The rows of one of the plugin's lists (groups, users), each with its uuid, in config order."""
    out = []
    for node in root.findall(path):
        out.append({
            'uuid': node.get('uuid') or '',
            'kind': kind,
            'enabled': _text(node, 'enabled', '1') == '1',
            'name': _text(node, 'name'),
            'alias': _text(node, 'alias'),
            'description': _text(node, 'description'),
        })
    return out


def server(root, name):
    """The System: Access: Servers entry by its name when it is an LDAP one, as config.xml holds it -
    the bind password with it, which nothing here ever prints."""
    if not name:
        return None
    for node in root.findall('system/authserver'):
        if _text(node, 'name') == name and _text(node, 'type') == 'ldap':
            return {child.tag: (child.text or '').strip() for child in node}
    return None


def zones(root):
    """{zone id: its description} of the captive portal's zones switched on - os-xgs-npu's cp_users.py
    reads them the same way. A session of a zone not here, switched off or gone, maps nothing."""
    out = {}
    for node in root.findall('OPNsense/captiveportal/zones/zone'):
        zoneid = _text(node, 'zoneid')
        if _text(node, 'enabled', '0') == '1' and zoneid.isdigit():
            out[str(int(zoneid))] = _text(node, 'description')
    return out


def read(path=None):
    out = {
        'read': False, 'enabled': False, 'ldap_server': '', 'server': None, 'dcs': [], 'bad_dcs': [],
        'interfaces': ['lan'], 'port': PORT, 'local_port': LOCAL_PORT, 'lifetime': LIFETIME * 60,
        'mac_check': True, 'stale': STALE * 60, 'nested': True, 'never_map': [], 'bad_never_map': [],
        'ignore': set(), 'log_names': False, 'history_days': HISTORY_DAYS, 'alert_silent': ALERT_SILENT * 60,
        'groups': [], 'users': [], 'cut_lists': [], 'xgs': False,
        'radius': False, 'radius_clients': [], 'bad_radius_clients': [], 'portal': False, 'zones': {},
        'vouchers': set(), 'realms': set(),
    }
    try:
        root = ET.parse(path or CONFIG).getroot()
    except (OSError, ET.ParseError):
        return out
    out['read'] = True
    general = root.find('OPNsense/UserIdentity/general')
    if general is not None:
        out['enabled'] = _text(general, 'enabled', '0') == '1'
        out['ldap_server'] = _text(general, 'ldap_server')
        for item in items(_text(general, 'domain_controllers')):
            address = ipv4(item)
            if address and address not in out['dcs']:
                out['dcs'].append(address)
            elif not address:
                out['bad_dcs'].append(item)
        chosen = items(_text(general, 'interfaces', 'lan'))
        out['interfaces'] = chosen
        out['port'] = _int(_text(general, 'port'), PORT, 1, 65535)
        out['local_port'] = _int(_text(general, 'local_port'), LOCAL_PORT, 1024, 65535)
        out['lifetime'] = _int(_text(general, 'lifetime'), LIFETIME, 5, 10080) * 60
        out['mac_check'] = _text(general, 'mac_check', '1') == '1'
        out['stale'] = _int(_text(general, 'stale'), STALE, 1, 1440) * 60
        out['nested'] = _text(general, 'nested', '1') == '1'
        out['never_map'], out['bad_never_map'] = networks(_text(general, 'never_map'))
        out['ignore'] = {item.lower() for item in items(_text(general, 'ignore_users'))}
        out['log_names'] = _text(general, 'log_names', '0') == '1'
        out['history_days'] = _int(_text(general, 'history_days'), HISTORY_DAYS, 0, 365)
        out['alert_silent'] = _int(_text(general, 'alert_silent'), ALERT_SILENT, 0, 10080) * 60
        out['radius'] = _text(general, 'radius', '0') == '1'
        # the RADIUS clients whose accounting may map, each as FreeRADIUS names its directory: an address
        for item in items(_text(general, 'radius_clients')):
            try:
                key = str(ipaddress.ip_address(item))
            except ValueError:
                out['bad_radius_clients'].append(item)
                continue
            if key not in out['radius_clients']:
                out['radius_clients'].append(key)
        out['portal'] = _text(general, 'portal', '0') == '1'
    out['server'] = server(root, out['ldap_server'])
    out['realms'] = realms(out['server'])
    out['zones'] = zones(root)
    # a voucher is a code anyone may hold, not a user: a portal session it opened maps nothing
    out['vouchers'] = {_text(node, 'name') for node in root.findall('system/authserver')
                       if _text(node, 'type') == 'voucher' and _text(node, 'name')}
    out['groups'] = rows(root, 'OPNsense/UserIdentity/groups/group', 'group')
    out['users'] = rows(root, 'OPNsense/UserIdentity/users/user', 'user')
    xgs = root.find('OPNsense/XGS/general')
    out['xgs'] = xgs is not None
    out['cut_lists'] = [u for u in items(_text(xgs, 'cut_lists')) if u]
    return out


def aliases(path=None):
    """{name: {'uuid', 'enabled', 'type', 'ours', 'description'}} of every alias in Firewall: Aliases. The
    plugin's own are named uid_ and described 'User Identity: ' (aliases.php writes them)."""
    out = {}
    try:
        root = ET.parse(path or CONFIG).getroot()
    except (OSError, ET.ParseError):
        return out
    for alias in root.findall('OPNsense/Firewall/Alias/aliases/alias'):
        name = _text(alias, 'name')
        text = _text(alias, 'description')
        out[name] = {
            'uuid': alias.get('uuid') or '',
            'enabled': _text(alias, 'enabled', '1') == '1',
            'type': _text(alias, 'type'),
            'description': text,
            'ours': name.startswith(PREFIX) and text.startswith(DESCRIPTION),
        }
    return out


def interface_addresses(path=None):
    """{key: IPv4 address} of the interfaces config.xml gives a static address - for the NXLog snippet
    the page shows; one that takes its address from upstream is not there."""
    out = {}
    try:
        root = ET.parse(path or CONFIG).getroot()
    except (OSError, ET.ParseError):
        return out
    found = root.find('interfaces')
    for node in (list(found) if found is not None else []):
        address = ipv4(_text(node, 'ipaddr'))
        if address:
            out[node.tag] = address
    return out


def main(argv):
    if argv[1:2] == ['enabled']:
        conf = read()
        print(json.dumps({'enabled': conf['enabled'], 'read': conf['read']}))
        return 0
    print('usage: settings.py enabled', file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
