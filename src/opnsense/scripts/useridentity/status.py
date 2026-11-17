#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""What the page shows, as one JSON object: whether the collector runs, the live map's counts, the
group and user tables with the addresses pf holds in each and whether XGS: Settings cuts on them, the
directory's state, each domain controller's lines and refusals, and syslog-ng's source.

    status.py        the cards, Groups' and Users' counts, Sources
    status.py map    the Users tab: the live map, one row an address

Read only; it prints JSON and exits 0 whatever it could not read. The map names users: it is the
owner's page (the system log does not name them unless asked, settled point 14).
"""

import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import engine                                                            # noqa: E402
import settings                                                          # noqa: E402

PIDFILE = '/var/run/useridentity.pid'
PROJECT = '/usr/local/opnsense/scripts/xgs'
PFCTL = '/sbin/pfctl'
GROUPS = engine.STATE + '/groups.json'
SOURCES = engine.STATE + '/sources.json'
SOURCE = engine.STATE + '/syslog.json'
MINUTE = engine.STATE + '/minute.json'


def running(pidfile=None):
    """The collector's pid when the pidfile names a live process running it; None otherwise."""
    try:
        with open(pidfile or PIDFILE) as handle:
            pid = int(handle.read().split()[0])
        if pid <= 1:
            return None
        os.kill(pid, 0)
        args = subprocess.run(['ps', '-ww', '-o', 'args=', '-p', str(pid)], capture_output=True, text=True,
                              timeout=10).stdout
    except (OSError, ValueError, IndexError, subprocess.SubprocessError):
        return None
    return pid if 'collector.py run' in args else None


def entries(pfctl=None):
    """{table: addresses} of the uid_ tables pf holds, from pfctl -vvs Tables."""
    try:
        text = subprocess.run([pfctl or PFCTL, '-vvs', 'Tables'], capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    out, name = {}, None
    for line in text.splitlines():
        head = re.match(r'^[-a-zA-Z]{7}\s+(\S+)', line)
        if head:
            name = head.group(1) if head.group(1).startswith(settings.PREFIX) else None
            if name:
                out[name] = 0
            continue
        found = re.match(r'^\s+Addresses:\s+(\d+)', line)
        if found and name:
            out[name] = int(found.group(1))
    return out


def users_in(state, groups, conf):
    """{user: [group rows' names it is in]} as the directory last said."""
    out = {}
    names = {row['name'].lower(): row['name'] for row in conf['groups']}
    for entry in state['map'].values():
        found = (groups.get(entry['user']) or {}).get('in', [])
        out[entry['user']] = [names.get(key, key) for key in found]
    return out


def mapped(state, groups, conf, now):
    """The Users tab's rows: one an address."""
    member = users_in(state, groups, conf)
    rows = []
    for where, entry in sorted(state['map'].items()):
        others = sorted(user for user, last in entry.get('others', {}).items()
                        if user != entry['user'] and last > now - conf['lifetime'])
        rows.append({'address': where, 'user': entry['user'], 'domain': entry.get('domain', ''),
                     'groups': member.get(entry['user'], []), 'known': entry['user'] in groups,
                     'source': entry.get('source', ''), 'first': entry.get('first'), 'last': entry.get('last'),
                     'expires': entry.get('expires'), 'mac': entry.get('mac', ''), 'shared': others})
    return rows


def sources(conf, found):
    """Each sender's counts for Sources: the domain controllers named first, then any other sender."""
    out = []
    senders = found.get('senders') or {}
    for address in conf['dcs'] + sorted(set(senders) - set(conf['dcs'])):
        seen = senders.get(address) or {}
        refused = dict(seen.get('refused') or {})
        stale = refused.pop('stale', 0)
        out.append({'address': address, 'named': address in conf['dcs'], 'hostname': seen.get('hostname', ''),
                    'last_line': seen.get('last_line'), 'last_event': seen.get('last_event'), 'late': seen.get('late'),
                    'lines': seen.get('lines', 0), 'accepted': seen.get('accepted', 0), 'joined': seen.get('joined', 0),
                    'renewed': seen.get('renewed', 0), 'changed': seen.get('changed', 0), 'stale': stale,
                    'refused': sum(refused.values()), 'reasons': refused,
                    'other': sum((seen.get('other') or {}).values())})
    return out


def report(now=None, pidfile=None, pfctl=None, project=None):
    now = now if now is not None else time.time()
    conf = settings.read()
    aliases = settings.aliases()
    state = engine.load()
    groups = engine.read_json(GROUPS, {})
    found = engine.read_json(SOURCES, {})
    held = entries(pfctl)
    cut = set(conf['cut_lists'])
    tables = []
    for row in conf['groups'] + conf['users']:
        alias = aliases.get(row['alias']) or {}
        present = bool(alias.get('ours') and alias.get('enabled') and alias.get('type') == 'external')
        tables.append({'kind': row['kind'], 'name': row['name'], 'alias': row['alias'], 'enabled': row['enabled'],
                       'present': present, 'owner': bool(alias) and not alias.get('ours'),
                       'entries': (held or {}).get(row['alias']) if present and held is not None else None,
                       'cut': alias.get('uuid', '') in cut if present else False})
    rows = mapped(state, groups.get('users') or {}, conf, now)
    addresses = settings.interface_addresses()
    pid = running(pidfile)
    told = sources(conf, found)
    events = [s['last_event'] for s in told if s['last_event']]
    return {
        'enabled': conf['enabled'], 'running': pid is not None, 'pid': pid,
        'project': os.path.isdir(project or PROJECT), 'xgs': conf['xgs'],
        'counts': {'users': len({r['user'] for r in rows}), 'addresses': len(rows),
                   'shared': sum(1 for r in rows if r['shared'])},
        'tables': tables, 'cut': sum(1 for t in tables if t['cut']),
        'ldap': dict(groups.get('server') or {}, chosen=conf['ldap_server'], nested=conf['nested'],
                     known=len(groups.get('users') or {})),
        'source': engine.read_json(SOURCE, {}), 'minute': engine.read_json(MINUTE, {}),
        'sources': told, 'since': found.get('since'), 'last_event': max(events) if events else None,
        'dcs': conf['dcs'], 'bad_dcs': conf['bad_dcs'], 'port': conf['port'],
        'listen': [{'interface': key, 'address': addresses.get(key, '')} for key in conf['interfaces']],
        'lifetime': conf['lifetime'], 'stale': conf['stale'], 'mac_check': conf['mac_check'],
    }


def main(argv):
    try:
        if argv[1:2] == ['map']:
            conf = settings.read()
            rows = mapped(engine.load(), engine.read_json(GROUPS, {}).get('users') or {}, conf, time.time())
            print(json.dumps({'rows': rows}))
            return 0
        print(json.dumps(report()))
    except Exception as error:                                           # noqa: BLE001
        print(json.dumps({'error': 'status could not be read: %r' % error}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
