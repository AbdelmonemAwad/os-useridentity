#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""The live map (engine.py), the tables made from it (tables.py, with a stand-in pfctl), what the
firewall tells it (host.py, from FreeBSD's own ifconfig, arp and ndp output) and the settings it reads
(settings.py, from tools/fixtures/config.xml): join, renew, latest wins and the shared mark, the
lifetime's end, the MAC check, the owner's flush, the tables of groups and of users, the log's counts
without names, the history, and the lab's A6 - three logons on one client in a row - played through.

    python3 tools/test-engine.py"""
import json
import os
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src', 'opnsense', 'scripts', 'useridentity'))
import engine                                                            # noqa: E402
import events                                                            # noqa: E402
import host                                                              # noqa: E402
import settings                                                          # noqa: E402
import tables                                                            # noqa: E402

failures = 0
checks = 0
LIFE = 480 * 60
T0 = 1794940893.0


def check(name, got, want):
    global failures, checks
    checks += 1
    ok = got == want
    failures += 0 if ok else 1
    print('%s %s%s' % ('ok  ' if ok else 'FAIL', name, '' if ok else ' - got %r, want %r' % (got, want)))


def ev(user, address, when, number=4768):
    return {'id': number, 'user': user, 'domain': 'EXAMPLE', 'address': address, 'time': when, 'logon_type': '',
            'hostname': 'DC1.example.test'}


def fresh():
    return {'version': 1, 'map': {}}


# join, renew
state = fresh()
check('join: an address not in the map', engine.see(state, ev('user1', '192.0.2.20', T0), T0 + 2, LIFE, '192.0.2.10'),
      [('joined', '192.0.2.20', 'user1')])
entry = state['map']['192.0.2.20']
check('join: the entry - its user, the domain controller, its times, no MAC yet, no one else',
      (entry['user'], entry['source'], entry['first'], entry['last'], entry['expires'], entry['mac'], entry['others']),
      ('user1', '192.0.2.10', T0, T0, T0 + LIFE, '', {}))
check('renew: the same user later', engine.see(state, ev('user1', '192.0.2.20', T0 + 600, 4624), T0 + 601, LIFE,
                                               '192.0.2.10'), [('renewed', '192.0.2.20', 'user1')])
check('renew: last and expires moved on, first kept',
      (entry['first'], entry['last'], entry['expires'], entry['event']), (T0, T0 + 600, T0 + 600 + LIFE, 4624))
engine.see(state, ev('user1', '192.0.2.20', T0 + 300), T0 + 700, LIFE, '192.0.2.10')
check('renew: an older event of the same user moves nothing back', (entry['last'], entry['expires']),
      (T0 + 600, T0 + 600 + LIFE))
engine.see(state, ev('user1', '192.0.2.20', T0 + 1000), T0 + 900, LIFE, '192.0.2.10')
check('renew: an event ahead of its arrival counts from its arrival', entry['last'], T0 + 900)
check('one user, two addresses: both mapped', engine.see(state, ev('user1', '2001:db8::20', T0 + 950), T0 + 951, LIFE),
      [('joined', '2001:db8::20', 'user1')])
check('one user, two addresses: the map holds both', sorted(state['map']), ['192.0.2.20', '2001:db8::20'])

# latest wins, shared
changes = engine.see(state, ev('user2', '192.0.2.20', T0 + 1200), T0 + 1201, LIFE, '192.0.2.10')
check('latest wins: another user\'s later event maps the address to it, and marks it shared',
      changes, [('changed', '192.0.2.20', ('user1', 'user2')), ('shared', '192.0.2.20', ['user1', 'user2'])])
check('latest wins: the new user\'s times, the one before among the others',
      (entry['user'], entry['first'], entry['last'], entry['others']), ('user2', T0 + 1200, T0 + 1200, {'user1': T0 + 900}))
check('shared: within the lifetime', engine.shared(entry, T0 + 1201, LIFE), True)
check('a third user: mapped, no second shared mark',
      engine.see(state, ev('user3', '192.0.2.20', T0 + 1300), T0 + 1301, LIFE),
      [('changed', '192.0.2.20', ('user2', 'user3'))])
check('an older event of another user: noted, the map unchanged',
      (engine.see(state, ev('user1', '192.0.2.20', T0 + 1250), T0 + 1310, LIFE), entry['user'], entry['others']),
      ([('noted', '192.0.2.20', 'user1')], 'user3', {'user1': T0 + 1250, 'user2': T0 + 1200}))
lone = fresh()
engine.see(lone, ev('user1', '192.0.2.21', T0 + 100), T0 + 100, LIFE)
check('an older event of another user on an address not shared: noted and marked shared',
      engine.see(lone, ev('user2', '192.0.2.21', T0 + 50), T0 + 101, LIFE),
      [('noted', '192.0.2.21', 'user2'), ('shared', '192.0.2.21', ['user1', 'user2'])])

# the lifetime's end
state = fresh()
engine.see(state, ev('user1', '192.0.2.20', T0), T0, LIFE)
engine.see(state, ev('user2', '192.0.2.20', T0 + 60), T0 + 60, LIFE)
engine.see(state, ev('user1', '198.51.100.20', T0 + 3600), T0 + 3600, LIFE)
check('expire: nothing before its time', engine.expire(state, T0 + LIFE, LIFE), [])
check('expire: the others older than the lifetime forgotten - no longer shared',
      (state['map']['192.0.2.20']['others'], engine.shared(state['map']['192.0.2.20'], T0 + LIFE + 1, LIFE)), ({}, False))
check('expire: at its time it leaves', engine.expire(state, T0 + 60 + LIFE, LIFE),
      [('left', '192.0.2.20', ('user2', 'expired'))])
check('expire: the other stays', sorted(state['map']), ['198.51.100.20'])

# the MAC check
state = fresh()
for i, where in enumerate(('192.0.2.20', '192.0.2.21', '192.0.2.22', '2001:db8::20')):
    engine.see(state, ev('user%d' % i, where, T0), T0, LIFE)
check('MAC check: the first MAC taken, nothing leaves',
      engine.check_macs(state, {'192.0.2.20': '02:00:00:00:00:14', '2001:db8::20': '02:00:00:00:00:14'}), [])
check('MAC check: the MACs recorded', (state['map']['192.0.2.20']['mac'], state['map']['2001:db8::20']['mac']),
      ('02:00:00:00:00:14', '02:00:00:00:00:14'))
check('MAC check: the same MAC again, an address the table does not hold - nothing leaves',
      engine.check_macs(state, {'192.0.2.20': '02:00:00:00:00:14'}), [])
check('MAC check: another device on the address - the mapping goes',
      engine.check_macs(state, {'192.0.2.20': '02:00:00:00:00:15', '2001:db8::20': '02:00:00:00:00:14'}),
      [('left', '192.0.2.20', ('user0', 'mac'))])
check('MAC check: the rest kept', sorted(state['map']), ['192.0.2.21', '192.0.2.22', '2001:db8::20'])
check('flush: every mapping forgotten', (engine.flush(state), state['map']),
      ([('left', '192.0.2.21', ('user1', 'flushed')), ('left', '192.0.2.22', ('user2', 'flushed')),
        ('left', '2001:db8::20', ('user3', 'flushed'))], {}))

# the lab's A6: three logons on PC1 in a row, each a computer account's logon first
lab, name = {}, None
for line in open(os.path.join(ROOT, 'tools', 'fixtures', 'lab-events.txt'), encoding='utf-8'):
    line = line.rstrip('\n')
    if line.startswith('#= '):
        name = line[3:]
    elif line and not line.startswith('#') and name:
        lab[name] = line.split(' ', 2)
        name = None
os.environ['TZ'] = 'UTC'
time.tzset()
state, seen = fresh(), []
context = events.Context(dcs=['192.0.2.10'], stale=300, own=['192.0.2.1'])
for name in ('runas-computer-1', 'runas-user1', 'runas-computer-2', 'runas-user2', 'runas-computer-3', 'runas-user3'):
    arrival, sender, message = lab[name]
    arrived = time.mktime(time.strptime(arrival[:19], '%Y-%m-%dT%H:%M:%S'))
    kind, found = events.parse(message)
    if kind != 'event' or events.judge(found, arrived, context):
        seen.append(found)
        continue
    seen.extend(engine.see(state, found, arrived, LIFE, sender))
check('A6 played through: the computer accounts dropped, latest wins, the address marked shared once',
      seen, ['computer', ('joined', '192.0.2.20', 'user1'), 'computer', ('changed', '192.0.2.20', ('user1', 'user2')),
             ('shared', '192.0.2.20', ['user1', 'user2']), 'computer', ('changed', '192.0.2.20', ('user2', 'user3'))])
check('A6: user3 holds the address, user1 and user2 among the others',
      (state['map']['192.0.2.20']['user'], sorted(state['map']['192.0.2.20']['others'])), ('user3', ['user1', 'user2']))

# the tables made from the map
state = fresh()
engine.see(state, ev('user1', '192.0.2.20', T0), T0, LIFE)
engine.see(state, ev('user1', '2001:db8::20', T0), T0, LIFE)
engine.see(state, ev('user2', '192.0.2.21', T0), T0, LIFE)
engine.see(state, ev('user3', '192.0.2.22', T0), T0, LIFE)
conf = {
    'groups': [{'enabled': True, 'name': 'G-Staff', 'alias': 'uid_grp_G_Staff'},
               {'enabled': True, 'name': 'Sales', 'alias': 'uid_grp_Sales'},
               {'enabled': False, 'name': 'Guests', 'alias': 'uid_grp_Guests'},
               {'enabled': True, 'name': 'Later', 'alias': 'uid_grp_Later'}],
    'users': [{'enabled': True, 'name': 'User1', 'alias': 'uid_usr_user1'},
              {'enabled': True, 'name': 'nobody', 'alias': 'uid_usr_nobody'}],
}
groups = {'user1': {'in': ['g-staff']}, 'user2': {'in': ['g-staff', 'sales']}, 'user3': {'in': []}}
present = {'uid_grp_G_Staff', 'uid_grp_Sales', 'uid_grp_Guests', 'uid_usr_user1', 'uid_usr_nobody'}
want = engine.tables(state, groups, conf, present)
check('tables: a group\'s - every address of its users, both families',
      want['uid_grp_G_Staff'], {'192.0.2.20', '2001:db8::20', '192.0.2.21'})
check('tables: another group\'s', want['uid_grp_Sales'], {'192.0.2.21'})
check('tables: a user\'s, its name in any case', want['uid_usr_user1'], {'192.0.2.20', '2001:db8::20'})
check('tables: a user with no address - an empty table', want['uid_usr_nobody'], set())
check('tables: a group switched off, and one whose alias is not in config.xml - not written',
      sorted(want), ['uid_grp_G_Staff', 'uid_grp_Sales', 'uid_usr_nobody', 'uid_usr_user1'])
check('tables: a user LDAP has not answered for yet - in no group\'s table',
      engine.tables({'map': {'192.0.2.30': {'user': 'user9'}}}, groups, conf, present)['uid_grp_G_Staff'], set())

# pf, through a stand-in
class FakePf:
    def __init__(self, held):
        self.held = {k: set(v) for k, v in held.items()}
        self.calls = []
        self.fail = set()

    def __call__(self, args):
        self.calls.append(' '.join(args))
        if args[:1] == ['-t']:
            table, verb, rest = args[1], args[3], set(args[4:])
            if verb in self.fail:
                return 1, 'pfctl: Operation not permitted'
            if verb == 'show':
                return (0, ''.join('   %s\n' % a for a in sorted(self.held[table]))) if table in self.held else \
                    (1, 'pfctl: Table does not exist.')
            if verb == 'add':
                self.held.setdefault(table, set()).update(rest)
            elif verb == 'delete':
                self.held.get(table, set()).difference_update(rest)
            elif verb == 'kill':
                self.held.pop(table, None)
            return 0, ''
        if args == ['-v', '-s', 'Tables']:
            return 0, ''.join('%s\t%s\n' % (flags, name) for flags, name in self.listed)
        return 1, 'unknown'


fake = FakePf({'uid_grp_G_Staff': {'192.0.2.20', '192.0.2.99'}})
pf = tables.Pf(run=fake)
done = tables.sync(pf, want)
check('sync: what a table lacks added, what the map does not ask for taken out, a table not there filled',
      (fake.held['uid_grp_G_Staff'], fake.held['uid_grp_Sales'], fake.held['uid_usr_user1'], 'uid_usr_nobody' in fake.held),
      ({'192.0.2.20', '2001:db8::20', '192.0.2.21'}, {'192.0.2.21'}, {'192.0.2.20', '2001:db8::20'}, False))
check('sync: what changed, table by table', done, [('uid_grp_G_Staff', 2, 1), ('uid_grp_Sales', 1, 0),
                                                   ('uid_usr_user1', 2, 0)])
fake.calls.clear()
check('sync again, nothing changed: only read', (tables.sync(pf, want), [c for c in fake.calls if ' show' not in c]), ([], []))
check('sync: only the tables named', tables.sync(pf, {'uid_grp_Sales': set(), 'uid_usr_user1': set()}, only={'uid_grp_Sales'}),
      [('uid_grp_Sales', 0, 1)])
many = {'uid_grp_G_Staff': {'198.51.100.%d' % i for i in range(1, 71)}}
fake.calls.clear()
tables.sync(pf, many)
check('sync: 70 addresses added 64 at a time, the 3 before taken out',
      [len(c.split()) - 4 for c in fake.calls if '-T add' in c] + [len(c.split()) - 4 for c in fake.calls if '-T delete' in c],
      [64, 6, 3])
fake.fail = {'add'}
tables.sync(pf, {'uid_grp_Sales': {'192.0.2.50'}})
check('sync: a pfctl that fails - said in errors, never raised', pf.errors, [
    'pfctl -t uid_grp_Sales -T add: pfctl: Operation not permitted'])
aliases = {'uid_grp_G_Staff': {'ours': True, 'enabled': True, 'type': 'external'},
           'uid_grp_Off': {'ours': True, 'enabled': False, 'type': 'external'},
           'uid_grp_Host': {'ours': True, 'enabled': True, 'type': 'host'},
           'uid_mine': {'ours': False, 'enabled': True, 'type': 'external'}}
check('present: the plugin\'s own, External, switched on', tables.present(aliases), {'uid_grp_G_Staff'})
fake.listed = [('-pa----', 'uid_grp_Gone'), ('-pa-r--', 'uid_grp_Used'), ('-pa----', 'uid_grp_G_Staff'),
               ('-pa----', 'bogons'), ('-pa----', 'uid_mine')]
fake.held.update({'uid_grp_Gone': {'192.0.2.5'}, 'uid_grp_Used': {'192.0.2.6'}})
check('flush-gone: a table whose alias is gone killed; one a rule uses, one whose alias is there, pf\'s own left',
      tables.flush_gone(tables.Pf(run=fake), aliases), ['uid_grp_Gone'])

# the system log: counts, names only when asked
changes = [('joined', '192.0.2.20', 'user1'), ('renewed', '192.0.2.20', 'user1'),
           ('changed', '192.0.2.21', ('user1', 'user2')), ('shared', '192.0.2.21', ['user1', 'user2']),
           ('left', '192.0.2.22', ('user3', 'expired')), ('noted', '192.0.2.21', 'user9')]
line = engine.summary(changes)
check('the log: counts, no name and no address', line, 'addresses: 1 mapped, 1 mapped to another user, 1 now shared, 1 left')
check('the log, Log user names on: each change with its names',
      engine.summary(changes, names=True), '192.0.2.20 mapped to user1; 192.0.2.21 mapped to user2, was user1; '
      '192.0.2.21 shared by user1, user2; 192.0.2.22 of user3 left (expired)')
check('the log: renewals alone say nothing', engine.summary([('renewed', '192.0.2.20', 'user1')]), '')

with tempfile.TemporaryDirectory() as tmp:
    folder = os.path.join(tmp, 'history')
    check('history, 0 days (the default): nothing written', (engine.record(changes, 0, T0, folder), os.path.exists(folder)),
          (0, False))
    check('history, 2 days: each mapping made, changed or ended', engine.record(changes, 2, T0, folder), 3)
    lines = [json.loads(x) for x in open(os.path.join(folder, '2026-11-17.jsonl'), encoding='utf-8')]
    check('history: what a line holds', lines[1], {'at': int(T0), 'change': 'changed', 'address': '192.0.2.21',
                                                   'user': 'user2', 'before': 'user1'})
    check('history: its file 0640', oct(os.stat(os.path.join(folder, '2026-11-17.jsonl')).st_mode & 0o777), '0o640')
    for day in ('2026-11-14', '2026-11-15', '2026-11-16'):
        open(os.path.join(folder, day + '.jsonl'), 'w').close()
    check('history pruned to 2 days', (engine.prune(2, T0, folder), sorted(os.listdir(folder))),
          (1, ['2026-11-15.jsonl', '2026-11-16.jsonl', '2026-11-17.jsonl']))
    check('history at 0 days: every file taken away', (engine.prune(0, T0, folder), os.listdir(folder)), (3, []))

    # the map's file and its lock
    path = os.path.join(tmp, 'map.json')
    state = fresh()
    engine.see(state, ev('user1', '192.0.2.20', T0), T0, LIFE)
    engine.save(state, path)
    check('the map saved and read again', engine.load(path)['map'], state['map'])
    check('the map: 0640', oct(os.stat(path).st_mode & 0o777), '0o640')
    with open(path, 'w') as handle:
        handle.write('{"map": {"192.0.2.9": {"user": ""}, "192.0.2.8": "x", "192.0.2.7": {"user": "user7"}}}')
    check('a map with entries of no user: those dropped', sorted(engine.load(path)['map']), ['192.0.2.7'])
    with open(path, 'w') as handle:
        handle.write('not json')
    check('a map that cannot be read: empty', engine.load(path), {'version': 1, 'map': {}})
    lock = os.path.join(tmp, 'lock')
    with engine.locked(lock) as first:
        with engine.locked(lock, wait=0.2) as second:
            pass
    check('the lock: taken, and a second holder waits, then goes on without it', (first, second), (True, False))
    with engine.locked(lock, wait=0.2) as again:
        pass
    check('the lock: free again once let go', again, True)

# what the firewall tells it
IFCONFIG = '''igb0: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
\tether 02:00:00:00:00:01
\tinet 192.0.2.1 netmask 0xffffff00 broadcast 192.0.2.255
\tinet6 fe80::db8:1%igb0 prefixlen 64 scopeid 0x1
\tinet6 2001:db8::1 prefixlen 64
\tstatus: active
igb1: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
\tinet 198.51.100.2/30 broadcast 198.51.100.3
\tinet 203.0.113.9 netmask 255.255.255.255
lo0: flags=1008049<UP,LOOPBACK,RUNNING,MULTICAST,LOWER_UP> metric 0 mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
\tinet6 ::1 prefixlen 128
\tinet 192.0.2.300 netmask 0xffffff00
'''
mine, broadcasts = host.own(IFCONFIG)
check('ifconfig -a: the firewall\'s addresses, both families, in the forms FreeBSD writes them',
      sorted(mine), sorted(['192.0.2.1', 'fe80::db8:1', '2001:db8::1', '198.51.100.2', '203.0.113.9', '127.0.0.1', '::1']))
check('ifconfig -a: the broadcasts of its networks', sorted(broadcasts),
      ['127.255.255.255', '192.0.2.255', '198.51.100.3'])
ARP = '''? (192.0.2.1) at 02:00:00:00:00:01 on igb0 permanent [ethernet]
? (192.0.2.20) at 02:00:00:00:00:14 on igb0 expires in 1185 seconds [ethernet]
? (192.0.2.30) at (incomplete) on igb0 expired [ethernet]
pc1.example.test (192.0.2.21) at 2:0:0:0:0:15 on igb0 expires in 30 seconds [ethernet]
'''
check('arp -an: each address with its MAC in one form, one with none left out', host.arp(ARP),
      {'192.0.2.1': '02:00:00:00:00:01', '192.0.2.20': '02:00:00:00:00:14', '192.0.2.21': '02:00:00:00:00:15'})
NDP = '''Neighbor                             Linklayer Address  Netif Expire    1s 5s
2001:db8::20                         02:00:00:00:00:14     igb0 23h59m58s S R
fe80::db8:1%igb0                     02:00:00:00:00:01     igb0 permanent R
2001:db8::30                         (incomplete)          igb0 expired   N
'''
check('ndp -an: each address with its MAC, its zone dropped, the header and one with none left out', host.ndp(NDP),
      {'2001:db8::20': '02:00:00:00:00:14', 'fe80::db8:1': '02:00:00:00:00:01'})

# the settings, read out of config.xml by element name
CONFIG = os.path.join(ROOT, 'tools', 'fixtures', 'config.xml')
conf = settings.read(CONFIG)
check('settings: on, the LDAP entry named, the domain controllers - IPv4 only, the rest said',
      (conf['read'], conf['enabled'], conf['ldap_server'], conf['dcs'], conf['bad_dcs']),
      (True, True, 'Example directory', ['192.0.2.10', '192.0.2.11'], ['dc3.example.test', '2001:db8::10']))
check('settings: interfaces, ports, minutes made seconds, the switches',
      (conf['interfaces'], conf['port'], conf['local_port'], conf['lifetime'], conf['stale'], conf['alert_silent'],
       conf['mac_check'], conf['nested'], conf['log_names'], conf['history_days']),
      (['lan', 'opt1'], 514, 5141, 480 * 60, 300, 1800, True, True, False, 0))
check('settings: Never map - each network, the entry that is none said; Ignore users in lower case',
      ([str(n) for n in conf['never_map']], conf['bad_never_map'], sorted(conf['ignore'])),
      (['198.51.100.50/32', '2001:db8:1::/48'], ['not-a-network'], ['svc-backup', 'svc-scan']))
check('settings: the group rows and the user rows, each with its uuid',
      ([(r['uuid'][-1], r['enabled'], r['name'], r['alias']) for r in conf['groups']],
       [(r['name'], r['alias']) for r in conf['users']]),
      ([('1', True, 'G-Staff', 'uid_grp_G_Staff'), ('2', False, 'CN=Guests,OU=Groups,DC=example,DC=test', 'uid_grp_Guests')],
       [('user1', 'uid_usr_user1')]))
check('settings: the LDAP entry as config.xml holds it',
      (conf['server']['host'], conf['server']['ldap_urltype'], conf['server']['ldap_attr_user']),
      ('dc1.example.test', 'StartTLS', 'sAMAccountName'))
check("settings: os-xgs-npu's cut list", (conf['xgs'], conf['cut_lists']),
      (True, ['33333333-0000-4000-8000-000000000003', '33333333-0000-4000-8000-000000000001']))
found = settings.aliases(CONFIG)
check("settings: the aliases, the plugin's told by their name and description",
      sorted((name, a['ours'], a['type']) for name, a in found.items()),
      [('office', False, 'host'), ('uid_grp_G_Staff', True, 'external'), ('uid_usr_user1', True, 'external')])
check("settings: the interfaces' static IPv4 addresses", settings.interface_addresses(CONFIG),
      {'lan': '192.0.2.1', 'opt1': '198.51.100.1'})
with tempfile.TemporaryDirectory() as tmp:
    bare = os.path.join(tmp, 'config.xml')
    with open(bare, 'w', encoding='utf-8') as handle:
        handle.write('<opnsense><system/></opnsense>')
    conf = settings.read(bare)
    check("settings: a config.xml without the plugin's - off, the defaults", (conf['read'], conf['enabled'],
          conf['interfaces'], conf['lifetime'], conf['stale'], conf['server'], conf['xgs']),
          (True, False, ['lan'], 480 * 60, 300, None, False))
    check('settings: no config.xml - not read, off', (settings.read(os.path.join(tmp, 'none'))['read'],
                                                      settings.read(os.path.join(tmp, 'none'))['enabled']), (False, False))
    with open(bare, 'w', encoding='utf-8') as handle:
        handle.write('<opnsense><OPNsense><UserIdentity><general><enabled>1</enabled><lifetime>2</lifetime>'
                     '<port>70000</port><stale>x</stale><interfaces/></general></UserIdentity></OPNsense></opnsense>')
    conf = settings.read(bare)
    check('settings: a value out of its range - the default; no interface chosen - none',
          (conf['lifetime'], conf['port'], conf['stale'], conf['interfaces']), (480 * 60, 514, 300, []))

print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
