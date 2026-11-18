#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""The service, in a temporary directory with stand-ins for what only a firewall has - sockstat,
syslog-ng's syntax check, pfctl, ifconfig, arp and the directory: the syslog-ng source written only
with a port it may take and that is free, and only when syslog-ng takes its configuration with it; the
collector reading the lab's lines from a datagram socket as syslog-ng hands them over, counting each
domain controller's lines and refusals, mapping, asking the directory in its own thread and writing
the tables; the minute's run - the lifetime's end, the MAC check, the tables made again, the flush;
the alerts - a domain controller silent, the directory failing, an address newly shared - kept 24
hours and 100 at most; and what status.py gives the page.

    python3 tools/test-service.py"""
import json
import os
import select
import shutil
import socket
import stat
import sys
import tempfile
import time
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src', 'opnsense', 'scripts', 'useridentity'))
import collector                                                         # noqa: E402
import engine                                                            # noqa: E402
import expire                                                            # noqa: E402
import outbox                                                            # noqa: E402
import settings                                                          # noqa: E402
import status                                                            # noqa: E402
import syslogng                                                          # noqa: E402

failures = 0
checks = 0
STAFF = 'CN=G-Staff,CN=Users,DC=example,DC=test'


def check(name, got, want):
    global failures, checks
    checks += 1
    ok = got == want
    failures += 0 if ok else 1
    print('%s %s%s' % ('ok  ' if ok else 'FAIL', name, '' if ok else ' - got %r, want %r' % (got, want)))


def lab():
    out, name = {}, None
    for line in open(os.path.join(ROOT, 'tools', 'fixtures', 'lab-events.txt'), encoding='utf-8'):
        line = line.rstrip('\n')
        if line.startswith('#= '):
            name = line[3:]
        elif line and not line.startswith('#') and name:
            arrival, sender, message = line.split(' ', 2)
            out[name] = (time.mktime(time.strptime(arrival[:19], '%Y-%m-%dT%H:%M:%S')), sender, message)
            name = None
    return out


class FakePf:
    def __init__(self):
        self.held, self.calls, self.errors = {}, [], []

    def __call__(self, args):
        self.calls.append(' '.join(args))
        table, verb, rest = args[1], args[3], set(args[4:])
        if verb == 'show':
            return (0, ''.join('   %s\n' % a for a in sorted(self.held[table]))) if table in self.held else (1, 'no table')
        if verb == 'add':
            self.held.setdefault(table, set()).update(rest)
        elif verb == 'delete':
            self.held.get(table, set()).difference_update(rest)
        return 0, ''


def directory(fail=False):
    """A stand-in of ldap3: user1 in G-Staff, user2 in nothing; failing to connect when fail is set."""
    module = types.SimpleNamespace(NONE='NO_INFO', SIMPLE='SIMPLE', ANONYMOUS='ANONYMOUS', BASE='BASE',
                                   LEVEL='LEVEL', SUBTREE='SUBTREE', asked=[], fail=fail)
    users = {'user1': [STAFF], 'user2': [], 'user3': []}

    class Connection:
        def __init__(self, *args, **kw):
            self.response = []

        def open(self):
            if module.fail:
                raise OSError('connection refused by dc1.example.test')

        def start_tls(self):
            pass

        def bind(self):
            pass

        def unbind(self):
            pass

        def search(self, base, query, scope, attributes=None):
            module.asked.append(query)
            self.response = []
            if 'objectClass=group' in query and 'cn=G-Staff' in query:
                self.response = [{'type': 'searchResEntry', 'dn': STAFF, 'attributes': {}}]
            elif 'objectClass=group' not in query and not query.startswith('(memberOf:'):
                for name, groups in users.items():
                    if '(sAMAccountName=%s)' % name in query and base.startswith('CN=Users'):
                        self.response = [{'type': 'searchResEntry', 'dn': 'CN=%s,CN=Users,DC=example,DC=test' % name,
                                          'attributes': {'memberOf': groups}}]
            return True

    module.Tls = lambda **kw: 'tls'
    module.Server = lambda host, **kw: 'server'
    module.Connection = Connection
    return module


def wait_for(predicate, seconds=5.0):
    until = time.time() + seconds
    while time.time() < until:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


os.environ['TZ'] = 'UTC'
time.tzset()
LAB = lab()
TMP = tempfile.mkdtemp(prefix='test-service.')
try:
    state = os.path.join(TMP, 'db')
    os.makedirs(state)
    config = os.path.join(TMP, 'config.xml')
    shutil.copy(os.path.join(ROOT, 'tools', 'fixtures', 'config.xml'), config)
    settings.CONFIG = config
    engine.MAP, engine.LOCK, engine.HISTORY = state + '/map.json', state + '/lock', state + '/history'
    collector.GROUPS, collector.SOURCES = state + '/groups.json', state + '/sources.json'
    expire.GROUPS, expire.SOURCES, expire.SILENT, expire.STATUS = (state + '/groups.json', state + '/sources.json',
                                                                   state + '/silent.json', state + '/minute.json')
    outbox.OUTBOX = state + '/alerts'
    syslogng.CONF, syslogng.STATUS = TMP + '/syslog-ng.conf.d/useridentity.conf', state + '/syslog.json'

    # the syslog-ng source
    conf = settings.read()
    asked = []

    def run_with(sockstat='', sockstat_status=0, syntax=(0, '')):
        def run(args):
            asked.append(args[0])
            if args[0] == syslogng.SOCKSTAT:
                return sockstat_status, sockstat
            return syntax
        return run

    out = syslogng.apply(conf, run=run_with(), now=100)
    written = open(syslogng.CONF, encoding='utf-8').read()
    check('source: on, two domain controllers, the port free - written, said', (out['written'], out['changed'], out['port'],
                                                                                out['reason']), (True, True, 5141, ''))
    check('source: on 127.0.0.1, TCP, the lines taken whole, to the collector\'s socket as "$SOURCEIP $MSG"',
          all(part in written for part in ('network(ip("127.0.0.1") port(5141) transport("tcp") flags(no-parse)',
                                           'unix-dgram("/var/run/useridentity.sock" template("${SOURCEIP} ${MSG}")',
                                           'source(s_useridentity);', 'destination(d_useridentity);')), True)
    check('source: the collector\'s socket opened again one second after it is back, not syslog-ng\'s 60',
          'unix-dgram("/var/run/useridentity.sock" template("${SOURCEIP} ${MSG}") time-reopen(1));' in written, True)
    check('source: never s_all, so no filter of OPNsense\'s files the lines', 's_all' in written, False)
    check('source: the file 0644, as syslog-ng\'s others', oct(stat.S_IMODE(os.stat(syslogng.CONF).st_mode)), '0o644')
    check('source: sockstat asked first, then syslog-ng\'s check of its whole configuration',
          asked, [syslogng.SOCKSTAT, syslogng.SYSLOG_NG])
    check('source: what was done kept for the firewall hook', engine.read_json(syslogng.STATUS, {}),
          {'written': True, 'changed': True, 'port': 5141, 'reason': '', 'at': 100})
    out = syslogng.apply(conf, run=run_with('root syslog-ng 1234 13 tcp4 127.0.0.1:5141 *:*\n'), now=101)
    check('source again, syslog-ng holding the port through this very file: written, nothing changed',
          (out['written'], out['changed']), (True, False))
    out = syslogng.apply(conf, run=run_with('root nginx 777 6 tcp4 *:5141 *:*\n'), now=102)
    check('another program on the port: taken away, said - syslog-ng would stop whole on it',
          (out['written'], out['changed'], out['reason'], os.path.exists(syslogng.CONF)),
          (False, True, 'port 5141 on 127.0.0.1 is in use by nginx', False))
    out = syslogng.apply(conf, run=run_with('root syslog-ng 1234 13 tcp4 127.0.0.1:5141 *:*\n'), now=103)
    check('syslog-ng on the port through a file not this one: in use, not written',
          (out['written'], out['reason']), (False, 'port 5141 on 127.0.0.1 is in use by syslog-ng'))
    out = syslogng.apply(conf, run=run_with(sockstat_status=1), now=104)
    check('sockstat that cannot be read: not written', (out['written'], out['reason']),
          (False, 'sockstat could not be read, so port 5141 is not known to be free'))
    out = syslogng.apply(conf, run=run_with(syntax=(1, '\nError parsing config, syntax error near line 3\n')), now=105)
    check('syslog-ng refusing its configuration with the file, none there before: taken away again, its first line '
          'said, nothing said changed - a restart would stop syslog-ng whole were the refusal another file\'s',
          (out['written'], out['changed'], out['reason'], os.path.exists(syslogng.CONF)),
          (False, False, 'syslog-ng refused its configuration with it: Error parsing config, syntax error near line 3', False))
    syslogng.apply(conf, run=run_with(), now=105)
    good = open(syslogng.CONF, encoding='utf-8').read()
    out = syslogng.apply(dict(conf, local_port=5142), run=run_with(syntax=(1, 'Error parsing config\n')), now=105)
    check('syslog-ng refusing it with another port, a file there before: that file put back whole, nothing said '
          'changed, no redirect', (out['written'], out['changed'], syslogng.read(syslogng.CONF) == good,
                                   os.path.exists(syslogng.CONF + '.new')), (False, False, True, False))
    out = syslogng.apply(conf, run=run_with(syntax=(1, 'Error in a file of another\n')), now=105)
    check('syslog-ng refusing a configuration this very file is already in: the file left, nothing said changed',
          (out['written'], out['changed'], syslogng.read(syslogng.CONF) == good), (False, False, True))
    for port, why in ((5140, 'port 5140 may not be used'), (1023, 'port 1023 may not be used')):
        out = syslogng.apply(dict(conf, local_port=port), run=run_with(), now=106)
        check('local port %d: not written' % port, (out['written'], out['reason']), (False, why))
    syslogng.apply(conf, run=run_with(), now=107)
    out = syslogng.apply(dict(conf, enabled=False), run=run_with(), now=108)
    check('off: taken away, changed - syslog-ng is restarted to let the port go', (out['written'], out['changed'],
          out['reason'], os.path.exists(syslogng.CONF)), (False, True, 'off', False))
    out = syslogng.apply(dict(conf, dcs=[]), run=run_with(), now=109)
    check('no domain controller named: not written', (out['written'], out['changed'], out['reason']),
          (False, False, 'no domain controller named'))
    syslogng.apply(conf, run=run_with(), now=110)
    out = syslogng.apply(dict(conf, read=False), run=run_with(), now=111)
    check('config.xml unreadable: left as it was', (out['written'], os.path.exists(syslogng.CONF)), (True, True))

    # the collector, through a datagram socket as syslog-ng writes to it
    pf = FakePf()
    module = directory()
    sock_path = os.path.join(TMP, 'useridentity.sock')
    service = collector.Collector(socket_path=sock_path, pf=collector.tables.Pf(run=pf), ldap3=module,
                                  now=1794940000.0, addresses=lambda: ({'192.0.2.1'}, {'192.0.2.255'}))
    service.open()
    check('the socket: made, 0600', oct(stat.S_IMODE(os.stat(sock_path).st_mode)), '0o600')
    sender = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    names = ['computer-pc', 'ticket-user1', 'service-ticket-user1', 'forged', 'logon-system', 'logon-user1-no-address',
             'logoff']
    for name in names:
        when, source, message = LAB[name]
        sender.sendto(('%s %s' % (source, message)).encode(), sock_path)
    got = service.drain()
    check('drain: every datagram, the largest of the lab\'s lines whole', (len(got), max(len(g) for g in got) > 3000),
          (len(names), True))
    changes = service.receive(got, LAB['ticket-user1'][0])
    check('the directory asked in its own thread', wait_for(lambda: not service.directory.answers.empty()), True)
    # its answer wakes the collector's select at once, not at the next line or the end of the second (phase 1's
    # lab: a group's table a second late)
    check('the answer wakes the collector: its pipe readable, then read away',
          (bool(select.select([service.directory.wake_r], [], [], 2.0)[0]),
           service.directory.woken() or bool(select.select([service.directory.wake_r], [], [], 0)[0])), (True, False))
    service.answers(LAB['ticket-user1'][0])
    when, source, message = LAB['logon-user1']
    sender.sendto(('%s %s' % (source, message)).encode(), sock_path)
    changes += service.receive(service.drain(), when)
    check('receive: user1 mapped from its ticket, renewed by its logon twelve minutes on', changes,
          [('joined', '192.0.2.20', 'user1'), ('renewed', '192.0.2.20', 'user1')])
    seen = service.sources.senders
    dc = seen['192.0.2.10']
    check('the domain controller\'s counts: lines, accepted, what changed, the other IDs, each refusal by its reason',
          (dc['lines'], dc['accepted'], dc['joined'], dc['renewed'], dc['other'], dc['refused']),
          (7, 2, 1, 1, {'4769': 1, '4634': 1}, {'computer': 1, 'not a user': 1, 'no address': 1}))
    check('the domain controller: its name and how late its last event came', (dc['hostname'], dc['late']),
          ('DC1.example.test', 2.0))
    check('a machine that is no domain controller: its line refused as such, its event never read',
          (seen['192.0.2.2']['lines'], seen['192.0.2.2']['refused'], seen['192.0.2.2']['accepted']),
          (1, {'not a domain controller': 1}, 0))
    check('the map saved: user1 on 192.0.2.20', engine.load()['map']['192.0.2.20']['user'], 'user1')
    check('its answer kept: user1 in G-Staff', engine.read_json(collector.GROUPS, {})['users']['user1']['in'], ['g-staff'])
    check('the tables: user1\'s own, and G-Staff\'s once the directory answered',
          {k: v for k, v in pf.held.items() if v}, {'uid_usr_user1': {'192.0.2.20'}, 'uid_grp_G_Staff': {'192.0.2.20'}})
    check('the directory asked by the user attribute and the extended query, under the first container holding it',
          [q for q in module.asked if 'user1' in q], ['(&(sAMAccountName=user1)(objectClass=user))'])
    service.sources.save()
    check('sources.json: counts and times, no line', ('Message' in open(collector.SOURCES).read(),
                                                     sorted(engine.read_json(collector.SOURCES, {})['senders'])),
          (False, ['192.0.2.10', '192.0.2.2']))

    # latest wins on the address, the shared alert - with no name, as Log user names is off
    when, source, message = LAB['runas-user2']
    sender.sendto(('%s %s' % (source, message)).encode(), sock_path)
    changes = service.receive(service.drain(), when)
    check('user2 on the same address: mapped to it, shared', changes,
          [('changed', '192.0.2.20', ('user1', 'user2')), ('shared', '192.0.2.20', ['user1', 'user2'])])
    alerts = sorted(os.listdir(outbox.OUTBOX))
    check('an alert for the address newly shared', [a.split('-')[0] + '-' + a.split('-')[1] for a in alerts],
          ['address-shared'])
    found = json.load(open(os.path.join(outbox.OUTBOX, alerts[0]), encoding='utf-8'))
    check('the alert in os-xgs-npu\'s form, the address and no user named',
          (found['source'], found['kind'], found['facts'], any(u in found['text'] for u in ('user1', 'user2'))),
          ('os-useridentity', 'address-shared', {'address': '192.0.2.20'}, False))
    check('the tables follow the map at once: user1 no longer holds the address, nor does G-Staff',
          (pf.held.get('uid_usr_user1'), pf.held.get('uid_grp_G_Staff')), (set(), set()))
    check('user2 asked of the directory too', wait_for(lambda: not service.directory.answers.empty()), True)
    service.answers(when)
    check('user2 in no group: G-Staff still empty', (engine.read_json(collector.GROUPS, {})['users']['user2']['in'],
                                                      pf.held.get('uid_grp_G_Staff')), ([], set()))

    # the directory failing: an alert, once
    module.fail = True
    service.directory.close()
    service.directory.ask('user3')
    check('the directory failing answers', wait_for(lambda: not service.directory.answers.empty()), True)
    service.answers(when)
    service.directory.ask('user9')
    wait_for(lambda: not service.directory.answers.empty(), 1.0)
    service.answers(when)
    kinds = sorted(a.split('-')[0] + '-' + a.split('-')[1] for a in os.listdir(outbox.OUTBOX))
    check('the directory failing: one alert, its state kept for the page', (kinds,
          engine.read_json(collector.GROUPS, {})['server']['ok']), (['address-shared', 'ldap-failing'], False))
    check('the error said without the bind password', 'not-a-real-one' in json.dumps(engine.read_json(collector.GROUPS, {})),
          False)

    # Settings changed: read again when config.xml's time moves
    text = open(config, encoding='utf-8').read()
    with open(config, 'w', encoding='utf-8') as handle:
        handle.write(text.replace('<log_names>0</log_names>', '<log_names>1</log_names>'))
    os.utime(config, (time.time() + 5, time.time() + 5))
    service.refresh(time.time())
    check('config.xml changed: read again', service.conf['log_names'], True)
    service.conf = dict(service.conf, server=None)
    when3, source, message = LAB['runas-user3']
    sender.sendto(('%s %s' % (source, message)).encode(), sock_path)
    service.receive(service.drain(), when3)
    check('no directory chosen: the user mapped, nobody asked, no alert',
          (engine.load()['map']['192.0.2.20']['user'], wait_for(lambda: not service.directory.answers.empty(), 0.5),
           service.directory.waiting), ('user3', False, set()))

    # at a start: the map's tables written whole
    engine.save({'map': {'192.0.2.30': {'user': 'user1', 'first': when, 'last': when, 'expires': when + 999,
                                        'mac': '', 'others': {}}}})
    pf.held.clear()
    service.written = {}
    service.start(when)
    check('a start: the tables made from the map, whatever pf held', pf.held,
          {'uid_grp_G_Staff': {'192.0.2.30'}, 'uid_usr_user1': {'192.0.2.30'}})
    service.groups['users'] = {'user1': {'in': ['g-staff'], 'at': when - 2000}, 'user8': {'in': [], 'at': when - 2000},
                               'user9': {'in': [], 'at': when - 10}}
    check('the directory\'s answers for users no longer mapped forgotten after 15 minutes - only the live map is kept',
          (service.prune_groups(when), sorted(engine.read_json(collector.GROUPS, {})['users'])), (1, ['user1', 'user9']))

    # a group row added: the answers kept but marked old, every user in the map asked again at once -
    # no table emptied meanwhile, nor fought over with the minute's run (the review's first finding)
    module.fail = False
    service.directory.failed_at = 0.0
    module.asked.clear()
    rows = open(config, encoding='utf-8').read()
    with open(config, 'w', encoding='utf-8') as handle:
        handle.write(rows.replace('</groups>', '<group uuid="11111111-0000-4000-8000-000000000003"><enabled>1</enabled>'
                                               '<name>G-Sales</name><alias>uid_grp_G_Sales</alias><description/></group>'
                                               '</groups>'))
    os.utime(config, (time.time() + 10, time.time() + 10))
    service.refresh(time.time())
    kept_answer = engine.read_json(collector.GROUPS, {})['users'].get('user1', {})
    check('a group row added: what the directory said kept, marked old, on the disk too',
          (kept_answer.get('in'), kept_answer.get('at')), (['g-staff'], 0))
    with engine.locked():
        service.write_tables(engine.load())
    check('a group row added: G-Staff\'s table not emptied while the directory is asked again',
          pf.held.get('uid_grp_G_Staff'), {'192.0.2.30'})
    check('a group row added: every user in the map asked again at once',
          wait_for(lambda: any('user1' in q for q in module.asked)), True)
    wait_for(lambda: not service.directory.answers.empty())
    service.answers(when)
    check('a group row added: the new answer kept, and the tables as the map says',
          (engine.read_json(collector.GROUPS, {})['users']['user1']['at'] > 0, pf.held.get('uid_grp_G_Staff')),
          (True, {'192.0.2.30'}))
    with open(config, 'w', encoding='utf-8') as handle:
        handle.write(rows)
    os.utime(config, (time.time() + 20, time.time() + 20))
    service.refresh(time.time())
    wait_for(lambda: not service.directory.answers.empty())
    service.answers(when)

    # the minute's run ends a mapping and empties its tables; the same user's next logon from the same
    # address is written at once, not at the next minute (the review's sixth finding)
    def logon_at(name, stamp):
        arrival, source, message = LAB[name]
        found = json.loads(message[message.find('{'):])
        found['EventTime'] = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(stamp))
        sender.sendto(('%s %s' % (source, json.dumps(found))).encode(), sock_path)
        return service.receive(service.drain(), stamp + 1)

    engine.save({'map': {}})
    first = 1795000000.0
    logon_at('runas-user1', first)
    check('user1 logs on from 192.0.2.20: its table written', pf.held.get('uid_usr_user1'), {'192.0.2.20'})
    expire.run(settings.read(), now=first + 480 * 60 + 5, pf=collector.tables.Pf(run=pf), macs=lambda: {})
    check('the minute\'s run: the lifetime over, the mapping gone and the table emptied', (engine.load()['map'],
          pf.held.get('uid_usr_user1')), ({}, set()))
    logon_at('runas-user1', first + 480 * 60 + 10)
    check('user1 logs on again from 192.0.2.20: its table written again at once', pf.held.get('uid_usr_user1'),
          {'192.0.2.20'})

    # Forget all while the collector runs: what the directory said, which it holds, goes with what groups.json
    # held, and the user's next logon asks again - the minute's run, which makes the group tables from
    # groups.json, never takes out what the collector put in (phase 1's lab, 2026-11-18: G-Staff's table
    # emptied at each minute while u3 was mapped, and the Users tab showed u3 in no group)
    engine.save({'map': {}})
    second = first + 480 * 60 + 100
    logon_at('runas-user1', second)
    # every answer the directory owes taken in first: one of an earlier question, landing after Forget all,
    # would write groups.json again and hide what is tested here
    while wait_for(lambda: not service.directory.answers.empty(), 1.0):
        service.answers(second + 1)
    check('user1 mapped and its groups asked: G-Staff holds the address', pf.held.get('uid_grp_G_Staff'),
          {'192.0.2.20'})
    expire.run(settings.read(), now=second + 2, pf=collector.tables.Pf(run=pf), flush=True)
    module.asked.clear()
    logon_at('runas-user1', second + 10)
    check('Forget all, then user1 again: the directory asked again, not answered from what the collector held',
          wait_for(lambda: any('user1' in q for q in module.asked)), True)
    wait_for(lambda: not service.directory.answers.empty())
    service.answers(second + 12)
    expire.run(settings.read(), now=second + 60, pf=collector.tables.Pf(run=pf), macs=lambda: {})
    check('... and the minute\'s run after it: G-Staff still holds the address, and groups.json says why',
          (pf.held.get('uid_grp_G_Staff'), engine.read_json(collector.GROUPS, {})['users'].get('user1', {}).get('in')),
          ({'192.0.2.20'}, ['g-staff']))
    service.close()
    check('closed: the socket taken away', os.path.exists(sock_path), False)
    sender.close()

    # the minute's run
    pf = FakePf()
    now = 1794990000.0
    engine.save({'map': {
        '192.0.2.20': {'user': 'user1', 'first': now - 100, 'last': now - 100, 'expires': now + 100, 'mac': '', 'others': {}},
        '192.0.2.21': {'user': 'user1', 'first': now - 100, 'last': now - 100, 'expires': now - 1, 'mac': '', 'others': {}},
        '192.0.2.22': {'user': 'user2', 'first': now - 100, 'last': now - 100, 'expires': now + 100,
                       'mac': '02:00:00:00:00:16', 'others': {}}}})
    engine.write_json(expire.GROUPS, {'users': {'user1': {'in': ['g-staff']}}})
    pf.held['uid_grp_G_Staff'] = {'192.0.2.99'}
    conf = settings.read()
    out = expire.run(conf, now=now, pf=collector.tables.Pf(run=pf),
                     macs=lambda: {'192.0.2.20': '02:00:00:00:00:14', '192.0.2.22': '02:00:00:00:00:17'})
    check('minute: one lifetime ended, one MAC changed, one kept', (out['expired'], out['mac'], out['mapped']), (1, 1, 1))
    check('minute: its MAC recorded on the one kept', engine.load()['map']['192.0.2.20']['mac'], '02:00:00:00:00:14')
    check('minute: every table made again from the map - one emptied by hand filled, one held wrongly put right',
          (pf.held['uid_grp_G_Staff'], pf.held['uid_usr_user1']), ({'192.0.2.20'}, {'192.0.2.20'}))
    check('minute: what it did kept for the page', engine.read_json(expire.STATUS, {})['mapped'], 1)
    kept = open(config, encoding='utf-8').read()
    with open(config, 'w', encoding='utf-8') as handle:
        handle.write(kept.replace('<aliases>', '<aliases><alias uuid="33333333-0000-4000-8000-000000000009"><enabled>0'
                                               '</enabled><name>uid_grp_Old</name><type>external</type><description>User '
                                               'Identity: group Old</description></alias>', 1))
    pf.held['uid_grp_Old'] = {'192.0.2.77'}
    expire.run(settings.read(), now=now, pf=collector.tables.Pf(run=pf), macs=lambda: {})
    check('minute: the table of an alias of the plugin\'s switched off - a rule still names it - kept empty',
          pf.held['uid_grp_Old'], set())
    with open(config, 'w', encoding='utf-8') as handle:
        handle.write(kept)
    out = expire.run(conf, now=now + 1, pf=collector.tables.Pf(run=pf), flush=True)
    check('Forget all: every mapping gone, the tables emptied, the directory\'s answers about its users with them',
          (out['flushed'], engine.load()['map'], pf.held['uid_grp_G_Staff'], pf.held['uid_usr_user1'],
           engine.read_json(expire.GROUPS, {})['users']), (1, {}, set(), set(), {}))
    engine.save({'map': {'192.0.2.20': {'user': 'user1', 'first': now, 'last': now, 'expires': now + 999, 'mac': '',
                                        'others': {}}}})
    out = expire.run(dict(conf, enabled=False), now=now + 2, pf=collector.tables.Pf(run=pf), macs=lambda: {})
    check('the plugin off: the map forgotten at the next minute', (out['flushed'], engine.load()['map']), (1, {}))
    out = expire.run(dict(conf, read=False), now=now + 3, pf=collector.tables.Pf(run=pf))
    check('config.xml unreadable: nothing done', out['errors'], ['config.xml could not be read: nothing done'])

    # a domain controller silent (the minute's runs above said what they saw: started afresh)
    shutil.rmtree(outbox.OUTBOX)
    os.unlink(expire.SILENT)
    sources = {'since': now - 3600, 'senders': {'192.0.2.10': {'last_line': now - 60}}}
    conf = dict(settings.read(), alert_silent=1800)
    check('silent: the one never heard from in 30 minutes, alerted', expire.silent(conf, now, sources), ['192.0.2.11'])
    check('silent: not again while it stays silent', expire.silent(conf, now + 60, sources), [])
    sources['senders']['192.0.2.11'] = {'last_line': now + 100}
    check('silent: heard from again - nothing', expire.silent(conf, now + 120, sources), [])
    check('silent: 30 minutes on, both silent - the one heard from again alerted again, the other for the first time',
          expire.silent(conf, now + 2000, sources), ['192.0.2.10', '192.0.2.11'])
    files = sorted(os.listdir(outbox.OUTBOX))
    found = json.load(open(os.path.join(outbox.OUTBOX, files[0]), encoding='utf-8'))
    check('the silent alert: its kind and facts', (found['kind'], found['facts']),
          ('dc-silent', {'domain_controller': '192.0.2.11', 'minutes': 60}))
    check('silent with the setting at 0: nothing', expire.silent(dict(conf, alert_silent=0), now + 9999, sources), [])

    # the outbox kept 24 hours and 100 at most
    shutil.rmtree(outbox.OUTBOX)
    for i in range(105):
        path = outbox.alert('dc-silent', 's', 't', {}, now=now + i, log=False)
        os.utime(path, (now + i, now + i))
    old = outbox.alert('ldap-failing', 's', 't', {}, now=now - 90000, log=False)
    os.utime(old, (now - 90000, now - 90000))
    check('the outbox: the one older than 24 hours and the 5 oldest past 100 taken away',
          (outbox.prune(now + 200), len(os.listdir(outbox.OUTBOX)), os.path.exists(old)), (6, 100, False))
    check('the outbox: an alert of the same second gets a name of its own',
          outbox.alert('x', 's', 't', {}, now=now, log=False) != outbox.alert('x', 's', 't', {}, now=now, log=False), True)

    # what the page shows
    status.GROUPS, status.SOURCES, status.SOURCE, status.MINUTE = (collector.GROUPS, collector.SOURCES,
                                                                   syslogng.STATUS, expire.STATUS)
    engine.save({'map': {
        '192.0.2.20': {'user': 'user2', 'domain': 'EXAMPLE', 'source': '192.0.2.10', 'first': now - 50, 'last': now - 10,
                       'expires': now + 999, 'mac': '02:00:00:00:00:14', 'others': {'user1': now - 60, 'user9': now - 99999}},
        '192.0.2.21': {'user': 'user1', 'source': '192.0.2.10', 'first': now, 'last': now, 'expires': now + 999,
                       'mac': '', 'others': {}}}})
    engine.write_json(collector.GROUPS, {'users': {'user1': {'in': ['g-staff']}},
                                         'server': {'ok': True, 'error': '', 'at': now, 'chain': 'used'}})
    engine.write_json(collector.SOURCES, {'since': now - 3600, 'senders': {
        '192.0.2.10': {'last_line': now - 5, 'last_event': now - 7, 'late': 2.0, 'hostname': 'DC1.example.test',
                       'lines': 9, 'accepted': 4, 'joined': 2, 'renewed': 2, 'changed': 0, 'other': {'4769': 3},
                       'refused': {'stale': 1, 'computer': 1}},
        '192.0.2.2': {'last_line': now - 60, 'lines': 1, 'refused': {'not a domain controller': 1}}}})
    pfctl = os.path.join(TMP, 'pfctl')
    with open(pfctl, 'w', encoding='utf-8') as handle:
        handle.write('#!/bin/sh\nprintf \'%s\\n\' "--a-r--\tuid_grp_G_Staff" "\tAddresses:   1" "\tCleared:     now" '
                     '"--a----\tuid_usr_user1" "\tAddresses:   2" "-pa----\tbogons" "\tAddresses:   1000"\n')
    os.chmod(pfctl, 0o755)
    shown = status.report(now=now, pidfile=os.path.join(TMP, 'none.pid'), pfctl=pfctl, project=os.path.join(TMP, 'xgs'))
    check('status: on, the collector not running, no os-xgs-npu', (shown['enabled'], shown['running'], shown['project']),
          (True, False, False))
    check('status: two users on two addresses, one address shared - user9 seen too long ago to count',
          shown['counts'], {'users': 2, 'addresses': 2, 'shared': 1})
    check('status: each table, the addresses pf holds there, whether XGS: Settings cuts on it',
          [(t['alias'], t['present'], t['entries'], t['cut']) for t in shown['tables']],
          [('uid_grp_G_Staff', True, 1, True), ('uid_grp_Guests', False, None, False), ('uid_usr_user1', True, 2, False)])
    check('status: the named domain controllers first, heard or not, then any other sender; stale apart from the rest',
          [(s['address'], s['named'], s['stale'], s['refused'], s['other']) for s in shown['sources']],
          [('192.0.2.10', True, 1, 1, 3), ('192.0.2.11', True, 0, 0, 0), ('192.0.2.2', False, 0, 1, 0)])
    check('status: the last event, the directory, where the domain controllers send to',
          (shown['last_event'], shown['ldap']['ok'], shown['ldap']['chosen'], shown['listen'], shown['port']),
          (now - 7, True, 'Example directory', [{'interface': 'lan', 'address': '192.0.2.1'},
                                                {'interface': 'opt1', 'address': '198.51.100.1'}], 514))
    rows = status.mapped(engine.load(), {'user1': {'in': ['g-staff']}}, settings.read(), now)
    check('the Users tab\'s rows: the group\'s name as its row gives it, who shares the address, whether the directory '
          'answered for the user', [(r['address'], r['user'], r['groups'], r['shared'], r['known']) for r in rows],
          [('192.0.2.20', 'user2', [], ['user1'], False), ('192.0.2.21', 'user1', ['G-Staff'], [], True)])
finally:
    shutil.rmtree(TMP, ignore_errors=True)

print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
