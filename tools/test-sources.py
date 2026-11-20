#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""The sources beside the domain controllers (src/opnsense/scripts/useridentity/sources/): RADIUS
accounting as os-freeradius writes it, and the captive portal's sessions as its database holds them.

RADIUS: the three records phase 0's lab had FreeRADIUS write for its A9 - Start, Interim-Update, Stop,
in tools/fixtures/radacct-detail.txt, the address made a documentation one - and records made from
them: the detail file's quoting, a record still being written, its time (FreeRADIUS's Timestamp less
Acct-Delay-Time, or its first line), each status by name and by number, what is refused and why - a
client not named, no status, no time, nobody, anonymous, a computer, a MAC address as the name, a realm
of another directory - the sessions an Interim-Update renews, a Stop ends, a new address replaces, a
Stop that another session of the same user holds the address against (a device that roamed),
Accounting-On and -Off ending the sessions of the NAS they name - behind a server that forwards several,
that NAS's alone; and the files read as they grow: only the days a record within the lifetime is in, a
file never read taken whole when written within the lifetime, else from its end, what was read kept
across a restart, one cut short or made again read from its start, one gone forgotten, a large one read
a part at a time, radius.json written at most every ten seconds, and where the reading stood put back.

The portal: a database with the tables of OPNsense core's captiveportal (cp_clients, cp_client_ips) -
the sessions of the zones switched on, not those deleted, each with its roaming addresses; a database
not there, one that cannot be read, one without cp_client_ips; the sessions that map nothing - an
allowed address or MAC, a zone with no login, a voucher, another directory, no address; and what the
map is to do to say
what the portal says: a session's addresses mapped at the first reading, renewed once a minute, taken
out at its end, a roaming address added and dropped, another login of the same user on the device no
logoff, a later event of another source not taken back but noted, a mapping forgotten made again, and,
at the collector's first reading, what the map holds of a session that ended while it was down.

    python3 tools/test-sources.py"""
import json
import os
import sqlite3
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src', 'opnsense', 'scripts', 'useridentity'))
import engine                                                            # noqa: E402
from sources import portal, radius                                       # noqa: E402

failures = 0
checks = 0
LIFE = 480 * 60


def check(name, got, want):
    global failures, checks
    checks += 1
    ok = got == want
    failures += 0 if ok else 1
    print('%s %s%s' % ('ok  ' if ok else 'FAIL', name, '' if ok else ' - got %r, want %r' % (got, want)))


os.environ['TZ'] = 'UTC'
time.tzset()
LAB = open(os.path.join(ROOT, 'tools', 'fixtures', 'radacct-detail.txt'), encoding='utf-8').read()

# the detail file's form
check('unquote: a string, its escapes, octal, and a value with no quotes',
      [radius.unquote(v) for v in ('"u1"', r'"a \"b\" c\\d"', r'"tab\there"', r'"bell\007"', 'Start', '192.0.2.77')],
      ['u1', 'a "b" c\\d', 'tab\there', 'bell\x07', 'Start', '192.0.2.77'])
texts, used = radius.split(LAB.encode())
check('split: the lab\'s three records, every byte taken', (len(texts), used), (3, len(LAB.encode())))
texts, used = radius.split(LAB.encode() + b'Tue Nov 17 21:22:00 2026\n\tUser-Name = "u2"\n')
check('split: a record still being written left for the next reading', (len(texts), used), (3, len(LAB.encode())))
texts, used = radius.split(b'\n\n\nTue Nov 17 21:22:00 2026\n\tUser-Name = "u2"\n\n\n\n')
check('split: empty lines around a record', (len(texts), texts[0].splitlines()[0]), (1, 'Tue Nov 17 21:22:00 2026'))
check('split: nothing complete - nothing taken', radius.split(b'Tue Nov 17'), ([], 0))
header, found = radius.parse(radius.split(LAB.encode())[0][2])
check('parse: the time line and each attribute, unquoted',
      (header, found['User-Name'], found['Acct-Status-Type'], found['Framed-IP-Address'], found['Timestamp']),
      ('Tue Nov 17 21:21:49 2026', 'u1', 'Stop', '192.0.2.77', '1794950509'))
header, found = radius.parse('\tUser-Name = "first"\n\tUser-Name = "second"\n\tClass = 0x01\n  Odd = "two spaces"\nnoise')
check('parse: no time line, an attribute given twice keeps its first value, a line with no tab ignored',
      (header, found), ('', {'User-Name': 'first', 'Class': '0x01', 'Odd': 'two spaces'}))
check('is_mac: the forms a NAS writes a MAC in', [radius.is_mac(n) for n in (
    '020000a90001', '02-00-00-00-a9-01', '02:00:00:00:a9:01', '0200.00a9.0001', 'abcdefabcdef1', 'user1', 'u-1-2-3-4-5')],
      [True, True, True, True, False, False, False])

# a record's time
check('time: FreeRADIUS\'s Timestamp', radius.record_time('', {'Timestamp': '1794950509'}), 1794950509.0)
check('time: less the seconds the NAS waited', radius.record_time('', {'Timestamp': '1794950509', 'Acct-Delay-Time': '9'}),
      1794950500.0)
check('time: no Timestamp - the time line, in the firewall\'s zone', radius.record_time('Tue Nov 17 21:21:49 2026', {}),
      1794950509.0)
check('time: a day of one digit, as ctime pads it', radius.record_time('Sat Nov  7 21:21:49 2026', {}), 1794086509.0)
check('time: none that can be read', radius.record_time('yesterday', {'Timestamp': 'soon'}), None)


def record(status='Start', user='u1', address='192.0.2.77', stamp=1794950505, session='s1', **more):
    found = {'Acct-Status-Type': status, 'Timestamp': stamp if isinstance(stamp, str) else str(int(stamp)),
             'Acct-Unique-Session-Id': session, 'NAS-IP-Address': '192.0.2.40'}
    if user is not None:
        found['User-Name'] = user
    if address is not None:
        found['Framed-IP-Address'] = address
    found.update(more)
    return found


status, found = radius.interpret('192.0.2.40', '', record(**{'NAS-Identifier': 'ap1', 'Framed-IPv6-Address': '2001:db8::77'}))
check('interpret: a Start - its user, both addresses, the NAS by its identifier, the session, its client and its NAS',
      (status, found['name'], found['user'], found['addresses'], found['hostname'], found['session'], found['client'],
       found['nas']),
      ('start', 'Start', 'u1', ['192.0.2.77', '2001:db8::77'], 'ap1', 's1', '192.0.2.40', ['192.0.2.40', '', 'ap1']))
check('the NAS: its IPv6 address written as the firewall writes it, one it does not give empty',
      radius.nas_of({'NAS-IPv6-Address': '2001:DB8:0::5', 'NAS-Identifier': ' sw-1 '}), ['', '2001:db8::5', 'sw-1'])
check('same NAS: by any of the three, none different; a record or a session that names none is its client\'s',
      [radius.same_nas(['198.51.100.1', '', 'sw-1'], ['198.51.100.1', '', '']),
       radius.same_nas(['198.51.100.1', '', 'sw-1'], ['', '', 'sw-1']),
       radius.same_nas(['198.51.100.1', '', 'sw-1'], ['198.51.100.2', '', '']),
       radius.same_nas(['198.51.100.1', '', 'sw-1'], ['198.51.100.1', '', 'sw-2']),
       radius.same_nas(['198.51.100.1', '', ''], ['', '', 'sw-1']),
       radius.same_nas(['198.51.100.1', '', ''], ['', '', '']),
       radius.same_nas(['', '', ''], ['198.51.100.3', '', ''])],
      [True, True, False, False, False, True, True])
check('interpret: each status, by name and by number', [radius.interpret('c', '', record(status=s))[0] for s in (
    'Interim-Update', 'Alive', '3', 'Stop', '2', 'Accounting-On', '7', 'Accounting-Off', '8', '1')],
      ['interim', 'interim', 'interim', 'stop', 'stop', 'on', 'on', 'off', 'off', 'start'])
check('interpret: a status that maps nothing - counted as it is written', radius.interpret('c', '', record(status='Failed')),
      ('other', 'Failed'))
check('interpret: no status - not readable', radius.interpret('c', '', {'User-Name': 'u1'}), ('refused', 'unreadable'))
check('interpret: no time - refused', radius.interpret('c', 'no time here', record(stamp='x')), ('refused', 'no time'))
names = ['', 'anonymous', 'anonymous@example.test', '-', 'host/pc1.example.test', 'EXAMPLE\\pc1$', '02-00-00-00-a9-01',
         '020000a90001', 'u1@example.test', 'EXAMPLE\\U1']
check('interpret: the names that are nobody, a computer, a MAC address; a realm or a domain taken off',
      [radius.interpret('c', '', record(user=n)) for n in names[:8]] +
      [(radius.interpret('c', '', record(user=n))[1]['user'], radius.interpret('c', '', record(user=n))[1]['domain'])
       for n in names[8:]],
      [('refused', 'not a user')] * 4 + [('refused', 'computer')] * 2 + [('refused', 'mac authentication')] * 2 +
      [('u1', 'example.test'), ('u1', 'EXAMPLE')])
status, found = radius.interpret('c', '', record(user=None))
check('interpret: no User-Name - nobody', (status, found), ('refused', 'not a user'))
status, found = radius.interpret('192.0.2.40', '', record(session='', **{'Acct-Session-Id': 'p0-a9-1'}))
check('interpret: no Acct-Unique-Session-Id - the session known by its client, its NAS and Acct-Session-Id',
      found['session'], '192.0.2.40|192.0.2.40||p0-a9-1')
status, found = radius.interpret('c', '', record(status='Accounting-On', user=None, address=None))
check('interpret: Accounting-On needs no user', (status, found['name']), ('on', 'Accounting-On'))

# the sessions
with tempfile.TemporaryDirectory() as tmp:
    acct = radius.Accounting(path=os.path.join(tmp, 'radius.json'), folder=os.path.join(tmp, 'radacct'))
    T = 1794950505.0

    def take(found, client='192.0.2.40'):
        return [i for i in acct.take(client, '', found, T, LIFE) if i[0] != 'line' and i[0] != 'heard']

    out = take(record())
    check('a Start: the event for its address - a logon', [(i[0], i[2]['address'], i[2]['kind'], i[2]['id']) for i in out],
          [('event', '192.0.2.77', 'radius', 'Start')])
    check('a Start: the session kept, with its client, its NAS and its logon\'s time', acct.sessions['s1'],
          {'client': '192.0.2.40', 'nas': ['192.0.2.40', '', ''], 'user': 'u1', 'addresses': ['192.0.2.77'],
           'since': T, 'last': T})
    out = take(record(status='Interim-Update', address=None, stamp=T + 600))
    check('an Interim-Update without an address renews the one the session had - a renewal, since its logon',
          [(i[0], i[2]['address'], i[2]['time'], i[3]) for i in out], [('renew', '192.0.2.77', T + 600, T)])
    out = take(record(status='Interim-Update', address='192.0.2.78', stamp=T + 700))
    check('an Interim-Update with another address: the old one ends, the new one maps',
          [(i[0], i[3] if i[0] == 'end' else i[2]['address']) for i in out], [('end', '192.0.2.77'), ('event', '192.0.2.78')])
    out = take(record(status='Stop', address=None, stamp=T + 800))
    check('a Stop without an address ends the session\'s, with the Stop\'s own time', (out, 's1' in acct.sessions),
          ([('end', '192.0.2.40', 'u1', '192.0.2.78', T + 800)], False))
    out = take(record(status='Stop', address='192.0.2.79', session='never-seen'))
    check('a Stop of a session never seen ends its own address', out, [('end', '192.0.2.40', 'u1', '192.0.2.79', T)])
    out = take(record(address=None, session='s2'))
    check('a Start with no address: refused, the session kept for its Interim-Update',
          (out, acct.sessions['s2']['addresses']), ([('refused', '192.0.2.40', 'no address')], []))
    out = take(record(status='Interim-Update', address='192.0.2.80', session='s2', stamp=T + 60))
    check('... which maps the address once it has one', [(i[0], i[2]['address']) for i in out], [('event', '192.0.2.80')])
    out = take(record(address='127.0.0.1', session='s3'))
    check('an address that is no client\'s: refused', out, [('refused', '192.0.2.40', 'not a client address')])
    out = take(record(user='u9', address='192.0.2.80', session='s2', status='Interim-Update', stamp=T + 90))
    check('a session that names another user: the one before ends there first',
          [(i[0], i[2] if i[0] == 'end' else i[2]['user']) for i in out], [('end', 'u1'), ('event', 'u9')])
    take(record(address='198.51.100.7', session='s4'), client='198.51.100.1')
    out = acct.take('192.0.2.40', '', record(status='Accounting-On', user=None, address=None), T, LIFE)
    check('Accounting-On: every session of the NAS it names ends, another client\'s kept, counted among the others',
          ([i for i in out if i[0] in ('end', 'other')], sorted(acct.sessions)),
          ([('other', '192.0.2.40', 'Accounting-On'), ('end', '192.0.2.40', 'u9', '192.0.2.80', T),
            ('end', '192.0.2.40', 'u1', '127.0.0.1', T)], ['s4']))
    acct.save()
    check('the sessions kept in radius.json, 0640', (json.load(open(acct.path))['sessions']['s4']['user'],
                                                     oct(os.stat(acct.path).st_mode & 0o777)), ('u1', '0o640'))
    acct.poll(T + LIFE + 1, LIFE)
    check('a session with no record for longer than the lifetime forgotten', acct.sessions, {})

    # which clients may map (the review's fifth finding, and its first: the name a NAS reports with EAP is the
    # device's own outer name - student1 giving 'ceo' - so nothing maps from a client the owner has not named)
    gate = radius.Accounting(path=os.path.join(tmp, 'gate.json'), folder=os.path.join(tmp, 'none'))
    out = gate.take('192.0.2.41', '', record(user='ceo', address='192.0.2.80'), T, LIFE, clients={'192.0.2.40'})
    check('a client not named: refused before anything else is read of its record, no session kept',
          (out, gate.sessions), ([('line', '192.0.2.41'), ('refused', '192.0.2.41', 'not a named client')], {}))
    out = gate.take('192.0.2.40', '', record(user='ceo', address='192.0.2.80'), T, LIFE, clients=set())
    check('none named: no record maps, whatever name it gives', [i[0] for i in out], ['line', 'refused'])
    out = gate.take('192.0.2.41', '', record(status='Accounting-Off', user=None, address=None), T, LIFE,
                    clients={'192.0.2.40'})
    check('... nor does a client not named end anything', [i[0] for i in out], ['line', 'refused'])
    out = gate.take('2001:DB8::40', '', record(session='v6'), T, LIFE, clients={'2001:db8::40'})
    check('a client named by its IPv6 address, its directory written another way: the same client',
          [i[0] for i in out], ['line', 'heard', 'event'])

    # another directory (the review's fourth finding): with a directory chosen, a realm or a domain not its own
    realms = {'example.test', 'example'}
    said = []
    for name in ('jsmith@partner.example', 'PARTNER\\jsmith', 'jsmith@example.test', 'EXAMPLE\\jsmith', 'jsmith'):
        out = gate.take('192.0.2.40', '', record(user=name, session='d-' + name), T, LIFE, realms=realms)
        said.append([i[2] if i[0] == 'refused' else i[0] for i in out if i[0] != 'line'][0])
    out = gate.take('192.0.2.40', '', record(status='Stop', user='jsmith@partner.example', session='d-x'), T, LIFE,
                    realms=realms)
    check('another directory: a name of another realm or domain refused - its Stop too, which ends nothing; the '
          'directory\'s own realm, its domain and a bare name taken',
          (said, [i[0] for i in out]), (['another directory', 'another directory', 'heard', 'heard', 'heard'],
                                        ['line', 'refused']))
    out = gate.take('192.0.2.40', '', record(user='jsmith@partner.example', session='d-y'), T, LIFE, realms=None)
    check('... no directory chosen: no realm refused', [i[0] for i in out], ['line', 'heard', 'event'])

    # a device that roams (the review's second finding, case A): ap2's Start, then ap1's Stop five seconds later
    roam = radius.Accounting(path=os.path.join(tmp, 'roam.json'), folder=os.path.join(tmp, 'none'))
    roam.take('192.0.2.40', '', record(user='alice', session='r1', stamp=T), T, LIFE)
    roam.take('192.0.2.41', '', record(user='alice', session='r2', stamp=T + 5, **{'NAS-IP-Address': '192.0.2.41'}),
              T, LIFE)
    out = roam.take('192.0.2.40', '', record(status='Stop', user='alice', session='r1', stamp=T + 10), T, LIFE)
    check('roaming: ap1\'s Stop after ap2\'s Start ends nothing - ap2\'s open session of the same user holds the address',
          ([i for i in out if i[0] == 'end'], sorted(roam.sessions)), ([], ['r2']))
    out = roam.take('192.0.2.41', '', record(status='Stop', user='alice', session='r2', stamp=T + 20), T, LIFE)
    check('... ap2\'s Stop ends it', [i for i in out if i[0] == 'end'],
          [('end', '192.0.2.41', 'alice', '192.0.2.77', T + 20)])
    roam.take('192.0.2.40', '', record(user='bob', address='192.0.2.78', session='r3', stamp=T), T, LIFE)
    roam.take('192.0.2.40', '', record(user='carol', address='192.0.2.78', session='r4', stamp=T + 1), T, LIFE)
    out = roam.take('192.0.2.40', '', record(status='Stop', user='bob', address='192.0.2.78', session='r3',
                                             stamp=T + 2), T, LIFE)
    check('... another user\'s session on the address holds nothing for this one: its Stop ends it (the map decides)',
          [i for i in out if i[0] == 'end'], [('end', '192.0.2.40', 'bob', '192.0.2.78', T + 2)])

    # Accounting-On/-Off of one NAS behind a RADIUS server that forwards three (the review's third finding)
    fwd = radius.Accounting(path=os.path.join(tmp, 'fwd.json'), folder=os.path.join(tmp, 'none'))
    for n, user in ((1, 'alice'), (2, 'bob'), (3, 'carol')):
        fwd.take('192.0.2.5', '', record(user=user, address='192.0.2.6%d' % n, session='f%d' % n,
                                         **{'NAS-IP-Address': '198.51.100.%d' % n, 'NAS-Identifier': 'switch-%d' % n}),
                 T, LIFE)
    out = fwd.take('192.0.2.5', '', record(status='Accounting-On', user=None, address=None, stamp=T + 30,
                                            **{'NAS-IP-Address': '198.51.100.3'}), T, LIFE)
    check('Accounting-On of switch-3 behind a forwarding server: only switch-3\'s session ends, the others go on',
          ([i for i in out if i[0] == 'end'], sorted(fwd.sessions)),
          ([('end', '192.0.2.5', 'carol', '192.0.2.63', T + 30)], ['f1', 'f2']))
    out = fwd.take('192.0.2.5', '', {'Acct-Status-Type': 'Accounting-Off', 'Timestamp': str(int(T + 40)),
                                     'NAS-Identifier': 'switch-2'}, T, LIFE)
    check('... Accounting-Off naming its NAS by NAS-Identifier alone: that NAS\'s', [i[2] for i in out if i[0] == 'end'],
          ['bob'])
    out = fwd.take('192.0.2.5', '', {'Acct-Status-Type': 'Accounting-On', 'Timestamp': str(int(T + 50))}, T, LIFE)
    check('... one that names no NAS: every session of its client', ([i[2] for i in out if i[0] == 'end'], fwd.sessions),
          (['alice'], {}))

    # an Interim-Update is a renewal of what its session had, not a new logon (the review's ninth finding)
    again = radius.Accounting(path=os.path.join(tmp, 'again.json'), folder=os.path.join(tmp, 'none'))
    again.take('192.0.2.40', '', record(user='wifi-staff', address='192.0.2.80', session='w1', stamp=T), T, LIFE)
    out = again.take('192.0.2.40', '', record(status='Interim-Update', user='wifi-staff', address='192.0.2.80',
                                              session='w1', stamp=T + 600), T, LIFE)
    check('an Interim-Update of the address its session had: a renewal, with the session\'s logon time',
          [(i[0], i[3]) for i in out if i[0] in ('event', 'renew')], [('renew', T)])
    out = again.take('192.0.2.40', '', record(status='Interim-Update', user='wifi-staff', address='192.0.2.81',
                                              session='w1', stamp=T + 1200), T, LIFE)
    check('... of an address it did not have: a logon there, the old one ends',
          [(i[0], i[3] if i[0] == 'end' else i[2]['address']) for i in out if i[0] in ('event', 'renew', 'end')],
          [('end', '192.0.2.80'), ('event', '192.0.2.81')])
    out = again.take('192.0.2.40', '', record(status='Interim-Update', user='u2', address='192.0.2.81', session='w9',
                                              stamp=T + 1300), T, LIFE)
    check('... of a session never seen: a logon', [i[0] for i in out if i[0] in ('event', 'renew')], ['event'])

    # where the reading stands, put back when what was read could not be put in the map (the review's eighth finding)
    before = again.mark()
    again.take('192.0.2.40', '', record(status='Stop', user='wifi-staff', address=None, session='w1', stamp=T + 1400),
               T, LIFE)
    check('mark, then a Stop: the session gone', 'w1' in again.sessions, False)
    again.restore(before)
    check('... restore: the session open again, to be ended by the same Stop read again',
          again.sessions['w1']['addresses'], ['192.0.2.81'])

    # radius.json written at most every ten seconds while records come, and at the end (the review's sixth finding)
    writes = radius.Accounting(path=os.path.join(tmp, 'writes.json'), folder=os.path.join(tmp, 'none'))
    times = []
    for second, user in ((0, 'a1'), (3, 'a2'), (9, 'a3'), (10, 'a4'), (15, 'a5')):
        writes.take('192.0.2.40', '', record(user=user, session=user), T, LIFE)
        writes.save(T + second)
        times.append(sorted(engine.read_json(writes.path, {}).get('sessions', {})))
    check('radius.json written at the first record, then not again within ten seconds, then again',
          times, [['a1'], ['a1'], ['a1'], ['a1', 'a2', 'a3', 'a4'], ['a1', 'a2', 'a3', 'a4']])
    writes.save(T + 16, force=True)
    check('... and whatever is left when the collector stops', sorted(engine.read_json(writes.path, {})['sessions']),
          ['a1', 'a2', 'a3', 'a4', 'a5'])
    writes.save(T + 30)
    check('... nothing new, nothing written', writes.dirty, False)

    # the files, read as they grow
    folder = os.path.join(tmp, 'radacct')
    os.makedirs(os.path.join(folder, '127.0.0.1'))
    os.makedirs(os.path.join(folder, '192.0.2.40'))
    today = os.path.join(folder, '127.0.0.1', 'detail-20261117')
    with open(today, 'w', encoding='utf-8') as handle:
        handle.write(LAB)
    now = 1794950600.0
    os.utime(today, (now - 10, now - 10))
    yesterday = os.path.join(folder, '192.0.2.40', 'detail-20261116')
    with open(yesterday, 'w', encoding='utf-8') as handle:
        handle.write(LAB.replace('192.0.2.77', '192.0.2.99'))
    os.utime(yesterday, (now - 20 * 3600, now - 20 * 3600))
    # nothing takes old files away: a day a week before, and what an owner compressed, are never read
    old = os.path.join(folder, '192.0.2.40', 'detail-20261110')
    for path in (old, today + '.gz', os.path.join(folder, '127.0.0.1', 'reply-detail-20261117')):
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(LAB.replace('192.0.2.77', '192.0.2.98'))
        os.utime(path, (now - 10, now - 10))
    state = os.path.join(tmp, 'state.json')
    acct = radius.Accounting(path=state, folder=folder)
    check('found: the accounting directory there', (acct.found(), radius.Accounting(folder=os.path.join(tmp, 'none')).found()),
          (True, False))
    check('the days read: from the day before the lifetime began to the day after today',
          sorted(radius.days(now, LIFE)), ['detail-20261116', 'detail-20261117', 'detail-20261118'])
    got = acct.read(now, LIFE)
    check('a file never read, written within the lifetime: read whole, in order; yesterday\'s, written 20 hours ago: '
          'from its end; a day past the lifetime, a compressed file, another module\'s: not read at all',
          [(c, f['Acct-Status-Type'], f['Framed-IP-Address']) for c, _, f in got],
          [('127.0.0.1', 'Start', '192.0.2.77'), ('127.0.0.1', 'Interim-Update', '192.0.2.77'),
           ('127.0.0.1', 'Stop', '192.0.2.77')])
    check('... and only the files of the days read kept in radius.json, however many there are',
          sorted(os.path.basename(p) for p in acct.files), ['detail-20261116', 'detail-20261117'])
    check('read again: nothing new', acct.read(now + 1, LIFE), [])
    with open(yesterday, 'a', encoding='utf-8') as handle:
        handle.write(LAB.split('\n\n')[0].replace('"u1"', '"u5"') + '\n\nTue Nov 17 21:30:00 2026\n\tUser-Name = "u6"\n')
    got = acct.read(now + 2, LIFE)
    check('the file written 20 hours ago, written to again: only what came since, the record being written left',
          [f['User-Name'] for _, _, f in got], ['u5'])
    with open(yesterday, 'a', encoding='utf-8') as handle:
        handle.write('\tAcct-Status-Type = Start\n\n')
    check('... and taken once it is whole', [f['User-Name'] for _, _, f in acct.read(now + 3, LIFE)], ['u6'])
    acct.save()
    again = radius.Accounting(path=state, folder=folder)
    check('a restart: what was read kept - nothing read twice', again.read(now + 4, LIFE), [])
    with open(today, 'w', encoding='utf-8') as handle:
        handle.write(LAB.split('\n\n')[0] + '\n\n')
    check('a file cut short: read from its start', [f['Acct-Status-Type'] for _, _, f in again.read(now + 5, LIFE)], ['Start'])
    # made again under the same name, its first record another time line, as FreeRADIUS writes each record's own
    # time; the inode is the old one's as the reader last saw it - a file system may give a freed inode out at once
    # (it did on GitHub's runners), so only the file's first bytes tell the two apart
    os.unlink(today)
    with open(today, 'w', encoding='utf-8') as handle:
        handle.write(LAB.replace('Tue Nov 17', 'Wed Nov 18', 1) + LAB)
    again.files[today]['inode'] = os.stat(today).st_ino
    check('a file made again under the same name, the same inode number: read from its start',
          len(again.read(now + 6, LIFE)), 6)
    check('... and its first bytes kept for the next reading', str(again.files[today].get('head', '')).split(':')[0],
          str(radius.HEAD))
    with open(today, 'a', encoding='utf-8') as handle:
        handle.write(LAB.split('\n\n')[0] + '\n\n')
    check('... a record added to it: that record alone', len(again.read(now + 7, LIFE)), 1)
    os.unlink(yesterday)
    again.read(now + 7, LIFE)
    check('a file gone: forgotten', sorted(os.path.basename(p) for p in again.files), ['detail-20261117'])
    later = radius.Accounting(path=os.path.join(tmp, 'later.json'), folder=folder)
    later.files = dict(again.files)
    later.read(now + 3 * 86400, LIFE)
    check('three days on: the file of a day past the lifetime forgotten, never read again',
          sorted(os.path.basename(p) for p in later.files), [])
    big = os.path.join(folder, '192.0.2.40', 'detail-20261118')
    with open(big, 'w', encoding='utf-8') as handle:
        handle.write(LAB * 20)
    small = radius.Accounting(path=os.path.join(tmp, 'small.json'), folder=folder)
    small.files = dict(again.files)
    first = len(small.read(now + 8, LIFE, chunk=2000))
    second = len(small.read(now + 9, LIFE, chunk=2000))
    rest = 0
    for _ in range(100):
        part = len(small.read(now + 10, LIFE, chunk=2000))
        if not part:
            break
        rest += part
    check('a large file read a part at a time, every record once', (first > 0, second > 0, first + second + rest), (True, True, 60))
    out = radius.Accounting(path=os.path.join(tmp, 'poll.json'), folder=os.path.join(tmp, 'lab'))
    os.makedirs(os.path.join(tmp, 'lab', '127.0.0.1'))
    with open(os.path.join(tmp, 'lab', '127.0.0.1', 'detail-20261117'), 'w', encoding='utf-8') as handle:
        handle.write(LAB)
    os.utime(os.path.join(tmp, 'lab', '127.0.0.1', 'detail-20261117'), (now, now))
    done = [i for i in out.poll(now, LIFE) if i[0] in ('event', 'renew', 'end')]
    check('the lab\'s A9 played through: the Start maps, the Interim-Update renews, the Stop ends',
          [(i[0], i[3] if i[0] == 'end' else i[2]['id']) for i in done],
          [('event', 'Start'), ('renew', 'Interim-Update'), ('end', '192.0.2.77')])

# the portal's database
SCHEMA = '''
create table cp_clients (zoneid int, sessionid varchar, authenticated_via varchar, username varchar,
                         ip_address varchar, mac_address varchar, created number, deleted integer default (0),
                         primary key (zoneid, sessionid));
create table cp_client_ips (zoneid int not null, sessionid varchar not null, ip_address varchar not null,
                            primary key (zoneid, sessionid, ip_address));
'''


def database(path, sessions, roaming=(), schema=SCHEMA):
    if os.path.exists(path):
        os.unlink(path)
    connection = sqlite3.connect(path)
    connection.executescript(schema)
    connection.executemany('insert into cp_clients (zoneid, sessionid, authenticated_via, username, ip_address, '
                           'mac_address, created, deleted) values (?, ?, ?, ?, ?, ?, ?, ?)', sessions)
    if roaming:
        connection.executemany('insert into cp_client_ips (zoneid, sessionid, ip_address) values (?, ?, ?)', roaming)
    connection.commit()
    connection.close()


with tempfile.TemporaryDirectory() as tmp:
    db = os.path.join(tmp, 'captiveportal.sqlite')
    T = 1795082400.0
    zones = {'0': 'Guests', '2': 'Staff'}
    database(db, [(0, 'a', 'Example directory', 'User2', '192.0.2.88', '02:00:00:00:00:88', T, 0),
                  (0, 'b', 'Example directory', 'u3', '192.0.2.89', '', T, 1),
                  (1, 'c', 'Example directory', 'u4', '192.0.2.90', '', T, 0),
                  (2, 'd', '---ip---', '', '192.0.2.91', '', T, 0),
                  (2, 'e', 'Vouchers', 'k3xq9p', '192.0.2.92', '', T, 0),
                  (2, 'f', '', 'anonymous@192.0.2.93', '192.0.2.93', '', T, 0),
                  (2, 'g', 'Local Database', 'EXAMPLE\\U5', '', '', 'x', 0)],
             [(0, 'a', '2001:db8::88'), (0, 'a', '192.0.2.88'), (1, 'c', '2001:db8::90')])
    found, why = portal.read(zones, db)
    check('read: the sessions of the zones switched on, not those deleted, each with its roaming addresses',
          (why, sorted(found), found['0/a']['addresses'], found['0/a']['user'], found['0/a']['created']),
          ('', ['0/a', '2/d', '2/e', '2/f', '2/g'], ['192.0.2.88', '2001:db8::88'], 'user2', T))
    check('read: a name with its domain, a time that is none', (found['2/g']['user'], found['2/g']['domain'],
                                                                 found['2/g']['created']), ('u5', 'EXAMPLE', 0.0))
    check('refused: an allowed address, a voucher, a zone with no login, no address; a user\'s session not',
          [portal.refused(found[k], {'Vouchers'}) for k in ('2/d', '2/e', '2/f', '2/g', '0/a')],
          ['not a user', 'voucher', 'not a user', 'no address', ''])
    check('another directory: with Groups from chosen, a session another server let in - the Local Database - '
          'refused; one of the directory chosen taken; none chosen, none refused',
          [portal.refused(found['2/g'], {'Vouchers'}, 'Example directory'),
           portal.refused(dict(found['2/g'], addresses=['192.0.2.94']), {'Vouchers'}, 'Example directory'),
           portal.refused(found['0/a'], {'Vouchers'}, 'Example directory'),
           portal.refused(dict(found['2/g'], addresses=['192.0.2.94']), {'Vouchers'}, None),
           portal.refused(found['2/e'], {'Vouchers'}, 'Example directory')],
          ['another directory', 'another directory', '', '', 'voucher'])
    check('read: no database - no zone has run - no session', portal.read(zones, os.path.join(tmp, 'none')), ({}, ''))
    with open(os.path.join(tmp, 'bad.sqlite'), 'w') as handle:
        handle.write('not a database, but long enough to be read as one ' * 20)
    found, why = portal.read(zones, os.path.join(tmp, 'bad.sqlite'))
    check('read: a database that cannot be read - none, and why', (found, bool(why)), (None, True))
    database(db, [(0, 'a', 'Example directory', 'user2', '192.0.2.88', '', T, 0)],
             schema=SCHEMA.split('create table cp_client_ips')[0])
    check('read: a portal before its roaming addresses', portal.read(zones, db)[0]['0/a']['addresses'], ['192.0.2.88'])


def session(user, *addresses, zone='0', created=1795082400.0):
    return {'zone': zone, 'user': user, 'raw': user, 'domain': '', 'via': 'Example directory', 'created': created,
            'addresses': list(addresses)}


def play(state, ops, now):
    """The operations applied as the collector applies them."""
    for op in ops:
        if op[0] == 'see':
            engine.see(state, op[3], now, LIFE, op[2])
        elif op[0] == 'leave':
            engine.leave(state, op[3], op[4])
        else:
            engine.note(state, op[4], op[3], op[1], now, LIFE)


T = 1795082400.0
state = {'map': {'192.0.2.50': {'user': 'gone', 'kind': 'portal', 'source': '0', 'last': T - 100, 'others': {}},
                 '192.0.2.51': {'user': 'u7', 'kind': 'ad', 'source': '192.0.2.10', 'last': T - 100, 'others': {}}}}
listed = {'0/a': session('user2', '192.0.2.88', '2001:db8::88')}
ops = portal.reconcile(state, listed, None, T)
check('first reading: each address of a session mapped now; what the map holds of a session gone taken out, '
      'a domain controller\'s left', [(o[0], o[3]['address'] if o[0] == 'see' else o[4]) for o in ops],
      [('leave', '192.0.2.50'), ('see', '192.0.2.88'), ('see', '2001:db8::88')])
check('the events: the portal\'s, a logon, now', (ops[1][1], ops[1][2], ops[1][3]['kind'], ops[1][3]['id'], ops[1][3]['time']),
      ('portal', '0', 'portal', 'logon', T))
play(state, ops, T)
check('... applied: the session\'s addresses the user\'s, by the portal', sorted((w, e['user'], e['kind']) for w, e in state['map'].items()),
      [('192.0.2.51', 'u7', 'ad'), ('192.0.2.88', 'user2', 'portal'), ('2001:db8::88', 'user2', 'portal')])
check('the same sessions again: nothing to do', portal.reconcile(state, listed, listed, T + 2), [])
ops = portal.reconcile(state, listed, listed, T + 61)
check('a minute on: renewed', [(o[0], o[3]['address'], o[3]['time']) for o in ops],
      [('see', '192.0.2.88', T + 61), ('see', '2001:db8::88', T + 61)])
play(state, ops, T + 61)
fewer = {'0/a': session('user2', '192.0.2.88')}
ops = portal.reconcile(state, fewer, listed, T + 62)
check('a roaming address dropped: it leaves', ops, [('leave', 'portal', '0', 'user2', '2001:db8::88')])
play(state, ops, T + 62)
ops = portal.reconcile(state, listed, fewer, T + 63)
check('... added again: mapped', [(o[0], o[3]['address']) for o in ops], [('see', '2001:db8::88')])
play(state, ops, T + 63)
relogin = {'0/z': session('user2', '192.0.2.88', '2001:db8::88', created=T + 70)}
ops = portal.reconcile(state, relogin, listed, T + 70)
check('the user logs on again, a new session on the same addresses: no logoff, renewed',
      [(o[0], o[3]['address']) for o in ops], [('see', '192.0.2.88'), ('see', '2001:db8::88')])
play(state, ops, T + 70)
other = {'0/y': session('user8', '192.0.2.88', created=T + 80)}
ops = portal.reconcile(state, other, relogin, T + 80)
check('another user on the device: the one before leaves first, then the new one maps - no clash, no shared',
      [(o[0], o[3]['address'] if o[0] == 'see' else o[3]) for o in ops],
      [('leave', 'user2'), ('leave', 'user2'), ('see', '192.0.2.88')])
play(state, ops, T + 80)
check('... applied', (state['map']['192.0.2.88']['user'], state['map']['192.0.2.88']['others'], '2001:db8::88' in state['map']),
      ('user8', {}, False))
ops = portal.reconcile(state, {}, other, T + 90)
check('the session ends: its address leaves', ops, [('leave', 'portal', '0', 'user8', '192.0.2.88')])
play(state, ops, T + 90)

# latest wins against another source, and the clash kept while both say so
state = {'map': {}}
engine.see(state, {'id': 4768, 'kind': 'ad', 'user': 'u1', 'address': '192.0.2.88', 'time': T}, T, LIFE, '192.0.2.10')
late = {'0/a': session('user2', '192.0.2.88', created=T - 300)}
ops = portal.reconcile(state, late, None, T + 5)
check('a session older than the other source\'s last event: weighed by its logon\'s time',
      [(o[0], o[3]['time']) for o in ops], [('see', T - 300)])
play(state, ops, T + 5)
entry = state['map']['192.0.2.88']
check('... the later event keeps the address, the portal\'s user among the others: a clash',
      (entry['user'], entry['others'], entry['via'], engine.clash(entry, T + 5, LIFE)),
      ('u1', {'user2': T - 300}, {'user2': 'portal'}, ['user2']))
ops = portal.reconcile(state, late, late, T + 10)
check('the next reading: the note made now, so the clash lasts as long as the session, not from its logon',
      ops, [('note', 'portal', '0', 'user2', '192.0.2.88')])
play(state, ops, T + 10)
check('the same session again within the minute: nothing', portal.reconcile(state, late, late, T + 30), [])
ops = portal.reconcile(state, late, late, T + 300)
check('later: noted again, not taken back', ops, [('note', 'portal', '0', 'user2', '192.0.2.88')])
play(state, ops, T + 300)
check('... the clash still shown', (entry['user'], entry['others']['user2'], engine.clash(entry, T + LIFE, LIFE)),
      ('u1', T + 300, ['user2']))
del state['map']['192.0.2.88']
ops = portal.reconcile(state, late, late, T + 400)
check('the other mapping gone - forgotten, or its lifetime over: the session\'s user has the address again',
      [(o[0], o[3]['user'], o[3]['time']) for o in ops], [('see', 'user2', T + 400)])
early = {'0/b': session('user3', '192.0.2.95', created=T + 30)}
state = {'map': {}}
engine.see(state, {'id': 4624, 'kind': 'ad', 'user': 'u1', 'address': '192.0.2.95', 'time': T}, T, LIFE, '192.0.2.10')
play(state, portal.reconcile(state, early, None, T + 31), T + 31)
check('a logon later than the other source\'s last event: the portal\'s user takes the address, the other noted',
      (state['map']['192.0.2.95']['user'], state['map']['192.0.2.95']['kind'], state['map']['192.0.2.95']['via']),
      ('user3', 'portal', {'u1': 'ad'}))

VOLT = open(os.path.join(ROOT, 'src', 'opnsense', 'mvc', 'app', 'views', 'OPNsense', 'UserIdentity', 'index.volt'),
            encoding='utf-8').read()
NAMED = VOLT.split('const reasons = {', 1)[1].split('};', 1)[0]
check('every reason RADIUS and the portal refuse for is one the page names in its words',
      [reason for reason in ('unreadable', 'no time', 'not a user', 'computer', 'mac authentication', 'no address',
                             'not a client address', 'not a named client', 'another directory', 'voucher')
       if "'%s':" % reason not in NAMED], [])

print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
