#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""events.py against the lines NXLog CE sent in phase 0's lab (tools/fixtures/lab-events.txt, every
address a documentation one and every name an example) and against lines made from them: what maps,
what is counted and goes no further, and why each refused line is refused.

    python3 tools/test-events.py"""
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src', 'opnsense', 'scripts', 'useridentity'))
import events                                                            # noqa: E402

failures = 0
checks = 0


def check(name, got, want):
    global failures, checks
    checks += 1
    ok = got == want
    failures += 0 if ok else 1
    print('%s %s%s' % ('ok  ' if ok else 'FAIL', name, '' if ok else ' - got %r, want %r' % (got, want)))


def fixture():
    """{name: (arrival, sender, line)} of the lab's lines."""
    out, name = {}, None
    with open(os.path.join(ROOT, 'tools', 'fixtures', 'lab-events.txt'), encoding='utf-8') as handle:
        for line in handle:
            line = line.rstrip('\n')
            if line.startswith('#= '):
                name = line[3:].strip()
            elif line and not line.startswith('#') and name:
                arrival, sender, message = line.split(' ', 2)
                out[name] = (arrival, sender, message)
                name = None
    return out


def stamp(text):
    """The listener's arrival time, 2026-11-17T18:41:35.123Z, as a timestamp."""
    return time.mktime(time.strptime(text[:19], '%Y-%m-%dT%H:%M:%S')) + float(text[19:-1] or 0)


def edited(message, **changes):
    """The line with fields changed; a field given as None is taken out."""
    found = json.loads(message[message.find('{'):])
    for key, value in changes.items():
        if value is None:
            found.pop(key, None)
        else:
            found[key] = value
    return json.dumps(found, separators=(',', ':'))


def kind(result):
    return result[0] if result[0] != 'event' else ('event', result[1]['user'], result[1]['address'], result[1]['id'])


# The lab's domain controller kept UTC, and the firewall reads EventTime in its own zone: here, UTC too.
os.environ['TZ'] = 'UTC'
time.tzset()

LAB = fixture()
check('the fixture: 25 lines, each named', len(LAB), 25)

WANT = {
    'computer-link-local': ('refused', 'computer'),
    'virtual-account': ('refused', 'not a user'),
    'logoff': ('other', 4634),
    'computer-loopback': ('refused', 'computer'),
    'computer-pc': ('refused', 'computer'),
    'ticket-user1': ('event', 'user1', '192.0.2.20', 4768),
    'service-ticket-user1': ('other', 4769),
    'ticket-user2': ('event', 'user2', '192.0.2.20', 4768),
    'ticket-user3': ('event', 'user3', '192.0.2.20', 4768),
    'forged': ('refused', 'failed'),
    'service-ticket-dc': ('other', 4769),
    'ticket-computer': ('refused', 'computer'),
    'logon-user1': ('event', 'user1', '192.0.2.20', 4624),
    'logon-user1-no-address': ('refused', 'no address'),
    'logon-user2': ('event', 'user2', '192.0.2.20', 4624),
    'logon-bind-from-firewall': ('event', 'svc-bind', '192.0.2.1', 4624),
    'logon-system': ('refused', 'not a user'),
    'renewal-user2': ('event', 'user2', '192.0.2.20', 4624),
    'runas-computer-1': ('refused', 'computer'),
    'runas-user1': ('event', 'user1', '192.0.2.20', 4768),
    'runas-computer-2': ('refused', 'computer'),
    'runas-user2': ('event', 'user2', '192.0.2.20', 4768),
    'runas-computer-3': ('refused', 'computer'),
    'runas-user3': ('event', 'user3', '192.0.2.20', 4768),
    'resent-user1-from-firewall': ('event', 'user1', '192.0.2.1', 4624),
}
for name, want in WANT.items():
    result = events.parse(LAB[name][2])
    check('lab line %s: %s' % (name, ' '.join(str(w) for w in want)),
          kind(result) if result[0] == 'event' else result, want)

found = events.parse(LAB['ticket-user1'][2])[1]
check('a ticket: the domain, the event\'s own time, the domain controller\'s name',
      (found['domain'], found['time'], found['hostname'], found['logon_type']),
      ('EXAMPLE', time.mktime((2026, 11, 17, 18, 41, 33, 0, 0, -1)), 'DC1.example.test', ''))
found = events.parse(LAB['logon-user1'][2])[1]
check('a network logon: its type kept', (found['domain'], found['logon_type']), ('EXAMPLE.TEST', '3'))

# what syslog-ng hands over: "$SOURCEIP $MSG"
sender, message = events.split(('192.0.2.10 ' + LAB['ticket-user1'][2] + '\n').encode())
check('split: the sender and the line, its end of line gone', (sender, message), ('192.0.2.10', LAB['ticket-user1'][2]))
check('split: a datagram with no line', events.split(b'192.0.2.10'), ('192.0.2.10', ''))

# made from the lab's lines
TICKET = LAB['ticket-user1'][2]
LOGON = LAB['logon-user1'][2]
cases = [
    ('a ticket refused by the KDC, Status 0x6', edited(TICKET, Status='0x6'), ('refused', 'failed')),
    ('a ticket with Status 0x12', edited(TICKET, Status='0x12'), ('refused', 'failed')),
    ('a ticket with no Status', edited(TICKET, Status=None), ('refused', 'failed')),
    ('a ticket issued with no pre-authentication (PreAuthType 0): anyone could have asked it',
     edited(TICKET, PreAuthType='0'), ('refused', 'no pre-authentication')),
    ('a ticket pre-authenticated by password (PreAuthType 2, as the lab\'s)', edited(TICKET, PreAuthType='2'),
     ('event', 'user1', '192.0.2.20', 4768)),
    ('a ticket pre-authenticated by a certificate (PreAuthType 16)', edited(TICKET, PreAuthType='16'),
     ('event', 'user1', '192.0.2.20', 4768)),
    ('a ticket with no PreAuthType field: not known, taken', edited(TICKET, PreAuthType=None),
     ('event', 'user1', '192.0.2.20', 4768)),
    ('a network logon with a PreAuthType of 0 (no such field in a 4624): taken', edited(LOGON, PreAuthType='0'),
     ('event', 'user1', '192.0.2.20', 4624)),
    ('a ticket from ::1, the domain controller itself', edited(TICKET, IpAddress='::1'),
     ('refused', 'not a client address')),
    ('a ticket from 127.0.0.1', edited(TICKET, IpAddress='127.0.0.1'), ('refused', 'not a client address')),
    ('a ticket from a link-local address with its zone', edited(TICKET, IpAddress='fe80::db8:2%5'),
     ('refused', 'not a client address')),
    ('a ticket from a multicast address', edited(TICKET, IpAddress='224.0.0.251'), ('refused', 'not a client address')),
    ('a ticket from the limited broadcast', edited(TICKET, IpAddress='255.255.255.255'),
     ('refused', 'not a client address')),
    ('a ticket from 0.0.0.0', edited(TICKET, IpAddress='0.0.0.0'), ('refused', 'not a client address')),
    ('a ticket from ::ffff:0.0.0.0', edited(TICKET, IpAddress='::ffff:0.0.0.0'), ('refused', 'not a client address')),
    ('a ticket from an address that is none', edited(TICKET, IpAddress='PC1'), ('refused', 'no address')),
    ('a ticket with no IpAddress', edited(TICKET, IpAddress=None), ('refused', 'no address')),
    ('a ticket from an IPv6 client', edited(TICKET, IpAddress='2001:db8::20'), ('event', 'user1', '2001:db8::20', 4768)),
    ('a ticket from an IPv6 client written in capitals', edited(TICKET, IpAddress='2001:DB8:0:0::20'),
     ('event', 'user1', '2001:db8::20', 4768)),
    ('a name written user@REALM', edited(TICKET, TargetUserName='User1@EXAMPLE.TEST'), ('event', 'user1', '192.0.2.20', 4768)),
    ('a name written DOMAIN\\name', edited(TICKET, TargetUserName='EXAMPLE\\User1'), ('event', 'user1', '192.0.2.20', 4768)),
    ('ANONYMOUS LOGON with no SID', edited(LOGON, TargetUserName='ANONYMOUS LOGON', TargetUserSid=None),
     ('refused', 'not a user')),
    ('a logon with no name', edited(LOGON, TargetUserName='-'), ('refused', 'not a user')),
    ('a logon whose SID is no domain account\'s', edited(LOGON, TargetUserSid='S-1-5-7'), ('refused', 'not a user')),
    ('a logon with no SID: the name decides', edited(LOGON, TargetUserSid=None), ('event', 'user1', '192.0.2.20', 4624)),
    ('a managed service account, its name ending with $', edited(LOGON, TargetUserName='svc-web$'),
     ('refused', 'computer')),
    ('a logon with no EventTime', edited(LOGON, EventTime=None), ('refused', 'no time')),
    ('a logon whose EventTime cannot be read', edited(LOGON, EventTime='yesterday'), ('refused', 'no time')),
    ('the EventID as a string', edited(LOGON, EventID='4624'), ('event', 'user1', '192.0.2.20', 4624)),
    ('an event of another ID: counted', edited(LOGON, EventID=4647), ('other', 4647)),
    ('no EventID', edited(LOGON, EventID=None), ('refused', 'unreadable')),
    ('a line that is not JSON', 'the event log service stopped', ('refused', 'unreadable')),
    ('a line cut short', TICKET[:400], ('refused', 'unreadable')),
    ('a JSON array', '[1, 2]', ('refused', 'unreadable')),
    ('an empty line', '', ('refused', 'unreadable')),
]
for name, line, want in cases:
    result = events.parse(line)
    check(name, kind(result) if result[0] == 'event' else result, want)

framed = '<14>Nov 17 18:41:35 DC1.example.test MSWinEventLog 1 Security 1 ' + TICKET
check('the same ticket after a syslog header: the JSON after it read', kind(events.parse(framed)),
      ('event', 'user1', '192.0.2.20', 4768))

# EventTime: NXLog CE's own form in the firewall's zone; ISO with a zone as it says; a number as it is
check('EventTime "2026-11-17 18:41:33" in UTC', events.event_time('2026-11-17 18:41:33'), 1794940893.0)
os.environ['TZ'] = 'Asia/Dubai'
time.tzset()
check('the same EventTime read in UTC+4: four hours earlier', events.event_time('2026-11-17 18:41:33'),
      1794940893.0 - 4 * 3600)
check('an ISO time with Z: as it says, whatever the zone', events.event_time('2026-11-17T18:41:33Z'), 1794940893.0)
check('an ISO time with +04:00', events.event_time('2026-11-17T22:41:33.5+04:00'), 1794940893.5)
check('an ISO time with -0130', events.event_time('2026-11-17T17:11:33-0130'), 1794940893.0)
os.environ['TZ'] = 'UTC'
time.tzset()
check('a timestamp as it is', events.event_time(1794940893), 1794940893.0)
check('true is no time', events.event_time(True), None)
check('a date that does not exist', events.event_time('2026-02-30 10:00:00'), None)

# judge(): what may map, and why not
context = events.Context(dcs=['192.0.2.10', '192.0.2.11'], stale=300, own=['192.0.2.1', '2001:db8::1'],
                         broadcast=['192.0.2.255'], never_map=[events.ipaddress.ip_network('198.51.100.0/24'),
                                                               events.ipaddress.ip_network('2001:db8:1::/48')],
                         ignore=['svc-backup'])
ticket = events.parse(TICKET)[1]


def judged(arrival_offset=2.0, **change):
    event = dict(ticket, **change)
    return events.judge(event, event['time'] + arrival_offset, context)


check('a ticket 2 s old from a named domain controller: may map', judged(), None)
check('an event 300 s old: may map', judged(300), None)
check('an event 301 s old: stale', judged(301), 'stale')
check('an event 301 s ahead of the firewall\'s clock: refused as such', judged(-301), 'clock')
check('an event 300 s ahead: may map', judged(-300), None)
check('the firewall\'s own address', judged(address='192.0.2.1'), 'firewall')
check('the firewall\'s own IPv6 address', judged(address='2001:db8::1'), 'firewall')
check('the broadcast of a network of the firewall\'s', judged(address='192.0.2.255'), 'firewall')
check('a domain controller\'s own address', judged(address='192.0.2.11'), 'domain controller')
check('an address of Never map', judged(address='198.51.100.7'), 'never map')
check('an IPv6 address of Never map', judged(address='2001:db8:1::7'), 'never map')
check('an IPv6 address outside it', judged(address='2001:db8:2::7'), None)
check('a user of Ignore users', judged(user='svc-backup'), 'ignored')
resent = LAB['resent-user1-from-firewall']
event = events.parse(resent[2])[1]
check('the lab\'s A4: a logon sent again ten minutes late, from the firewall itself - stale',
      events.judge(event, stamp(resent[0]), context), 'stale')
check('the same with the stale setting at 15 minutes - the firewall\'s own address',
      events.judge(event, stamp(resent[0]), events.Context(dcs=['192.0.2.10'], stale=900, own=['192.0.2.1'])), 'firewall')
for name in ('ticket-user1', 'logon-user1', 'renewal-user2', 'runas-user3'):
    arrival, sender, message = LAB[name]
    check('lab line %s, as it arrived: may map' % name, events.judge(events.parse(message)[1], stamp(arrival), context),
          None)
check('every reason judge() and parse() give is one the page knows',
      {'stale', 'clock', 'firewall', 'domain controller', 'never map', 'ignored', 'failed', 'computer', 'not a user',
       'no address', 'not a client address', 'no time', 'unreadable', 'not a domain controller',
       'no pre-authentication'} - set(events.REFUSED), set())
check('the lab\'s tickets issued to users: each pre-authenticated, PreAuthType 2',
      sorted({json.loads(LAB[name][2][LAB[name][2].find('{'):]).get('PreAuthType') for name in LAB
              if name.startswith(('ticket-user', 'runas-user'))}), ['2'])
VOLT = open(os.path.join(ROOT, 'src', 'opnsense', 'mvc', 'app', 'views', 'OPNsense', 'UserIdentity', 'index.volt'),
            encoding='utf-8').read()
check('the page names the reason no pre-authentication', "'no pre-authentication':" in VOLT, True)

print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
