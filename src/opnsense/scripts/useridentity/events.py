#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""One message from a domain controller, as syslog-ng hands it to the collector: the sender's address,
a space, and the line NXLog CE sent - an event of the Windows Security log as JSON (im_msvistalog and
xm_json's to_json()), with or without a syslog header before it.

Two events map an address to a user, as phase 0's lab saw them arrive from a Windows Server 2025
domain controller (its A2):

  4768  a ticket-granting ticket issued (Status 0x0): the user, and the address the client asked
        from, IpAddress, written ::ffff:a.b.c.d for IPv4. A logon gives one, 1.5 to 2.4 s after it,
        and so does an unlock.
  4624  a logon to the domain controller itself: type 3 (network) bursts are what renews an idle
        session - an idle hour gave 37 lines about one user, the longest gap 22 minutes. IpAddress
        is plain IPv4, or '-' when the logon has none.

Nothing says a user left: a lock and a logoff send nothing that does, and 4634 (logoff) carries no
address. Every other event is counted by its ID and goes no further.

    split(datagram)                   (sender, message)
    parse(message)                    ('event', {...}) | ('other', event id) | ('refused', reason)
    judge(event, arrival, context)    None when the event may map, else the reason it may not

Refused, each counted on the page by its reason: a line that is not JSON; a ticket not issued; a
computer account (its name ends with $ - every logon through a task or runas gives one first); an
account that is not a domain user (its SID is not S-1-5-21-..., as SYSTEM, ANONYMOUS LOGON and the
virtual accounts); no address, or one that is no client's (loopback, link-local, multicast,
unspecified, broadcast); no event time.

And, by judge(): an event older than the stale setting when it arrives - NXLog CE sends again what it
held while stopped, ten minutes old in the lab's A4 - or as far ahead of the firewall's clock; the
firewall's own address (OPNsense's own LDAP connector binds as a user from it, A4), a domain
controller's, one of Never map's; a user of Ignore users. Before any of it the collector refuses a
line whose sender is not a domain controller named in Settings: the redirect lets no other sender in
from the network, but a process on the firewall itself could reach syslog-ng's source.
"""

import datetime
import ipaddress
import json
import re
import time

MAPPING = (4768, 4624)

REFUSED = ('unreadable', 'failed', 'computer', 'not a user', 'no address', 'not a client address', 'no time',
           'not a domain controller', 'stale', 'clock', 'firewall', 'domain controller', 'never map', 'ignored')

NOT_USERS = ('anonymous logon', '-', '')
LIMITED = ipaddress.ip_address('255.255.255.255')
WHEN = re.compile(r'^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$')


def split(datagram):
    """(sender, message) of what syslog-ng sends: its template is "$SOURCEIP $MSG"."""
    text = datagram.decode('utf-8', 'replace') if isinstance(datagram, bytes) else str(datagram)
    sender, _, message = text.partition(' ')
    return sender.strip(), message.strip('\r\n\x00 ')


def user_name(raw):
    """The account's bare name, lower case: 'DOMAIN\\name' and 'name@REALM' are written both ways."""
    name = str(raw or '').strip()
    if '\\' in name:
        name = name.rsplit('\\', 1)[1]
    if '@' in name:
        name = name.split('@', 1)[0]
    return name.strip().lower()


def address(raw):
    """The address as the firewall writes it - ::ffff:a.b.c.d made a.b.c.d, a zone dropped - or None."""
    text = str(raw or '').strip()
    if not text or text == '-':
        return None
    text = text.split('%', 1)[0]
    try:
        found = ipaddress.ip_address(text)
    except ValueError:
        return None
    if found.version == 6 and found.ipv4_mapped is not None:
        found = found.ipv4_mapped
    return str(found)


def no_client(text):
    """True when the address can be no client's: loopback, link-local, multicast, unspecified, reserved,
    or the limited broadcast."""
    found = ipaddress.ip_address(text)
    return (found.is_loopback or found.is_link_local or found.is_multicast or found.is_unspecified
            or found == LIMITED or (found.version == 4 and found.is_reserved))


def event_time(raw):
    """The event's own time as a timestamp. NXLog CE writes EventTime as the domain controller's local
    time with no zone, 'YYYY-MM-DD hh:mm:ss': it is read in the firewall's own zone, so the two must
    keep one. An ISO time with a zone, or a number, is taken as it is. None when it cannot be read."""
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        return float(raw)
    found = WHEN.match(str(raw or '').strip())
    if not found:
        return None
    year, month, day, hour, minute, second = (int(found.group(i)) for i in range(1, 7))
    fraction = float(found.group(7) or 0)
    zone = found.group(8)
    try:
        if zone:
            if zone == 'Z':
                offset = datetime.timedelta(0)
            else:
                digits = zone.replace(':', '')
                offset = datetime.timedelta(hours=int(digits[1:3]), minutes=int(digits[3:5]))
                offset = -offset if digits[0] == '-' else offset
            stamp = datetime.datetime(year, month, day, hour, minute, second,
                                      tzinfo=datetime.timezone(offset)).timestamp()
        else:
            stamp = time.mktime(datetime.datetime(year, month, day, hour, minute, second).timetuple())
    except (ValueError, OverflowError):
        return None
    return stamp + fraction


def parse(message):
    """What one message says - see the top."""
    start = message.find('{')
    if start < 0:
        return 'refused', 'unreadable'
    try:
        found = json.loads(message[start:])
    except ValueError:
        return 'refused', 'unreadable'
    if not isinstance(found, dict):
        return 'refused', 'unreadable'
    try:
        number = int(found.get('EventID'))
    except (TypeError, ValueError):
        return 'refused', 'unreadable'
    if number not in MAPPING:
        return 'other', number
    if number == 4768 and str(found.get('Status', '')).strip().lower() not in ('0x0', '0'):
        return 'refused', 'failed'
    raw_user = str(found.get('TargetUserName') or '')
    user = user_name(raw_user)
    if user.endswith('$'):
        return 'refused', 'computer'
    sid = str(found.get('TargetUserSid') or found.get('TargetSid') or '').strip()
    if user in NOT_USERS or (sid.startswith('S-1-') and not sid.startswith('S-1-5-21-')):
        return 'refused', 'not a user'
    where = address(found.get('IpAddress'))
    if where is None:
        return 'refused', 'no address'
    if no_client(where):
        return 'refused', 'not a client address'
    when = event_time(found.get('EventTime'))
    if when is None:
        return 'refused', 'no time'
    return 'event', {
        'id': number,
        'user': user,
        'domain': str(found.get('TargetDomainName') or '').strip(),
        'address': where,
        'time': when,
        'logon_type': str(found.get('LogonType') or ''),
        'hostname': str(found.get('Hostname') or '').strip(),
    }


class Context:
    """What judge() needs to know of the firewall and of Settings."""

    def __init__(self, dcs=(), stale=300, own=(), broadcast=(), never_map=(), ignore=()):
        self.dcs = set(dcs)
        self.stale = stale
        self.own = {ipaddress.ip_address(a) for a in own}
        self.broadcast = {ipaddress.ip_address(a) for a in broadcast}
        self.never_map = list(never_map)
        self.ignore = {name.lower() for name in ignore}


def judge(event, arrival, context):
    """None when the event, arrived at arrival, may map its address; else why not."""
    age = arrival - event['time']
    if age > context.stale:
        return 'stale'
    if -age > context.stale:
        return 'clock'
    where = ipaddress.ip_address(event['address'])
    if where in context.own or where in context.broadcast:
        return 'firewall'
    if event['address'] in context.dcs:
        return 'domain controller'
    if any(where in net for net in context.never_map if net.version == where.version):
        return 'never map'
    if event['user'] in context.ignore:
        return 'ignored'
    return None
