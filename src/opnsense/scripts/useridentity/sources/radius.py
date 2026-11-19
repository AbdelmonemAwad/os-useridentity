#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""RADIUS accounting as a source (the plan's top-03): the accounting records os-freeradius writes,
read as they are written.

os-freeradius sends every Accounting-Request through FreeRADIUS's detail module, which appends it to
/var/log/radacct/<client>/detail-YYYYMMDD - <client> the address the request came from, one file a
day, 0600 root:freeradius, written in the second the request comes (phase 0's A9: os-freeradius
1.10.3 with freeradius3 3.2.10, on the second XGS 3300). A record is a line with the time, then one
attribute a line, each after a tab, then an empty line:

    Tue Nov 17 21:21:49 2026
            User-Name = "u1"
            Acct-Status-Type = Stop
            Acct-Session-Id = "p0-a9-1"
            Framed-IP-Address = 192.0.2.77
            NAS-IP-Address = 127.0.0.1
            Calling-Station-Id = "02-00-00-00-a9-01"
            Event-Timestamp = "Nov 17 2026 21:21:49 UTC"
            Acct-Unique-Session-Id = "38950487608e4f75190df8111cf4a78a"
            Timestamp = 1794950509

A request reaches the detail module only from a client FreeRADIUS knows, by the secret the two share:
the clients of Services: FreeRADIUS are the gate here, as the redirect is the domain controllers'. A
NAS, or another RADIUS server that forwards its accounting to this one, is one of them.

What a record does:

  Start, Interim-Update   the session's user on its Framed-IP-Address and Framed-IPv6-Address: a Start
                          maps them, each Interim-Update renews them - a NAS that sends none leaves the
                          mapping to the lifetime's end, even while the session goes on
  Stop                    the session's addresses leave the map, when they are still its user's
  Accounting-On, -Off     the NAS started again, or stopped: every session it had ends

Refused, each counted on the page by its reason: a record with no Acct-Status-Type, or no time; no
user, or one that names nobody - anonymous, the outer name of an EAP client that hides its own; a
computer (host/... or a name ending in $); a MAC address as the name (MAC authentication); no
address, or none that is a client's. The collector then judges each address as it judges a domain
controller's event: the firewall's own, a domain controller's, Never map's, a user of Ignore users,
and a record older than the mapping lifetime when it is read (stale: its mapping would end at once).

A record's time is the time FreeRADIUS wrote it (its Timestamp), less the seconds the NAS said it
waited before sending (Acct-Delay-Time): the firewall's own clock, never the NAS's.

What was read of each file, and the sessions open, are kept in /var/db/os-useridentity/radius.json:
the collector goes on where it stopped, and what came while it was down is read then, in order. A
file it never read is read whole when it was written to within the lifetime, else from its end.
"""

import glob
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import engine                                                            # noqa: E402
import events                                                            # noqa: E402

RADACCT = '/var/log/radacct'
STATE = engine.STATE + '/radius.json'
CHUNK = 4 << 20         # bytes of one file read at a time: what is left, at the next reading

STATUS = {'start': 'start', '1': 'start', 'interim-update': 'interim', 'alive': 'interim', '3': 'interim',
          'stop': 'stop', '2': 'stop', 'accounting-on': 'on', '7': 'on', 'accounting-off': 'off', '8': 'off'}
NAMES = {'start': 'Start', 'interim': 'Interim-Update', 'stop': 'Stop', 'on': 'Accounting-On',
         'off': 'Accounting-Off'}
ADDRESSES = ('Framed-IP-Address', 'Framed-IPv6-Address')
NOBODY = ('', '-', 'anonymous')
SEPARATORS = re.compile(r'[-:.]')
HEX12 = re.compile(r'^[0-9a-f]{12}$')
OCTAL = re.compile(r'^[0-7]{3}')


def unquote(value):
    """A value as the detail module writes it: a string in double quotes, with \\\\, \\", \\n, \\r, \\t
    and \\ooo (octal) for what is not printable; anything else as it is."""
    value = value.strip()
    if len(value) < 2 or value[0] != '"' or value[-1] != '"':
        return value
    body, out, i = value[1:-1], [], 0
    while i < len(body):
        char = body[i]
        if char == '\\' and i + 1 < len(body):
            following = body[i + 1]
            if OCTAL.match(body[i + 1:i + 4]):
                out.append(chr(int(body[i + 1:i + 4], 8)))
                i += 4
                continue
            out.append({'n': '\n', 'r': '\r', 't': '\t'}.get(following, following))
            i += 2
            continue
        out.append(char)
        i += 1
    return ''.join(out)


def split(data):
    """([record text], bytes taken) of what was read: the complete records - each ends with an empty
    line; one being written is left for the next reading."""
    end = data.rfind(b'\n\n')
    if end < 0:
        return [], 0
    texts = [piece.decode('utf-8', 'replace').strip('\n') for piece in data[:end].split(b'\n\n')]
    return [text for text in texts if text.strip()], end + 2


def parse(text):
    """(time line, {attribute: value}) of one record; an attribute given twice keeps its first value."""
    lines = text.split('\n')
    header = ''
    if lines and lines[0][:1] not in ('\t', ' '):
        header = lines.pop(0).strip()
    found = {}
    for line in lines:
        if line[:1] not in ('\t', ' '):
            continue
        name, sep, value = line.strip().partition(' = ')
        if sep and name and name not in found:
            found[name] = unquote(value)
    return header, found


def is_mac(name):
    """True when a user's name is a MAC address - 020000a90001, 02-00-00-00-a9-01, 02:00:..., 0200.00a9.0001:
    what a NAS sends for a device let in by its MAC alone."""
    return len(name) in (12, 14, 17) and HEX12.match(SEPARATORS.sub('', name)) is not None


def record_time(header, found):
    """The record's time - see the top - or None when it has none that can be read."""
    stamp = found.get('Timestamp', '').strip()
    if stamp.isdigit():
        when = float(stamp)
    else:
        try:
            when = time.mktime(time.strptime(header, '%a %b %d %H:%M:%S %Y'))
        except (ValueError, OverflowError):
            return None
    delay = found.get('Acct-Delay-Time', '').strip()
    if delay.isdigit():
        when -= int(delay)
    return when


def interpret(client, header, found):
    """What one record says: (status, record) with status start, interim, stop, on or off; ('other',
    the status as written) for a status that maps nothing; ('refused', reason). The record:
    {'status', 'name', 'time', 'nas', 'hostname', 'session', 'user', 'domain', 'addresses'}."""
    raw = found.get('Acct-Status-Type', '').strip()
    if not raw:
        return 'refused', 'unreadable'
    status = STATUS.get(raw.lower())
    if status is None:
        return 'other', raw
    when = record_time(header, found)
    if when is None:
        return 'refused', 'no time'
    record = {'status': status, 'name': NAMES[status], 'time': when, 'nas': client,
              'hostname': (found.get('NAS-Identifier') or found.get('NAS-IP-Address') or '').strip()}
    if status in ('on', 'off'):
        return status, record
    record['session'] = found.get('Acct-Unique-Session-Id') or '|'.join(
        (client, found.get('NAS-IP-Address', ''), found.get('NAS-Identifier', ''), found.get('Acct-Session-Id', '')))
    raw_user = found.get('User-Name', '')
    user = events.user_name(raw_user)
    if user in NOBODY:
        return 'refused', 'not a user'
    if user.startswith('host/') or user.endswith('$'):
        return 'refused', 'computer'
    if is_mac(user):
        return 'refused', 'mac authentication'
    addresses = []
    for name in ADDRESSES:
        where = events.address(found.get(name))
        if where is not None and where not in addresses:
            addresses.append(where)
    record.update(user=user, domain=events.domain_of(raw_user), addresses=addresses)
    return status, record


def event(record, where):
    """The event the engine takes for one address of a Start or an Interim-Update."""
    return {'id': record['name'], 'kind': 'radius', 'user': record['user'], 'domain': record['domain'],
            'address': where, 'time': record['time'], 'logon_type': '', 'hostname': record['hostname']}


class Accounting:
    """The detail files read, and the sessions open: {session: {'nas', 'user', 'addresses', 'last'}}."""

    def __init__(self, path=None, folder=None):
        self.path = path or STATE
        self.folder = folder or RADACCT
        found = engine.read_json(self.path, {})
        self.files = found.get('files') if isinstance(found.get('files'), dict) else {}
        self.sessions = found.get('sessions') if isinstance(found.get('sessions'), dict) else {}
        self.dirty = False

    def found(self):
        """Whether os-freeradius's accounting directory is there."""
        return os.path.isdir(self.folder)

    def read(self, now, lifetime, chunk=CHUNK):
        """[(client, time line, {attribute: value})] of the records written since the last reading, the
        files of each client in their days' order."""
        out = []
        paths = sorted(glob.glob(os.path.join(self.folder, '*', 'detail-*')))
        for path in paths:
            try:
                stat = os.stat(path)
            except OSError:
                continue
            known = self.files.get(path)
            if known is None:
                offset = 0 if stat.st_mtime >= now - lifetime else stat.st_size
            elif known.get('inode') != stat.st_ino or stat.st_size < known.get('offset', 0):
                offset = 0          # a file made again under the same name, or cut short: read from its start
            else:
                offset = known['offset']
            if offset < stat.st_size:
                try:
                    with open(path, 'rb') as handle:
                        handle.seek(offset)
                        texts, used = split(handle.read(chunk))
                except OSError:
                    continue
                offset += used
                client = os.path.basename(os.path.dirname(path))
                for text in texts:
                    header, found = parse(text)
                    out.append((client, header, found))
            mark = {'inode': stat.st_ino, 'offset': offset}
            if known != mark:
                self.files[path] = mark
                self.dirty = True
        there = set(paths)
        for path in [p for p in self.files if p not in there]:
            del self.files[path]
            self.dirty = True
        return out

    def take(self, client, header, found, now, lifetime):
        """What one record does to the sessions, in order: [('line', client)], then ('refused', client,
        reason), ('other', client, status), ('event', client, event) for each address a Start or an
        Interim-Update gives, ('end', client, user, address) for each a Stop or Accounting-On/-Off
        ends, ('heard', client, record)."""
        out = [('line', client)]
        status, record = interpret(client, header, found)
        if status == 'refused':
            return out + [('refused', client, record)]
        if status == 'other':
            return out + [('other', client, record)]
        out.append(('heard', client, record))
        self.dirty = True
        if status in ('on', 'off'):
            out.append(('other', client, record['name']))
            for key in sorted(self.sessions):
                session = self.sessions[key]
                if session.get('nas') == client:
                    out.extend(('end', client, session['user'], where) for where in session.get('addresses', []))
                    del self.sessions[key]
            return out
        key = record['session']
        known = self.sessions.get(key) or {}
        if status == 'stop':
            gone = list(known.get('addresses', []))
            gone += [where for where in record['addresses'] if where not in gone]
            out.extend(('end', client, known.get('user') or record['user'], where) for where in gone)
            self.sessions.pop(key, None)
            return out
        addresses = record['addresses']
        if not addresses:
            # an Interim-Update that leaves the address out renews the one the session had
            addresses = list(known.get('addresses', [])) if known.get('user') == record['user'] else []
        if not addresses:
            out.append(('refused', client, 'no address'))
        if known.get('user') and known['user'] != record['user']:
            out.extend(('end', client, known['user'], where) for where in known.get('addresses', []))
        elif known:
            # an address the session no longer has: its NAS gave it another
            out.extend(('end', client, known['user'], where) for where in known.get('addresses', [])
                       if where not in addresses)
        self.sessions[key] = {'nas': client, 'user': record['user'], 'addresses': addresses, 'last': record['time']}
        for where in addresses:
            if events.no_client(where):
                out.append(('refused', client, 'not a client address'))
            else:
                out.append(('event', client, event(record, where)))
        return out

    def poll(self, now, lifetime):
        """take() of every record written since the last reading, in order; the sessions with no record
        for longer than the lifetime forgotten - their mappings have ended by then."""
        out = []
        for client, header, found in self.read(now, lifetime):
            out.extend(self.take(client, header, found, now, lifetime))
        for key in [k for k, s in self.sessions.items() if s.get('last', 0) < now - lifetime]:
            del self.sessions[key]
            self.dirty = True
        return out

    def forget(self):
        """The sessions forgotten - RADIUS switched off: the minute's run takes their mappings out. What
        was read of each file is kept: switched on again, what came since is read."""
        if self.sessions:
            self.sessions = {}
            self.dirty = True

    def save(self):
        if self.dirty:
            engine.write_json(self.path, {'files': self.files, 'sessions': self.sessions}, mode=0o640)
            self.dirty = False
