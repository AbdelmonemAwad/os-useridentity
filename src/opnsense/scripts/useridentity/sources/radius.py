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

Which clients may map: only those Settings names in RADIUS clients, by their address - the name of
their directory. A request reaches the detail module only from a client FreeRADIUS knows, by the
secret the two share, but a client of Services: FreeRADIUS may be a whole network sharing one secret,
and the name a record carries is the one its NAS reports: with EAP - PEAP, TTLS, TLS, most 802.1X -
the outer name the device itself gives, anything its user types, unless FreeRADIUS checks it against
the name it authenticated or returns that one to the NAS in the Access-Accept (RFC 2865 5.1, RFC 3579
2.1). os-freeradius as installed does neither, and nothing it writes ties the name it authenticated
to a session. So the owner names the clients whose names are the authenticated ones; a record from
any other client is refused, as "not a named client", before anything else is read of it.

What a record does:

  Start                   a logon: the session's user on its Framed-IP-Address and Framed-IPv6-Address
                          - the latest wins the address, as a domain controller's event does
  Interim-Update          renews them. An address the session already had is not taken back from a
                          later logon of another user - from a domain controller, another session,
                          the portal - which keeps it while the session's user is noted beside it
                          (the clash shown); an address that is no one's is mapped again. A NAS that
                          sends none leaves the mapping to the lifetime's end, even while the session
                          goes on
  Stop                    the session's addresses leave the map, when they are still its user's -
                          but an address another open session of the same user holds (a device that
                          roamed to another NAS, whose Stop at the first comes after its Start at the
                          second), and a mapping something renewed after the Stop's own time (read
                          late, the Stop of a session long gone)
  Accounting-On, -Off     a NAS started again, or stopped: every session of that NAS ends as by a
                          Stop - the NAS by its NAS-IP-Address, NAS-IPv6-Address and NAS-Identifier,
                          so that behind a RADIUS server that forwards several, the others' sessions
                          go on; all the sessions of the client only when the record names no NAS

Refused, each counted on the page by its reason: a record from a client not named; one with no
Acct-Status-Type, or no time; no user, or one that names nobody - anonymous, the outer name of an EAP
client that hides its own; a computer (host/... or a name ending in $); a MAC address as the name
(MAC authentication); with a directory chosen in Groups from, a name written with a realm or a domain
that is not the directory's (another directory: its groups would be those of a user of the same name
there); no address, or none that is a client's. The collector then judges each address as it judges
a domain controller's event: the firewall's own, a domain controller's, Never map's, a user of Ignore
users, and a record older than the mapping lifetime when it is read (stale: its mapping would end at
once).

A record's time is the time FreeRADIUS wrote it (its Timestamp), less the seconds the NAS said it
waited before sending (Acct-Delay-Time): the firewall's own clock, never the NAS's.

Only the files a record within the lifetime can be in are read: detail-YYYYMMDD of the days from the
lifetime's start to tomorrow - nothing ever takes the older ones away (os-freeradius keeps them), and
compressed ones are not records. What was read of each, and the sessions open, are kept in
/var/db/os-useridentity/radius.json, written at most every ten seconds and when the collector stops:
the collector goes on where it stopped, and what came while it was down is read then, in order - after
a crash, the last seconds again, which renews nothing twice and ends nothing renewed since. A file it
never read is read whole when it was written to within the lifetime, else from its end.
"""

import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import engine                                                            # noqa: E402
import events                                                            # noqa: E402
import settings                                                          # noqa: E402

RADACCT = '/var/log/radacct'
STATE = engine.STATE + '/radius.json'
CHUNK = 4 << 20         # bytes of one file read at a time: what is left, at the next reading
SAVE_EVERY = 10         # seconds: radius.json written at most this often while records come

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


def nas_of(found):
    """[NAS-IP-Address, NAS-IPv6-Address, NAS-Identifier] of a record, each '' when it gives none: who
    the NAS is, whichever client - the NAS itself, or a RADIUS server forwarding it - sent the record."""
    return [events.address(found.get('NAS-IP-Address')) or '', events.address(found.get('NAS-IPv6-Address')) or '',
            str(found.get('NAS-Identifier') or '').strip()]


def same_nas(session, record):
    """Whether a session is of the NAS a record names: one of the three at least the same in both, none
    different. A record that names no NAS is its client's - every NAS behind it; so is a session whose
    records named none, which no other way tells apart."""
    session, record = list(session or ['', '', '']), list(record or ['', '', ''])
    if not any(record) or not any(session):
        return True
    both = [(one, other) for one, other in zip(session, record) if one and other]
    return bool(both) and all(one == other for one, other in both)


def interpret(client, header, found):
    """What one record says: (status, record) with status start, interim, stop, on or off; ('other',
    the status as written) for a status that maps nothing; ('refused', reason). The record:
    {'status', 'name', 'time', 'client', 'nas', 'hostname', 'session', 'user', 'domain', 'addresses'}."""
    raw = found.get('Acct-Status-Type', '').strip()
    if not raw:
        return 'refused', 'unreadable'
    status = STATUS.get(raw.lower())
    if status is None:
        return 'other', raw
    when = record_time(header, found)
    if when is None:
        return 'refused', 'no time'
    record = {'status': status, 'name': NAMES[status], 'time': when, 'client': client, 'nas': nas_of(found),
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


def days(now, lifetime):
    """The names of the files a record within the lifetime can be in: one a day, from the day before the
    lifetime began to the day after today - FreeRADIUS names them by its own date, and a day either way
    leaves room for a zone or a clock that is not the firewall's."""
    names = set()
    start, end = int(now - lifetime) - 86400, int(now) + 86400
    for stamp in list(range(start, end, 3 * 3600)) + [end]:
        names.add('detail-' + time.strftime('%Y%m%d', time.localtime(stamp)))
    return names


class Accounting:
    """The detail files read, and the sessions open: {session: {'client', 'nas', 'user', 'addresses',
    'since', 'last'}} - since the session's logon, last its last record. A session's entry is replaced
    whole, never changed in place, so a copy of the dict is a copy of the sessions (mark())."""

    def __init__(self, path=None, folder=None):
        self.path = path or STATE
        self.folder = folder or RADACCT
        found = engine.read_json(self.path, {})
        self.files = found.get('files') if isinstance(found.get('files'), dict) else {}
        self.sessions = {}
        for key, session in (found.get('sessions') if isinstance(found.get('sessions'), dict) else {}).items():
            if isinstance(session, dict) and session.get('user') and isinstance(session.get('addresses'), list):
                last = session.get('last') if isinstance(session.get('last'), (int, float)) else 0
                nas = session.get('nas') if isinstance(session.get('nas'), list) and len(session['nas']) == 3 else \
                    ['', '', '']
                self.sessions[key] = {'client': str(session.get('client') or ''), 'nas': nas, 'user': session['user'],
                                      'addresses': session['addresses'], 'last': last,
                                      'since': session.get('since') if isinstance(session.get('since'), (int, float))
                                      else last}
        self.dirty = False
        self.saved_at = 0.0

    def found(self):
        """Whether os-freeradius's accounting directory is there."""
        return os.path.isdir(self.folder)

    def paths(self, now, lifetime):
        """The files that may be read now, each client's in their days' order: its directory's
        detail-YYYYMMDD of days(), whether there or not."""
        try:
            clients = sorted(os.listdir(self.folder))
        except OSError:
            return []
        names = sorted(days(now, lifetime))
        return [os.path.join(self.folder, client, name) for client in clients for name in names]

    def read(self, now, lifetime, chunk=CHUNK):
        """[(client, time line, {attribute: value})] of the records written since the last reading, the
        files of each client in their days' order."""
        out = []
        there = set()
        for path in self.paths(now, lifetime):
            try:
                stat = os.stat(path)
            except OSError:
                continue
            there.add(path)
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
        # a file gone, or of a day past the lifetime: forgotten - what is in it is older than the lifetime
        for path in [p for p in self.files if p not in there]:
            del self.files[path]
            self.dirty = True
        return out

    def ends(self, client, user, addresses, when):
        """('end', client, user, address, when) for each address that leaves - but those another open
        session of the same user still holds."""
        held = {where for session in self.sessions.values() if session['user'] == user
                for where in session['addresses']}
        return [('end', client, user, where, when) for where in addresses if where not in held]

    def take(self, client, header, found, now, lifetime, clients=None, realms=None):
        """What one record does to the sessions, in order: [('line', client)], then ('refused', client,
        reason), ('other', client, status), ('heard', client, record), and for its addresses:
        ('event', client, event) - a logon, the latest wins - ('renew', client, event, since) - an
        Interim-Update of an address its session had, since the session's logon - and ('end', client,
        user, address, when) for each a Stop or Accounting-On/-Off ends. clients: the addresses of the
        clients that may map (None: any); realms: the directory's realms (None: no directory chosen)."""
        out = [('line', client)]
        if clients is not None and settings.address_key(client) not in clients:
            return out + [('refused', client, 'not a named client')]
        status, record = interpret(client, header, found)
        if status == 'refused':
            return out + [('refused', client, record)]
        if status == 'other':
            return out + [('other', client, record)]
        if realms is not None and record.get('domain') and record['domain'].lower() not in realms:
            return out + [('refused', client, 'another directory')]
        out.append(('heard', client, record))
        self.dirty = True
        when = record['time']
        if status in ('on', 'off'):
            out.append(('other', client, record['name']))
            gone = []
            for key in sorted(self.sessions):
                session = self.sessions[key]
                if session['client'] == client and same_nas(session['nas'], record['nas']):
                    gone.append(session)
                    del self.sessions[key]
            for session in gone:
                out.extend(self.ends(client, session['user'], session['addresses'], when))
            return out
        key = record['session']
        known = self.sessions.get(key)
        if status == 'stop':
            self.sessions.pop(key, None)
            gone = list(known['addresses']) if known else []
            gone += [where for where in record['addresses'] if where not in gone]
            out.extend(self.ends(client, known['user'] if known else record['user'], gone, when))
            return out
        same = known is not None and known['user'] == record['user']
        addresses = record['addresses']
        if not addresses:
            # an Interim-Update that leaves the address out renews the one the session had
            addresses = list(known['addresses']) if same else []
        if not addresses:
            out.append(('refused', client, 'no address'))
        since = known['since'] if same and status == 'interim' else when
        self.sessions[key] = {'client': client, 'nas': record['nas'], 'user': record['user'], 'addresses': addresses,
                              'since': since, 'last': when}
        if known is not None and not same:
            # the session names another user now: the one before ends there first
            out.extend(self.ends(client, known['user'], known['addresses'], when))
        elif known is not None:
            # an address the session no longer has: its NAS gave it another
            out.extend(self.ends(client, known['user'], [w for w in known['addresses'] if w not in addresses], when))
        for where in addresses:
            if events.no_client(where):
                out.append(('refused', client, 'not a client address'))
            elif status == 'interim' and same and where in known['addresses']:
                out.append(('renew', client, event(record, where), since))
            else:
                out.append(('event', client, event(record, where)))
        return out

    def poll(self, now, lifetime, clients=None, realms=None):
        """take() of every record written since the last reading, in order; the sessions with no record
        for longer than the lifetime forgotten - their mappings have ended by then."""
        out = []
        for client, header, found in self.read(now, lifetime):
            out.extend(self.take(client, header, found, now, lifetime, clients, realms))
        for key in [k for k, s in self.sessions.items() if s['last'] < now - lifetime]:
            del self.sessions[key]
            self.dirty = True
        return out

    def mark(self):
        """Where the reading stands - what was read of each file, the sessions - to go back to with
        restore() when what was read could not be put in the map."""
        return dict(self.files), dict(self.sessions), self.dirty

    def restore(self, mark):
        self.files, self.sessions, self.dirty = dict(mark[0]), dict(mark[1]), mark[2]

    def forget(self, keep=None):
        """The sessions keep(session) refuses forgotten - all of them without keep: RADIUS switched off,
        or their client no longer named; the minute's run takes their mappings out. What was read of each
        file is kept: switched on again, what came since is read."""
        for key in [k for k, s in self.sessions.items() if keep is None or not keep(s)]:
            del self.sessions[key]
            self.dirty = True

    def save(self, now=None, force=False):
        """radius.json written when something changed: at most every SAVE_EVERY seconds, or now when forced."""
        now = time.time() if now is None else now
        if self.dirty and (force or now - self.saved_at >= SAVE_EVERY):
            engine.write_json(self.path, {'files': self.files, 'sessions': self.sessions}, mode=0o640)
            self.dirty = False
            self.saved_at = now
