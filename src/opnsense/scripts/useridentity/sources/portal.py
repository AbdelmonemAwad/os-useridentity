#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""The captive portal's sessions as a source (the plan's top-03): who logged on to the portal from which
address, read from the portal's own database the way its own API reads it - OPNsense core's
captiveportal lib/db.py, list_clients(): the sessions of cp_clients not deleted, and the roaming
addresses of each in cp_client_ips - and read-only, as os-xgs-npu's cp_users.py reads it every two
seconds. No API key, and nothing written there.

The portal's word is what the map says: each address of a session is its user's from the logon to the
session's end - a logout, the portal's idle or hard timeout, the owner's disconnect - for as long as the
portal holds the session, which is as long as it lets the address through. The address leaves the map
at the first reading after the session ends: two seconds at most.

Latest wins, as between the domain controllers' events: a logon on an address another user holds is
weighed by its time against that user's last event, and the later takes it. A session whose address
went to a later event of another source does not take it back while that mapping lives: it stays among
the others of the address, so the page shows the clash; once that mapping ends, the session's user has
the address again.

Refused, each counted once a session by its reason: the portal's own sessions of an allowed address or
MAC address (---ip---, ---mac---) and those of a zone with no login (anonymous@ and the address) - not
a user; a voucher's session - System: Access: Servers names its server a voucher, and a code anyone may
hold is not a user; then, as for the domain controllers, an address that is no client's, the firewall's
own, a domain controller's, Never map's, and a user of Ignore users. Only the zones switched on in
Services: Captive Portal are read.
"""

import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import events                                                            # noqa: E402

DB = '/var/captiveportal/captiveportal.sqlite'
EVERY = 2               # seconds between readings
RENEW = 60              # seconds: a mapping a session holds renewed, a lost one noted again, at most this often
TIMEOUT = 1             # seconds to wait for the database while the portal writes it
ALLOWED = ('---ip---', '---mac---')
NOBODY = ('', '-', 'anonymous')


def read(zones, path=None):
    """({key: session}, '') of the portal's sessions in the zones given ({zone id: description}) - key
    'zone/session id', a session {'zone', 'user', 'raw', 'domain', 'via', 'created', 'addresses'} - or
    (None, why) when the database cannot be read. No database - no zone has run yet - is no session."""
    path = path or DB
    if not os.path.exists(path):
        return {}, ''
    try:
        connection = sqlite3.connect('file:' + path + '?mode=ro', uri=True, timeout=TIMEOUT)
        try:
            rows = connection.execute('select zoneid, sessionid, authenticated_via, username, created, ip_address '
                                      'from cp_clients where deleted = 0').fetchall()
            try:
                roaming = connection.execute('select zoneid, sessionid, ip_address from cp_client_ips').fetchall()
            except sqlite3.OperationalError:
                roaming = []        # a portal before its roaming addresses: one address a session
        finally:
            connection.close()
    except sqlite3.Error as error:
        return None, str(error)
    out = {}
    for zoneid, sid, via, name, created, ip in rows:
        zone = str(zoneid)
        if zone not in zones:
            continue
        where = events.address(ip)
        try:
            started = float(created or 0)
        except (TypeError, ValueError):
            started = 0.0
        out['%s/%s' % (zone, sid)] = {'zone': zone, 'user': events.user_name(name), 'raw': str(name or ''),
                                      'domain': events.domain_of(name), 'via': str(via or ''), 'created': started,
                                      'addresses': [where] if where else []}
    for zoneid, sid, ip in roaming:
        session = out.get('%s/%s' % (zoneid, sid))
        where = events.address(ip)
        if session is not None and where and where not in session['addresses']:
            session['addresses'].append(where)
    return out, ''


def refused(session, vouchers):
    """Why a session maps nothing, whatever its addresses - see the top - or ''."""
    if session['via'] in ALLOWED or session['user'] in NOBODY:
        return 'not a user'
    if session['via'] in vouchers:
        return 'voucher'
    if not session['addresses']:
        return 'no address'
    return ''


def event(session, where, when):
    """The event the engine takes for one address of a session."""
    return {'id': 'logon', 'kind': 'portal', 'user': session['user'], 'domain': session['domain'],
            'address': where, 'time': when, 'logon_type': '', 'hostname': ''}


def reconcile(state, listed, seen, now, renew=RENEW):
    """What the map is to do to say what the portal says, as [operation] in the order to do them - the
    sessions ended first, so a user that follows another on one device is no clash:

        ('leave', 'portal', zone, user, address)   a session ended, or lost the address: its user
                                                   leaves it
        ('see', 'portal', zone, event)             the address is the session's - new, not in the map,
                                                   or due to be renewed
        ('note', 'portal', zone, user, address)    another user holds it after a later event: the
                                                   session's user kept among the others

    listed and seen are the sessions accepted now and at the reading before - {key: session}, each
    with only the addresses that may map. seen is None at the collector's first reading: then a
    mapping the portal gave last whose session the portal no longer holds goes too - one that ended
    while the collector was down."""
    leave, see, note = [], [], []
    held = {(session['user'], where) for session in listed.values() for where in session['addresses']}
    for key in sorted(seen or {}):
        session = seen[key]
        still = (listed.get(key) or {}).get('addresses', [])
        for where in session['addresses']:
            if where not in still and (session['user'], where) not in held:
                leave.append(('leave', 'portal', session['zone'], session['user'], where))
    if seen is None:
        for where in sorted(state['map']):
            entry = state['map'][where]
            if entry.get('kind') == 'portal' and (entry['user'], where) not in held:
                leave.append(('leave', 'portal', entry.get('source', ''), entry['user'], where))
    for key in sorted(listed):
        session = listed[key]
        before = (seen or {}).get(key)
        for where in session['addresses']:
            entry = state['map'].get(where)
            new = before is None or where not in before['addresses']
            if entry is None:
                see.append(('see', 'portal', session['zone'], event(session, where, now)))
            elif entry['user'] == session['user']:
                if new or now - entry.get('last', 0) >= renew:
                    see.append(('see', 'portal', session['zone'], event(session, where, now)))
            elif new:
                # the logon against the other user's last event: the later takes the address
                when = session['created'] if before is None and session['created'] else now
                see.append(('see', 'portal', session['zone'], event(session, where, when)))
            elif now - entry.get('others', {}).get(session['user'], 0) >= renew:
                note.append(('note', 'portal', session['zone'], session['user'], where))
    return leave + see + note
