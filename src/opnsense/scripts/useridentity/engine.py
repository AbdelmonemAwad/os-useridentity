#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""The live map: which user each address belongs to, kept in /var/db/os-useridentity/map.json, and
the pf tables that follow from it. Only the live map is kept (settled point 14); what came before is
written down only when Settings keeps a history.

An address's entry:

    user     the user it is mapped to, in lower case        domain   as the event wrote it
    kind     the source that said so last: ad (a domain controller's event), radius (an accounting
             record of os-freeradius) or portal (a session of the captive portal)
    source   who said it: the domain controller, the RADIUS client, the portal's zone
    event    what said it: 4768 or 4624, Start or Interim-Update, logon
    first    when it was mapped to this user                  last     the last event that renewed it
    expires  last and the lifetime: then it leaves the map    mac      the first MAC the firewall's ARP
                                                                       or NDP table gave it while mapped
    others   {user: last} the other users an event put on it within the lifetime - shared when any
    via      {user: kind} the source each of the others came from - a clash when one is not kind

The rules (settled points 7 and 8, and the plan's top-03 for the sources beside the domain controllers):

- join: an address not in the map is mapped to the event's user;
- renew: an event of the same user moves last and expires on, whichever source it came from;
- latest wins: a logon of another user, no older than the last event, maps the address to that user,
  and the one before goes into others: the address is shared - a runas or a service logon on a client
  does this while another user sits at its console (the lab's A6) - and when the two users came from
  two sources, the sources clash over it. An older event of another user is only noted in others, and
  so is a session's renewal - a RADIUS Interim-Update - of an address a later logon took from it: the
  session goes on, but it is no new logon, and taking the address back at each update would move it
  between the two users at every interval;
- leave: at the lifetime's end; when the address's MAC in ARP is not the one it had (another device
  took it); when a source says its user left - a RADIUS Stop, a captive portal session ended - unless
  that user's mapping was renewed after the word was said; when the source that gave it last is
  switched off; or when the owner forgets every mapping. A domain controller says nothing at a logoff
  (the lab's A2): its mappings end by the others alone - and are left to their lifetime when it is no
  longer named in Settings, as they were made true.

Times are the events' own, never later than their arrival, so an event sent late renews no further
than when it happened. The map is changed by the collector for each batch of events and by expire.py
every minute, each under the lock, each reading it again first.
"""

import contextlib
import fcntl
import json
import os
import tempfile
import time

STATE = '/var/db/os-useridentity'
MAP = STATE + '/map.json'
LOCK = STATE + '/lock'
HISTORY = STATE + '/history'
KINDS = ('ad', 'radius', 'portal')


@contextlib.contextmanager
def locked(path=None, wait=30.0):
    """The map's lock, held for the with block; waits up to wait seconds, then goes on without it
    rather than stop - the map is written whole each time, so the worst is one change lost."""
    path = path or LOCK
    os.makedirs(os.path.dirname(path), mode=0o750, exist_ok=True)
    handle = open(path, 'a')
    until = time.monotonic() + wait
    held = False
    try:
        while True:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                held = True
                break
            except OSError:
                if time.monotonic() >= until:
                    break
                time.sleep(0.05)
        yield held
    finally:
        if held:
            fcntl.flock(handle, fcntl.LOCK_UN)
        handle.close()


def write_json(path, data, mode=0o640):
    """Written whole beside it and put in place in one step: a reader never meets half of it."""
    folder = os.path.dirname(path)
    os.makedirs(folder, mode=0o750, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=folder, prefix='.' + os.path.basename(path) + '.')
    try:
        with os.fdopen(handle, 'w', encoding='utf-8') as stream:
            json.dump(data, stream, sort_keys=True)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise


def read_json(path, default):
    try:
        with open(path, encoding='utf-8') as handle:
            found = json.load(handle)
        return found if isinstance(found, type(default)) else default
    except (OSError, ValueError):
        return default


def load(path=None):
    state = read_json(path or MAP, {})
    entries = state.get('map') if isinstance(state.get('map'), dict) else {}
    clean = {}
    for address, entry in entries.items():
        if isinstance(entry, dict) and entry.get('user'):
            if not isinstance(entry.get('others'), dict):
                entry['others'] = {}
            entry.setdefault('mac', '')
            if entry.get('kind') not in KINDS:
                # a map the first part wrote: each of its mappings was a domain controller's
                entry['kind'] = 'ad'
            via = entry.get('via') if isinstance(entry.get('via'), dict) else {}
            entry['via'] = {user: via[user] if via.get(user) in KINDS else 'ad' for user in entry['others']}
            clean[address] = entry
    return {'version': 1, 'map': clean, 'writer': str(state.get('writer') or '')}


def save(state, path=None, writer=''):
    """The map written whole; writer says who wrote it - the collector by a name of its own, the minute's
    run as 'minute' - so the collector knows when the tables may have been changed behind it."""
    write_json(path or MAP, {'version': 1, 'map': state['map'], 'saved': int(time.time()), 'writer': writer})


def shared(entry, now, lifetime):
    """True when another user was put on the address within the lifetime."""
    return any(user != entry['user'] and last > now - lifetime for user, last in entry.get('others', {}).items())


def clash(entry, now, lifetime):
    """The other users within the lifetime that another source gave the address to: [user]."""
    kind = entry.get('kind', 'ad')
    via = entry.get('via') or {}
    return sorted(user for user, last in entry.get('others', {}).items()
                  if user != entry['user'] and last > now - lifetime and via.get(user, 'ad') != kind)


def see(state, event, arrival, lifetime, source=''):
    """The map after one accepted event: [(change, address, detail)], change one of joined, renewed,
    changed (detail: (user before, user now)), noted (another user's older event) and shared (the
    address became shared: detail the users on it). The event's kind - ad, radius or portal, ad when
    it gives none - is its source's."""
    kind = event.get('kind', 'ad')
    when = min(event['time'], arrival)
    where, user = event['address'], event['user']
    entries = state['map']
    entry = entries.get(where)
    if entry is None:
        entries[where] = {'user': user, 'domain': event.get('domain', ''), 'kind': kind, 'source': source,
                          'event': event['id'], 'first': when, 'last': when, 'expires': when + lifetime,
                          'mac': '', 'others': {}, 'via': {}}
        return [('joined', where, user)]
    if entry['user'] == user:
        if when >= entry['last']:
            # an older event renews nothing, nor says who spoke last
            entry['last'] = when
            entry['expires'] = when + lifetime
            entry.update(domain=event.get('domain') or entry.get('domain', ''), kind=kind,
                         source=source or entry.get('source', ''), event=event['id'])
        return [('renewed', where, user)]
    before = shared(entry, arrival, lifetime)
    others = entry.setdefault('others', {})
    via = entry.setdefault('via', {})
    if when >= entry['last']:
        old = entry['user']
        others[old] = max(others.get(old, 0), entry['last'])
        via[old] = entry.get('kind', 'ad')
        others.pop(user, None)
        via.pop(user, None)
        # the MAC was the device of the user before: the address may have gone to another device with
        # this logon, whose MAC the next check takes - kept, it would end the new mapping
        entry.update(user=user, domain=event.get('domain', ''), kind=kind, source=source, event=event['id'],
                     first=when, last=when, expires=when + lifetime, mac='')
        changes = [('changed', where, (old, user))]
    else:
        others[user] = max(others.get(user, 0), when)
        via[user] = kind
        changes = [('noted', where, user)]
    if not before and shared(entry, arrival, lifetime):
        changes.append(('shared', where, sorted({entry['user']} | set(others))))
    return changes


def renew(state, event, arrival, lifetime, source='', since=None):
    """A session's renewal of an address it had - a RADIUS Interim-Update - as see() takes a logon, but
    for an address another user's later logon took: that user keeps it, and the session's is noted among
    the others (the clash stays shown), as the captive portal's sessions do. since is the session's own
    logon: a mapping no later than it was not a later logon, and the session takes the address."""
    where, user = event['address'], event['user']
    entry = state['map'].get(where)
    if entry is None or entry['user'] == user or (since is not None and entry.get('last', 0) <= since):
        return see(state, event, arrival, lifetime, source)
    return note(state, where, user, event.get('kind', 'ad'), min(event['time'], arrival), lifetime)


def note(state, where, user, kind, when, lifetime):
    """A source still gives the address to a user that lost it to a later event: kept among the others,
    so the page goes on showing the clash while both say so. [('shared', ...)] when that makes the
    address shared again, else []."""
    entry = state['map'].get(where)
    if entry is None or entry['user'] == user:
        return []
    before = shared(entry, when, lifetime)
    entry.setdefault('others', {})[user] = max(entry['others'].get(user, 0), when)
    entry.setdefault('via', {})[user] = kind
    if not before and shared(entry, when, lifetime):
        return [('shared', where, sorted({entry['user']} | set(entry['others'])))]
    return []


def leave(state, user, where, reason='logoff', when=None):
    """A source says the user left the address - a RADIUS Stop, a captive portal session ended: the
    address leaves the map when it is still that user's, whichever source renewed it last (a logoff is
    the surest word there is); when another user holds it, the one that left is only no longer among
    the others. when, the time the source said it: a mapping that user's renewed after it - by a domain
    controller's event, or a session elsewhere - is not ended by it, nor is a later note of the user
    among the others; a Stop read hours late ends only what it ended then."""
    entry = state['map'].get(where)
    if entry is None:
        return []
    if entry['user'] == user:
        if when is not None and entry.get('last', 0) > when:
            return []
        del state['map'][where]
        return [('left', where, (user, reason))]
    if when is None or entry.get('others', {}).get(user, 0) <= when:
        entry.get('others', {}).pop(user, None)
        entry.get('via', {}).pop(user, None)
    return []


def drop(state, keep, reason='source off'):
    """The mappings keep(entry) refuses taken out: those a source switched off gave last - RADIUS or
    the captive portal turned off, a RADIUS client no longer named, a portal's zone switched off."""
    changes = []
    for where in sorted(state['map']):
        entry = state['map'][where]
        if not keep(entry):
            del state['map'][where]
            changes.append(('left', where, (entry['user'], reason)))
    return changes


def expire(state, now, lifetime):
    """Entries whose lifetime ended taken out, and others no longer within it forgotten."""
    changes = []
    for where in sorted(state['map']):
        entry = state['map'][where]
        if entry['expires'] <= now:
            del state['map'][where]
            changes.append(('left', where, (entry['user'], 'expired')))
            continue
        entry['others'] = {user: last for user, last in entry.get('others', {}).items() if last > now - lifetime}
        entry['via'] = {user: kind for user, kind in entry.get('via', {}).items() if user in entry['others']}
    return changes


def forget_ignored(state, ignore):
    """Users put in Ignore users since they were seen: what they hold ends, and they leave the others -
    so a clash over one account many share, each user's own on another source, ends at the next minute
    once that account is in Ignore users, as the Users tab says. ignore holds the names in lower case,
    as settings.py reads them and events.py refuses them."""
    changes = []
    if not ignore:
        return changes
    for where in sorted(state['map']):
        entry = state['map'][where]
        if entry['user'].lower() in ignore:
            del state['map'][where]
            changes.append(('left', where, (entry['user'], 'ignored')))
            continue
        others = entry.get('others', {})
        for user in [u for u in others if u.lower() in ignore]:
            others.pop(user, None)
            entry.get('via', {}).pop(user, None)
    return changes


def check_macs(state, macs):
    """The MAC check (settled point 7): an address whose MAC in the firewall's ARP or NDP table is not
    the one it had leaves the map - another device has it; one with no MAC yet takes the one there.
    An address the table does not hold - behind a router, or quiet - is left as it is, and so is one a
    captive portal session gave last: the portal lets that address through for as long as it holds the
    session, and ends the session itself."""
    changes = []
    for where in sorted(state['map']):
        entry = state['map'][where]
        mac = macs.get(where)
        if not mac or entry.get('kind') == 'portal':
            continue
        if not entry.get('mac'):
            entry['mac'] = mac
        elif entry['mac'] != mac:
            del state['map'][where]
            changes.append(('left', where, (entry['user'], 'mac')))
    return changes


def flush(state):
    """Every mapping forgotten: the owner's flush, or the plugin turned off."""
    changes = [('left', where, (state['map'][where]['user'], 'flushed')) for where in sorted(state['map'])]
    state['map'].clear()
    return changes


def tables(state, groups, conf, present):
    """{alias: {address}} the map asks for: for each group row switched on whose alias is in config.xml,
    the addresses of the users LDAP put in that group (groups: {user: {'in': [row names]}}); for each
    user row, that user's addresses. An alias that is not there - not applied yet, or the owner's of
    that name - is written nothing."""
    want = {}
    for row in conf.get('groups', []):
        if not row['enabled'] or row['alias'] not in present:
            continue
        key = row['name'].lower()
        want[row['alias']] = {where for where, entry in state['map'].items()
                              if key in (groups.get(entry['user']) or {}).get('in', [])}
    for row in conf.get('users', []):
        if not row['enabled'] or row['alias'] not in present:
            continue
        key = row['name'].lower()
        want[row['alias']] = {where for where, entry in state['map'].items() if entry['user'] == key}
    return want


def summary(changes, names=False):
    """One line for the system log: counts, or with names when Settings says so (settled point 14)."""
    counts = {}
    for change, _, _ in changes:
        counts[change] = counts.get(change, 0) + 1
    if not names:
        words = {'joined': 'mapped', 'changed': 'mapped to another user', 'left': 'left', 'shared': 'now shared'}
        parts = ['%d %s' % (counts[k], words[k]) for k in ('joined', 'changed', 'shared', 'left') if counts.get(k)]
        return ('addresses: ' + ', '.join(parts)) if parts else ''
    parts = []
    for change, where, detail in changes:
        if change == 'joined':
            parts.append('%s mapped to %s' % (where, detail))
        elif change == 'changed':
            parts.append('%s mapped to %s, was %s' % (where, detail[1], detail[0]))
        elif change == 'shared':
            parts.append('%s shared by %s' % (where, ', '.join(detail)))
        elif change == 'left':
            parts.append('%s of %s left (%s)' % (where, detail[0], detail[1]))
    return '; '.join(parts)


def record(changes, days, now, folder=None):
    """The history Settings keeps (0 days: none): each mapping made, changed or ended, a file a day."""
    if days <= 0:
        return 0
    lines = []
    for change, where, detail in changes:
        if change == 'joined':
            lines.append({'at': int(now), 'change': change, 'address': where, 'user': detail})
        elif change == 'changed':
            lines.append({'at': int(now), 'change': change, 'address': where, 'user': detail[1], 'before': detail[0]})
        elif change == 'left':
            lines.append({'at': int(now), 'change': change, 'address': where, 'user': detail[0], 'why': detail[1]})
    if not lines:
        return 0
    folder = folder or HISTORY
    os.makedirs(folder, mode=0o750, exist_ok=True)
    path = os.path.join(folder, time.strftime('%Y-%m-%d', time.localtime(now)) + '.jsonl')
    with open(path, 'a', encoding='utf-8') as handle:
        os.fchmod(handle.fileno(), 0o640)
        for line in lines:
            handle.write(json.dumps(line, sort_keys=True) + '\n')
    return len(lines)


def prune(days, now, folder=None):
    """The history's files older than days taken away; all of them when it is 0."""
    removed = 0
    folder = folder or HISTORY
    try:
        names = os.listdir(folder)
    except OSError:
        return 0
    oldest = time.strftime('%Y-%m-%d', time.localtime(now - days * 86400))
    for name in names:
        if not name.endswith('.jsonl'):
            continue
        if days <= 0 or name[:10] < oldest:
            with contextlib.suppress(OSError):
                os.unlink(os.path.join(folder, name))
                removed += 1
    return removed
