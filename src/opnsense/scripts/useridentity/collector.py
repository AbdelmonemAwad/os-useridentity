#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""User Identity's collector: the service that keeps the map (rc.d/useridentity runs it under
daemon(8), which starts it again when it ends unasked).

    collector.py run

syslog-ng hands it each line a domain controller sent as one datagram on /var/run/useridentity.sock,
"$SOURCEIP $MSG" (syslogng.py). Each line is refused unless its sender is a domain controller named
in Settings, then read and judged (events.py); a batch at a time, under the map's lock, the accepted
events change the map (engine.py) and the tables that changed are written (tables.py). A user whose
groups are not known, or were asked more than 15 minutes ago, is asked of the directory in a thread of
its own (ldap_groups.py), so a directory slow to answer never holds the lines back; until it answers,
the user's addresses are in its user table, if it has one, and in no group's.

What it counts goes to /var/db/os-useridentity/sources.json for the page: each domain controller's
last line and last event, how late its last event arrived, what it sent, what was refused and why -
counts, never the lines. groups.json keeps what the directory said of each user, and whether it could
be asked. The minute's work - the lifetime's end, the MAC check, every table made again from the map -
is expire.py's, from cron, whether this runs or not.

At its start the tables are made again from the map. It never fails: an error is said in the system
log, under useridentity, and it goes on.
"""

import errno
import os
import queue
import select
import signal
import socket
import sys
import syslog
import threading
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import engine                                                            # noqa: E402
import events                                                            # noqa: E402
import host                                                              # noqa: E402
import ldap_groups                                                       # noqa: E402
import outbox                                                            # noqa: E402
import settings                                                          # noqa: E402
import tables                                                            # noqa: E402

SOCKET = '/var/run/useridentity.sock'
GROUPS = engine.STATE + '/groups.json'
SOURCES = engine.STATE + '/sources.json'
CACHE = 900             # seconds what the directory said of a user is kept
RETRY = 60              # seconds before a directory that failed is asked again
BATCH = 500             # datagrams read at most before they are applied
REFRESH = 60            # seconds between readings of the firewall's own addresses
RCVBUF = (4 << 20, 2 << 20, 1 << 20, 256 << 10)

running = True


def log(message, level=syslog.LOG_NOTICE):
    syslog.syslog(level, message)


def rows_key(conf):
    """What the directory's answers depend on: the group rows switched on, and Nested groups."""
    return '|'.join(sorted(row['name'].lower() for row in conf['groups'] if row['enabled'])) + '|nested=%d' % conf['nested']


class Sources:
    """What each sender sent, for the page: counts and times, never a line."""

    def __init__(self, path=None, now=None):
        self.path = path = path or SOURCES
        found = engine.read_json(path, {})
        self.since = now if now is not None else time.time()
        self.senders = {}
        for sender, before in (found.get('senders') or {}).items():
            if isinstance(before, dict):
                # the times are kept across a restart, so a silent domain controller stays seen as silent
                self.senders[sender] = self.blank(before)
        self.dirty = True

    @staticmethod
    def blank(before=None):
        before = before or {}
        return {'last_line': before.get('last_line'), 'last_event': before.get('last_event'),
                'late': before.get('late'), 'hostname': before.get('hostname', ''), 'lines': 0, 'accepted': 0,
                'joined': 0, 'renewed': 0, 'changed': 0, 'other': {}, 'refused': {}}

    def get(self, sender):
        return self.senders.setdefault(sender, self.blank())

    def line(self, sender, arrival):
        entry = self.get(sender)
        entry['lines'] += 1
        entry['last_line'] = arrival
        self.dirty = True
        return entry

    def refused(self, sender, reason):
        refused = self.get(sender)['refused']
        refused[reason] = refused.get(reason, 0) + 1

    def other(self, sender, number):
        other = self.get(sender)['other']
        other[str(number)] = other.get(str(number), 0) + 1

    def accepted(self, sender, event, arrival):
        entry = self.get(sender)
        entry['accepted'] += 1
        entry['last_event'] = event['time']
        entry['late'] = round(arrival - event['time'], 1)
        if event.get('hostname'):
            entry['hostname'] = event['hostname']

    def changes(self, sender, changes):
        entry = self.get(sender)
        for change, _, _ in changes:
            if change in ('joined', 'renewed', 'changed'):
                entry[change] += 1

    def save(self):
        if self.dirty:
            engine.write_json(self.path, {'since': self.since, 'senders': self.senders}, mode=0o640)
            self.dirty = False


class Asker(threading.Thread):
    """The directory's questions, one user at a time, in a thread of their own."""

    def __init__(self, conf, ldap3=None):
        super().__init__(daemon=True)
        self.asked = queue.Queue()
        self.answers = queue.Queue()
        self.conf = conf
        self.ldap3 = ldap3
        self.directory = None
        self.failed_at = 0.0
        self.waiting = set()
        self.lock = threading.Lock()
        # a byte written after each answer wakes the collector's select at once: with only its socket to
        # wait on, an answer waited for the next line or the end of the second (phase 1's lab, 2026-11-18:
        # logon to let through by a group's table, median 3.02 s, where a user's table needs no answer)
        self.wake_r, self.wake_w = os.pipe()
        os.set_blocking(self.wake_r, False)
        os.set_blocking(self.wake_w, False)

    def wake(self):
        try:
            os.write(self.wake_w, b'.')
        except OSError:
            pass                    # the pipe full is the collector awake already; closed is the end

    def woken(self):
        """What the answers wrote to the pipe, read away."""
        try:
            while os.read(self.wake_r, 512):
                pass
        except OSError:
            pass

    def ask(self, user):
        with self.lock:
            if user in self.waiting:
                return
            self.waiting.add(user)
        self.asked.put(user)

    def update(self, conf):
        """New settings: the next question is asked on a new connection."""
        self.asked.put(('settings', conf))

    def stop(self):
        self.asked.put(None)

    def run(self):
        while True:
            item = self.asked.get()
            if item is None:
                break
            if isinstance(item, tuple):
                self.conf = item[1]
                self.close()
                continue
            try:
                self.answers.put(self.answer(item))
                self.wake()
            finally:
                with self.lock:
                    self.waiting.discard(item)
        self.close()

    def close(self):
        if self.directory is not None:
            self.directory.close()
        self.directory = None

    def answer(self, user):
        """(user, answer, server state) - answer None when the directory could not be asked."""
        conf, now = self.conf, time.time()
        entry = conf.get('server')
        if entry is None:
            reason = 'no LDAP server is chosen in Settings' if not conf.get('ldap_server') else \
                'the server chosen is not an LDAP entry of System: Access: Servers'
            return user, None, {'ok': False, 'error': reason, 'at': now}
        if self.failed_at and now - self.failed_at < RETRY:
            return user, None, None
        for attempt in (1, 2):
            try:
                if self.directory is None:
                    self.directory = ldap_groups.Directory(entry, ldap3=self.ldap3)
                    self.directory.connect()
                found = ldap_groups.lookup(self.directory, user, conf['groups'], conf['nested'])
                self.failed_at = 0.0
                return user, found, {'ok': True, 'error': '', 'at': now, 'chain': self.directory.chain}
            except Exception as error:                                   # noqa: BLE001
                self.close()
                said = ldap_groups.quiet('%s: %s' % (type(error).__name__, error), entry)
                if attempt == 2:
                    self.failed_at = now
                    return user, None, {'ok': False, 'error': said[:300], 'at': now}
        return user, None, None


class Collector:
    def __init__(self, socket_path=None, pf=None, ldap3=None, now=None, addresses=None):
        now = now if now is not None else time.time()
        self.socket_path = socket_path or SOCKET
        self.pf = pf or tables.Pf()
        self.conf = settings.read()
        self.mtime = self.config_mtime()
        self.present = tables.present(settings.aliases())
        self.addresses = addresses or host.addresses
        self.own, self.broadcast = self.addresses()
        self.own_at = now
        self.context = self.make_context()
        self.sources = Sources(now=now)
        self.groups = engine.read_json(GROUPS, {})
        self.groups_dirty = False
        if not isinstance(self.groups.get('users'), dict):
            self.groups['users'] = {}
        self.ldap_failing = False
        self.written = {}
        # the name this collector signs map.json with: another name there means another wrote it
        self.token = 'collector %d %s' % (os.getpid(), os.urandom(4).hex())
        self.directory = Asker(self.conf, ldap3=ldap3)
        self.directory.start()
        self.sock = None
        if self.groups.get('rows') != rows_key(self.conf):
            self.rows_changed()

    def asking(self):
        """Whether the directory is asked at all: one chosen and a group row on - a user row needs no group,
        and no directory chosen is no failure to alert about."""
        return bool(self.conf.get('server')) and any(row['enabled'] for row in self.conf['groups'])

    def rows_changed(self):
        """Settings' group rows or Nested changed: what the directory said of each user is kept - so no
        table goes empty meanwhile, and this and the minute's run, which reads groups.json, never write
        two answers in turn - but marked old and written down at once, and every user in the map asked
        again now, not at its next event."""
        for known in self.groups['users'].values():
            if isinstance(known, dict):
                known['at'] = 0
        self.groups['rows'] = rows_key(self.conf)
        engine.write_json(GROUPS, self.groups, mode=0o640)
        if self.asking():
            for user in sorted({entry['user'] for entry in engine.load()['map'].values()}):
                self.directory.ask(user)

    @staticmethod
    def config_mtime():
        try:
            return os.stat(settings.CONFIG).st_mtime
        except OSError:
            return 0.0

    def make_context(self):
        return events.Context(dcs=self.conf['dcs'], stale=self.conf['stale'], own=self.own, broadcast=self.broadcast,
                              never_map=self.conf['never_map'], ignore=self.conf['ignore'])

    def open(self):
        """The socket syslog-ng writes to: made afresh, 0600 - syslog-ng runs as root."""
        try:
            os.unlink(self.socket_path)
        except OSError:
            pass
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        old = os.umask(0o177)
        try:
            sock.bind(self.socket_path)
        finally:
            os.umask(old)
        for size in RCVBUF:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, size)
                break
            except OSError:
                continue
        sock.setblocking(False)
        self.sock = sock
        return sock

    def close(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None
            try:
                os.unlink(self.socket_path)
            except OSError:
                pass
        # the pipe is left open: the directory's thread may still be in a question, and a closed descriptor's
        # number given to another file would take its byte; the process ends here
        self.directory.stop()

    def refresh(self, now):
        """Settings read again when config.xml changed, the firewall's addresses every minute."""
        mtime = self.config_mtime()
        if mtime != self.mtime:
            self.mtime = mtime
            self.conf = settings.read()
            self.present = tables.present(settings.aliases())
            self.directory.update(self.conf)
            if self.groups.get('rows') != rows_key(self.conf):
                self.rows_changed()
            self.written = {}
        if now - self.own_at >= REFRESH:
            own, broadcast = self.addresses()
            if own:
                self.own, self.broadcast = own, broadcast
            self.own_at = now
        self.context = self.make_context()

    def drain(self):
        """The datagrams waiting, BATCH at most."""
        found = []
        while len(found) < BATCH:
            try:
                found.append(self.sock.recv(65536))
            except BlockingIOError:
                break
            except OSError as error:
                if error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    break
                raise
        return found

    def receive(self, datagrams, now):
        """The accepted events of a batch applied; [change] of the map."""
        accepted = []
        for datagram in datagrams:
            sender, message = events.split(datagram)
            self.sources.line(sender, now)
            if sender not in self.context.dcs:
                self.sources.refused(sender, 'not a domain controller')
                continue
            kind, found = events.parse(message)
            if kind == 'other':
                self.sources.other(sender, found)
                continue
            if kind == 'refused':
                self.sources.refused(sender, found)
                continue
            reason = events.judge(found, now, self.context)
            if reason:
                self.sources.refused(sender, reason)
                continue
            self.sources.accepted(sender, found, now)
            accepted.append((sender, found))
        if not accepted or not self.conf['enabled']:
            return []
        changes = []
        with engine.locked():
            state = self.load()
            for sender, event in accepted:
                made = engine.see(state, event, now, self.conf['lifetime'], sender)
                self.sources.changes(sender, made)
                changes.extend(made)
            engine.save(state, writer=self.token)
            self.write_tables(state)
        self.after(changes, now)
        if self.asking():
            for user in sorted({event['user'] for _, event in accepted}):
                known = self.groups['users'].get(user)
                if known is None or now - known.get('at', 0) >= CACHE:
                    self.directory.ask(user)
        return changes

    def answers(self, now):
        """What the directory said since the last batch: kept, and the tables of those users written."""
        got = False
        while True:
            try:
                user, found, server = self.directory.answers.get_nowait()
            except queue.Empty:
                break
            if server is not None:
                self.groups['server'] = dict(server, name=self.conf.get('ldap_server', ''))
                self.groups_dirty = True
                if not server['ok'] and not self.ldap_failing:
                    self.ldap_failing = True
                    outbox.alert('ldap-failing', 'User Identity: the directory cannot be asked',
                                 'The groups of the users mapped are not known: %s' % server['error'],
                                 {'server': self.conf.get('ldap_server', ''), 'error': server['error']}, now=now)
                elif server['ok']:
                    self.ldap_failing = False
            if found is not None:
                self.groups['users'][user] = {'in': found['in'], 'found': found['found'], 'at': now}
                got = True
            elif server is not None and not server['ok']:
                # asked again once RETRY has passed: what was known stays until then
                known = self.groups['users'].get(user)
                if known is not None:
                    known['at'] = now - CACHE + RETRY
        if got or self.groups_dirty:
            engine.write_json(GROUPS, self.groups, mode=0o640)
            self.groups_dirty = False
        if got:
            with engine.locked():
                self.write_tables(self.load())

    def load(self):
        """The map, read under the lock. When the collector did not write it last - the minute's run,
        Forget all, or a collector before this one - the tables may have changed behind it: what it
        wrote to each is forgotten, and each is made whole again at its next write. What the directory
        said of each user is read again from groups.json then too: Forget all empties it there, and the
        minute's run makes the group tables from it - held in memory alone, it kept a user in a group's
        table that the minute's run took out again each minute, the Users tab showing the user in no
        group (phase 1's lab, 2026-11-18). A user it no longer knows is asked again at its next event."""
        state = engine.load()
        if state.get('writer') != self.token:
            self.written = {}
            self.groups = engine.read_json(GROUPS, {})
            if not isinstance(self.groups.get('users'), dict):
                self.groups['users'] = {}
        return state

    def write_tables(self, state):
        """The tables the map asks for, those that changed since the last write; under the lock."""
        want = engine.tables(state, self.groups['users'], self.conf, self.present)
        changed = {name for name, addresses in want.items() if self.written.get(name) != addresses}
        if changed:
            tables.sync(self.pf, want, only=changed)
            self.written.update({name: want[name] for name in changed})
        if self.pf.errors:
            log('tables: ' + '; '.join(self.pf.errors[:3]), syslog.LOG_ERR)
            self.pf.errors.clear()

    def after(self, changes, now):
        """The log's line, the history, and an alert for each address newly shared."""
        line = engine.summary(changes, self.conf['log_names'])
        if line:
            log(line)
        engine.record(changes, self.conf['history_days'], now)
        for change, where, users in changes:
            if change != 'shared':
                continue
            facts = {'address': where}
            text = 'Two users were mapped to %s within the mapping lifetime: the latest holds it.' % where
            if self.conf['log_names']:
                facts['users'] = users
                text = '%s were mapped to %s within the mapping lifetime: the latest holds it.' % (
                    ', '.join(users), where)
            outbox.alert('address-shared', 'User Identity: %s is shared' % where, text, facts, now=now)

    def prune_groups(self, now):
        """What the directory said of users no longer in the map, forgotten once it is older than CACHE:
        only the live map is kept (settled point 14). How many were forgotten."""
        mapped = {entry['user'] for entry in engine.load()['map'].values()}
        users = self.groups['users']
        gone = [user for user, known in users.items() if user not in mapped and now - known.get('at', 0) >= CACHE]
        for user in gone:
            del users[user]
        if gone:
            engine.write_json(GROUPS, self.groups, mode=0o640)
        return len(gone)

    def start(self, now):
        """At the start: the map's tables written whole."""
        with engine.locked():
            self.write_tables(self.load())
        self.sources.save()

    def loop(self):
        last_save = last_prune = 0.0
        while running:
            try:
                ready, _, _ = select.select([self.sock, self.directory.wake_r], [], [], 1.0)
            except InterruptedError:
                continue
            now = time.time()
            try:
                if self.directory.wake_r in ready:
                    self.directory.woken()
                self.refresh(now)
                datagrams = self.drain() if self.sock in ready else []
                if datagrams:
                    self.receive(datagrams, now)
                self.answers(now)
                if now - last_save >= 10:
                    self.sources.save()
                    last_save = now
                if now - last_prune >= REFRESH:
                    self.prune_groups(now)
                    last_prune = now
            except Exception:                                            # noqa: BLE001
                log('error: ' + traceback.format_exc().strip().splitlines()[-1], syslog.LOG_ERR)
                time.sleep(1)
        self.sources.save()


def stop(signum, frame):
    global running
    running = False


def main(argv):
    if argv[1:2] != ['run']:
        print('usage: collector.py run', file=sys.stderr)
        return 2
    syslog.openlog('useridentity', syslog.LOG_PID, syslog.LOG_DAEMON)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    os.makedirs(engine.STATE, mode=0o750, exist_ok=True)
    collector = Collector()
    collector.open()
    log('started: %d domain controller(s) named, %d group table(s), %d user table(s)' % (
        len(collector.conf['dcs']), len(collector.conf['groups']), len(collector.conf['users'])))
    try:
        collector.start(time.time())
        collector.loop()
    finally:
        collector.close()
        log('stopped')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
