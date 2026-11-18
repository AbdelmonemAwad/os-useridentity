#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""Alerts, one file each, in os-xgs-npu's form (settled point 13), for os-netreport to send:
/var/db/os-useridentity/alerts/<kind>-<time>-<pid>.json holding {"source": "os-useridentity", "kind",
"at", "subject", "text", "facts"}, and said in the system log too. os-netreport's alert layer (its pull
request 50) reads os-xgs-npu's folder alone so far; until it reads this one, nothing grows: an alert is
kept 24 hours at most - as os-netreport keeps one it could not send - and 100 at most.

    dc-silent        a domain controller named in Settings sent nothing for the minutes it gives (0: off)
    ldap-failing     the directory could not be asked for a user's groups; once, until it answers again
    address-shared   an address newly shared by two users within the lifetime

An alert names users only when Settings' Log user names is on, as the system log does (settled point 14).
"""

import contextlib
import json
import os
import syslog
import time

STATE = '/var/db/os-useridentity'
OUTBOX = STATE + '/alerts'
SOURCE = 'os-useridentity'
KEEP = 24 * 3600
MOST = 100


def alert(kind, subject, text, facts, now=None, folder=None, log=True):
    """Write one alert; its path, or None when it could not be written (said in the system log)."""
    at = int(now if now is not None else time.time())
    if log:
        syslog.openlog('useridentity', syslog.LOG_PID, syslog.LOG_DAEMON)
        syslog.syslog(syslog.LOG_WARNING, '%s: %s' % (subject, text))
    folder = folder or OUTBOX
    try:
        os.makedirs(folder, mode=0o750, exist_ok=True)
        path = os.path.join(folder, '%s-%d-%d.json' % (kind, at, os.getpid()))
        n = 1
        while os.path.exists(path):
            path = os.path.join(folder, '%s-%d-%d-%d.json' % (kind, at, os.getpid(), n))
            n += 1
        temporary = os.path.join(folder, '.' + os.path.basename(path))
        with open(temporary, 'w', encoding='utf-8') as handle:
            json.dump({'source': SOURCE, 'kind': kind, 'at': at, 'subject': subject, 'text': text, 'facts': facts},
                      handle, sort_keys=True)
        os.chmod(temporary, 0o640)
        os.replace(temporary, path)
        return path
    except OSError as error:
        if log:
            syslog.syslog(syslog.LOG_ERR, 'alert not written: %s' % error)
        return None


def prune(now=None, folder=None, keep=KEEP, most=MOST):
    """Alerts older than keep taken away, then the oldest past most; how many went."""
    now = now if now is not None else time.time()
    folder = folder or OUTBOX
    try:
        names = sorted(n for n in os.listdir(folder) if n.endswith('.json') and not n.startswith('.'))
    except OSError:
        return 0
    dated = []
    for name in names:
        try:
            dated.append((os.stat(os.path.join(folder, name)).st_mtime, name))
        except OSError:
            continue
    dated.sort()
    gone = [name for when, name in dated if when < now - keep]
    left = [name for when, name in dated if when >= now - keep]
    gone += left[:max(0, len(left) - most)]
    for name in gone:
        with contextlib.suppress(OSError):
            os.unlink(os.path.join(folder, name))
    return len(gone)
