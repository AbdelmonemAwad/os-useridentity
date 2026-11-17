#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""The receiving end (settled point 1): OPNsense's own syslog-ng, with a source of the plugin's on
127.0.0.1 that the domain controllers' lines reach through the pf redirect the firewall hook registers
- os-xgs-npu's way for the coprocessor's log - and from it to the collector's socket. A file of
syslog-ng's include directory, /usr/local/etc/syslog-ng.conf.d/useridentity.conf, which OPNsense's
syslog-ng.conf includes.

One source that cannot bind stops syslog-ng whole, and every log of OPNsense's with it (os-xgs-npu,
xgs.inc). So the file is written only when the port is one a source may take - 1024 to 65535, not
5140, os-xgs-npu's - with no other program listening on it (sockstat), and only when syslog-ng reads
its whole configuration with it (syslog-ng --syntax-only); else it is taken away, and the page says
why. Off, or with no domain controller named, it is taken away too. The source is a source of its
own, never s_all, so none of OPNsense's filters files the lines: no event is written to a log.

What was done is kept in /var/db/os-useridentity/syslog.json, which the firewall hook reads: the
redirect is registered only while the source is there, so no line goes to a port another program holds.

    syslogng.py apply    write or take away the file; JSON: written, changed, port, reason. The caller
                         restarts syslog-ng when changed (configctl syslog restart).
    syslogng.py status   what syslog.json says
"""

import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import engine                                                            # noqa: E402
import settings                                                          # noqa: E402

CONF = '/usr/local/etc/syslog-ng.conf.d/useridentity.conf'
MAIN = '/usr/local/etc/syslog-ng.conf'
STATUS = engine.STATE + '/syslog.json'
SOCKET = '/var/run/useridentity.sock'
SYSLOG_NG = '/usr/local/sbin/syslog-ng'
SOCKSTAT = '/usr/bin/sockstat'
TAKEN = (5140,)

TEMPLATE = '''# os-useridentity: the domain controllers' logon events (scripts/useridentity/syslogng.py writes
# this file, and takes it away when the plugin is off). pf redirects port %(port)d of the chosen
# interfaces, from the named domain controllers alone, to this source; each line goes to the
# collector as "$SOURCEIP $MSG", and to no log file.
source s_useridentity {
    network(ip("127.0.0.1") port(%(local)d) transport("tcp") flags(no-parse) log-msg-size(65536)
            max-connections(64));
};

destination d_useridentity {
    unix-dgram("%(socket)s" template("${SOURCEIP} ${MSG}"));
};

log {
    source(s_useridentity);
    destination(d_useridentity);
};
'''


def content(conf):
    return TEMPLATE % {'port': conf['port'], 'local': conf['local_port'], 'socket': SOCKET}


def listeners(port, run=None):
    """[(command, local address)] of the TCP listeners on the port, from sockstat; None when it cannot
    be read."""
    run = run or _run
    status, out = run([SOCKSTAT, '-46', '-l', '-q', '-P', 'tcp', '-p', str(port)])
    if status != 0:
        return None
    found = []
    for line in out.splitlines():
        words = line.split()
        if len(words) >= 6 and words[5].rsplit(':', 1)[-1] == str(port):
            found.append((words[1], words[5]))
    return found


def _run(args):
    try:
        done = subprocess.run(args, capture_output=True, text=True, errors='replace', timeout=60)
    except (OSError, subprocess.SubprocessError) as error:
        return 1, str(error)
    return done.returncode, (done.stdout or '') + (done.stderr or '')


def read(path):
    try:
        with open(path, encoding='utf-8') as handle:
            return handle.read()
    except OSError:
        return None


def remove(path):
    try:
        os.unlink(path)
        return True
    except OSError:
        return False


def apply(conf=None, path=None, status_path=None, run=None, now=None):
    """Write or take away the source - see the top - and say what was done."""
    conf = conf if conf is not None else settings.read()
    path, status_path = path or CONF, status_path or STATUS
    run = run or _run
    now = int(now if now is not None else time.time())
    before = read(path)
    port = conf['local_port']
    out = {'written': False, 'changed': False, 'port': port, 'reason': '', 'at': now}

    def away(reason):
        out['reason'] = reason
        out['changed'] = remove(path) or out['changed']
        return out

    if not conf['read']:
        out['reason'] = 'config.xml could not be read: left as it was'
        out['written'] = before is not None
        return finish(out, status_path)
    if not conf['enabled']:
        return finish(away('off'), status_path)
    if not conf['dcs']:
        return finish(away('no domain controller named'), status_path)
    if not 1024 <= port <= 65535 or port in TAKEN:
        return finish(away('port %d may not be used' % port), status_path)
    held = listeners(port, run)
    if held is None:
        return finish(away('sockstat could not be read, so port %d is not known to be free' % port), status_path)
    ours = before is not None and 'port(%d)' % port in before
    others = [command for command, _ in held if not (command == 'syslog-ng' and ours)]
    if others:
        return finish(away('port %d on 127.0.0.1 is in use by %s' % (port, ', '.join(sorted(set(others))))), status_path)
    want = content(conf)
    if before != want:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path + '.new', 'w', encoding='utf-8') as handle:
                handle.write(want)
            os.chmod(path + '.new', 0o644)
            os.replace(path + '.new', path)
        except OSError as error:
            remove(path + '.new')
            return finish(away('not written: %s' % error), status_path)
        out['changed'] = True
    status, said = run([SYSLOG_NG, '--syntax-only', '--cfgfile=' + MAIN])
    if status != 0:
        first = next((line.strip() for line in said.splitlines() if line.strip()), 'no reason given')
        return finish(away('syslog-ng refused its configuration with it: %s' % first[:200]), status_path)
    out['written'] = True
    return finish(out, status_path)


def finish(out, status_path):
    try:
        engine.write_json(status_path, out, mode=0o644)
    except OSError:
        pass
    return out


def main(argv):
    if argv[1:2] == ['apply']:
        print(json.dumps(apply()))
        return 0
    if argv[1:2] == ['status']:
        print(json.dumps(engine.read_json(STATUS, {})))
        return 0
    print('usage: syslogng.py apply|status', file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
