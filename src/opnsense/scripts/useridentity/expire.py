#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""The minute's work, from cron (etc/cron.d/useridentity), whether the collector runs or not:

- the mappings whose lifetime ended taken out of the map;
- the MAC check (settled point 7): an address whose MAC in the firewall's ARP or NDP table is not the
  one it had leaves the map - another device has it - while Settings has it on;
- with the plugin off, every mapping forgotten;
- the mappings a source switched off gave last taken out: RADIUS accounting or the captive portal
  turned off in Settings, a RADIUS client no longer named, a portal's zone switched off - a domain
  controller no longer named leaves its mappings to their lifetime;
- every table of the plugin's made again from the map, so one emptied by hand, or written while the
  collector was down, is right within a minute; and the table of an alias of the plugin's switched off -
  kept because a rule or a setting names it - kept empty;
- the history kept as long as Settings says, and the alerts no one collected 24 hours;
- an alert for each domain controller silent for the minutes Settings gives, once until it speaks again.

All of the map's work is done under its lock, as the collector does its own. It prints a JSON summary
and never fails its caller.

    expire.py           the minute's run
    expire.py --flush   every mapping forgotten and the tables emptied now (the page's Forget all)
"""

import json
import os
import sys
import syslog
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import engine                                                            # noqa: E402
import host                                                              # noqa: E402
import outbox                                                            # noqa: E402
import settings                                                          # noqa: E402
import tables                                                            # noqa: E402

GROUPS = engine.STATE + '/groups.json'
SOURCES = engine.STATE + '/sources.json'
SILENT = engine.STATE + '/silent.json'
STATUS = engine.STATE + '/minute.json'


def silent(conf, now, sources=None, notes=None):
    """[domain controller] newly silent for alert_silent seconds: alerted once, again only after it
    has been heard from."""
    if not conf['enabled'] or conf['alert_silent'] <= 0:
        return []
    sources = sources if sources is not None else engine.read_json(SOURCES, {})
    notes_path = notes or SILENT
    said = set(engine.read_json(notes_path, {}).get('silent', []))
    since = sources.get('since') or now
    newly = []
    for dc in conf['dcs']:
        seen = (sources.get('senders', {}).get(dc) or {}).get('last_line') or since
        if now - seen >= conf['alert_silent']:
            if dc not in said:
                said.add(dc)
                newly.append(dc)
                minutes = int((now - seen) // 60)
                outbox.alert('dc-silent', 'User Identity: domain controller %s is silent' % dc,
                             'No line has come from %s for %d minutes: no logon there maps an address.' % (dc, minutes),
                             {'domain_controller': dc, 'minutes': minutes}, now=now)
        else:
            said.discard(dc)
    said &= set(conf['dcs'])
    engine.write_json(notes_path, {'silent': sorted(said)}, mode=0o640)
    return newly


def kept(conf):
    """Whether a mapping's source is still on: RADIUS accounting and the client named, the captive portal
    and the zone of the session - their logoffs are read no more once off. A domain controller's mapping
    is kept whether its domain controller is still named or not: none ever says a user left, so its
    mappings end at their lifetime as they would have - a domain controller retired takes no user out
    of a table at the next minute. Forget every mapping ends them at once."""
    clients = set(conf['radius_clients'])

    def keep(entry):
        kind = entry.get('kind', 'ad')
        if kind == 'radius':
            return conf['radius'] and settings.address_key(entry.get('source', '')) in clients
        if kind == 'portal':
            return conf['portal'] and entry.get('source', '') in conf['zones']
        return True
    return keep


def run(conf=None, now=None, pf=None, macs=None, flush=False):
    conf = conf if conf is not None else settings.read()
    now = now if now is not None else time.time()
    pf = pf or tables.Pf()
    summary = {'at': int(now), 'expired': 0, 'mac': 0, 'off': 0, 'flushed': 0, 'tables': [], 'errors': []}
    if not conf['read']:
        summary['errors'].append('config.xml could not be read: nothing done')
        return summary
    with engine.locked():
        state = engine.load()
        changes = engine.expire(state, now, conf['lifetime'])
        if flush or not conf['enabled']:
            changes += engine.flush(state)
        else:
            changes += engine.drop(state, kept(conf))
            if conf['mac_check'] and state['map']:
                changes += engine.check_macs(state, macs() if macs else host.macs())
        engine.save(state, writer='minute')
        known = engine.read_json(GROUPS, {})
        if (flush or not conf['enabled']) and known.get('users'):
            # with the map, what the directory said of its users: only the live map is kept
            known['users'] = {}
            engine.write_json(GROUPS, known, mode=0o640)
        groups = known.get('users', {})
        aliases = settings.aliases()
        want = engine.tables(state, groups, conf, tables.present(aliases))
        for name in tables.switched_off(aliases) - set(want):
            want[name] = set()
        summary['tables'] = tables.sync(pf, want)
    summary['expired'] = sum(1 for c in changes if c[0] == 'left' and c[2][1] == 'expired')
    summary['mac'] = sum(1 for c in changes if c[0] == 'left' and c[2][1] == 'mac')
    summary['off'] = sum(1 for c in changes if c[0] == 'left' and c[2][1] == 'source off')
    summary['flushed'] = sum(1 for c in changes if c[0] == 'left' and c[2][1] == 'flushed')
    summary['mapped'] = len(state['map'])
    summary['errors'] = pf.errors
    line = engine.summary(changes, conf['log_names'])
    if line:
        syslog.syslog(syslog.LOG_NOTICE, line)
    engine.record(changes, conf['history_days'], now)
    engine.prune(conf['history_days'], now)
    outbox.prune(now)
    summary['silent'] = silent(conf, now)
    engine.write_json(STATUS, summary, mode=0o640)
    return summary


def main(argv):
    syslog.openlog('useridentity', syslog.LOG_PID, syslog.LOG_DAEMON)
    try:
        print(json.dumps(run(flush='--flush' in argv)))
    except Exception as error:                                           # noqa: BLE001
        syslog.syslog(syslog.LOG_ERR, 'the minute\'s run stopped: %s' % traceback.format_exc().strip().splitlines()[-1])
        print(json.dumps({'errors': ['stopped: %s' % error]}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
