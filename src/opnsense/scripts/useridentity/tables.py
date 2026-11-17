#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""User Identity's pf tables: what each holds, made to say what the map says.

Each table is an alias of type External in config.xml (settled point 4), written through OPNsense's
own Alias model by aliases.php - so a rule's source or destination names it like any alias, and XGS:
Settings' "Cut open connections when listed" can watch it. OPNsense declares such a table with no
content and leaves what is put in it alone. The plugin's are named uid_ and described 'User Identity: ';
only those whose alias is in config.xml and switched on are written, so pf holds no table of the
plugin's that OPNsense does not know.

The tables are made from the map each time, never edited by the event alone: what a table holds that
the map does not ask for goes, what it lacks is added. So a restart, a missed write or a table
emptied by hand is put right at the next minute's run (expire.py) at the latest.

    tables.py flush-gone   the tables of the plugin's aliases gone, taken out of pf (Apply, removal)
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import settings                                                          # noqa: E402

PFCTL = '/sbin/pfctl'
BATCH = 64


class Pf:
    """pfctl, for this plugin's tables. run(args) -> (exit status, output); a stand-in in the tests."""

    def __init__(self, run=None, pfctl=PFCTL):
        self.pfctl = pfctl
        self.run = run or self._run
        self.errors = []

    def _run(self, args):
        try:
            done = subprocess.run([self.pfctl] + args, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError) as error:
            return 1, str(error)
        return done.returncode, (done.stdout or '') + (done.stderr or '')

    def show(self, table):
        """What the table holds, or None when pf has no such table."""
        status, out = self.run(['-t', table, '-T', 'show'])
        if status != 0:
            return None
        return {line.strip() for line in out.splitlines() if line.strip() and not line.startswith('pfctl')}

    def change(self, table, verb, addresses):
        for i in range(0, len(addresses), BATCH):
            status, out = self.run(['-t', table, '-T', verb] + addresses[i:i + BATCH])
            if status != 0:
                self.errors.append('pfctl -t %s -T %s: %s' % (table, verb, out.strip()[:200]))


def present(aliases):
    """{name} of the plugin's aliases that pf holds a table for: its own, External, switched on."""
    return {name for name, alias in aliases.items() if alias['ours'] and alias['enabled'] and alias['type'] == 'external'}


def sync(pf, want, only=None):
    """Each table of want made to hold what want says, or only those named in only; [(table, added,
    removed)] of what changed. A table pf does not hold yet is filled when its addresses are added."""
    done = []
    for table in sorted(want):
        if only is not None and table not in only:
            continue
        held = pf.show(table) or set()
        add = sorted(want[table] - held)
        remove = sorted(held - want[table])
        if add:
            pf.change(table, 'add', add)
        if remove:
            pf.change(table, 'delete', remove)
        if add or remove:
            done.append((table, len(add), len(remove)))
    return done


def flush_gone(pf, aliases):
    """[table] taken out of pf: the uid_ tables whose alias config.xml no longer has, that no rule uses.
    A table outlives its alias and goes on holding its addresses (os-blocklists, 2026-10-29), and one
    only emptied stays listed until the next boot (os-appcontrol, 2026-11-17): it is killed. One a
    rule still uses, or whose alias is there, is left as it is."""
    status, out = pf.run(['-v', '-s', 'Tables'])
    if status != 0:
        return []
    killed = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2 or not parts[1].startswith(settings.PREFIX) or 'r' in parts[0] or parts[1] in aliases:
            continue
        status, text = pf.run(['-t', parts[1], '-T', 'kill'])
        if status == 0:
            killed.append(parts[1])
        else:
            pf.errors.append('pfctl -t %s -T kill: %s' % (parts[1], text.strip()[:200]))
    return killed


def main(argv):
    if argv[1:2] == ['flush-gone']:
        pf = Pf()
        print(json.dumps({'killed': flush_gone(pf, settings.aliases()), 'errors': pf.errors}))
        return 0
    print('usage: tables.py flush-gone', file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
