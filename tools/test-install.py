#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""The installer, the removal, the package's three scripts, place-menu.sh and the rc script, run in a
temporary root.

As os-appcontrol's test: the scripts are run with sh from a copy of the repository in which their
absolute paths are moved into the temporary root - /usr/local, /var/db/os-useridentity, /var/run,
PHP's /var/lib/php/tmp, the caches in /tmp, /conf/config.xml, /sbin/pfctl, /bin/pkill,
/usr/sbin/daemon, /etc/rc.subr - and stand-ins answer for what only a firewall has: service,
configctl, pfctl, pkill, daemon and rc.subr, each writing down how it was called (pkill kills nothing
here). Two things FreeBSD does otherwise are bridged in the copy: BSD's `cp -R dir/` copies what dir
holds, written `dir/.` for GNU's cp; BSD's `mktemp -t prefix` takes a prefix, which a stand-in gives GNU's
mktemp; and install's -o root -g wheel, which a test run by anyone cannot take, is left out by a
stand-in.

What is checked is what the scripts do: which files are laid down with which modes, where the menu
goes, that nothing is copied when a file has a syntax error, the page's Apply done in its order - off
by default, so the collector stopped and the map forgotten before the aliases, on, the collector
started after them, syslog-ng restarted only when its source changed - the collector started and
stopped by the rc script, the collector stopped, the map forgotten and the aliases taken out before
the files go, syslog-ng's source taken away by every removal, the tables of aliases gone taken out of
pf, nothing of the plugin left, and nothing done by the old package's pre-deinstall in an upgrade.

    python3 tools/test-install.py"""
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = ['install/install.sh', 'install/uninstall.sh', 'pkg/post-install.sh', 'pkg/pre-deinstall.sh',
           'pkg/post-deinstall.sh', 'src/opnsense/scripts/useridentity/place-menu.sh',
           'src/opnsense/scripts/useridentity/settings.py', 'src/etc/rc.d/useridentity']
LOCAL = '/usr/local'
MENU = '/usr/local/opnsense/mvc/app/models/OPNsense/UserIdentity/Menu/Menu.xml'
XGS = '/usr/local/opnsense/mvc/app/models/OPNsense/XGS/Menu/Menu.xml'
HOOK = '/usr/local/etc/inc/plugins.inc.d/useridentity.inc'
RC = '/usr/local/etc/rc.d/useridentity'
SOURCE = '/usr/local/etc/syslog-ng.conf.d/useridentity.conf'
STATE = '/var/db/os-useridentity'
# rc.subr as far as rc.d/useridentity asks it
RC_SUBR = ('load_rc_config() { :; }\nwarn() { echo "${name}: WARNING: $*" >&2; }\n'
           'run_rc_command() {\n\tcase "$1" in\n\t*start) ${start_cmd} ;;\n\t*stop) ${stop_cmd} ;;\n'
           '\t*status) ${status_cmd} ;;\n\tesac\n}\n')
CACHES = ['/var/lib/php/tmp/opnsense_menu_cache.xml', '/var/lib/php/tmp/opnsense_acl_cache.json',
          '/tmp/opnsense_menu_cache.xml', '/tmp/opnsense_acl_cache.json']
COMMIT = '0123456789abcdef0123456789abcdef01234567'
ON = '<opnsense><OPNsense><UserIdentity><general><enabled>1</enabled></general></UserIdentity></OPNsense></opnsense>'
OFF = '<opnsense><system/></opnsense>'
APPLY_OFF = ['configctl useridentity stop hook=yes', 'configctl useridentity flush hook=yes',
             'configctl useridentity apply hook=yes', 'configctl useridentity source hook=yes',
             'configctl filter reload skip_alias hook=yes', 'configctl cron restart hook=yes',
             'configctl useridentity gone hook=yes']

failures = 0
checks = 0


def check(name, got, want):
    global failures, checks
    checks += 1
    ok = got == want
    failures += 0 if ok else 1
    print('%s %s%s' % ('ok  ' if ok else 'FAIL', name, '' if ok else ' - got %r, want %r' % (got, want)))


class Box:
    """A temporary root, a copy of the repository whose scripts work in it, and the stand-ins."""

    def __init__(self, tmp):
        self.fake = os.path.join(tmp, 'root')
        self.repo = os.path.join(tmp, 'repo')
        self.bin = os.path.join(tmp, 'bin')
        self.calls = os.path.join(tmp, 'calls')
        self.tables = os.path.join(tmp, 'pf-tables')
        self.source_answer = os.path.join(tmp, 'source-answer')
        os.makedirs(self.fake)
        os.makedirs(self.bin)
        shutil.copytree(ROOT, self.repo, ignore=shutil.ignore_patterns('.git', '__pycache__', '*.pyc'))
        # every file as a checkout has it, not runnable: the scripts set what must be
        for base, _, files in os.walk(self.repo):
            for name in files:
                os.chmod(os.path.join(base, name), 0o644)
        for script in SCRIPTS:
            path = os.path.join(self.repo, script)
            text = open(path, encoding='utf-8').read()
            # a path where one starts, not one inside another (/var/lib/php/tmp/ holds /tmp/ too)
            text = re.sub(r'(?<![\w/.-])(/usr/local/|/var/lib/php/tmp/|/tmp/opnsense_|/sbin/pfctl|/var/db/os-useridentity|'
                          r'/var/run/useridentity|/conf/config\.xml|/bin/pkill|/usr/sbin/daemon\b|/etc/rc\.subr)',
                          lambda m: self.fake + m.group(1), text)
            text = text.replace('cp -R "${HERE}/src/" ', 'cp -R "${HERE}/src/." ')
            with open(path, 'w', encoding='utf-8', newline='\n') as handle:
                handle.write(text)
        hook = self.fake + HOOK
        log = self.calls
        self.stub('configctl', 'echo "configctl $* hook=$([ -f %s ] && echo yes || echo no)" >> %s\n'
                               'case "$*" in "useridentity source") cat %s 2>/dev/null || echo \'{"changed": false}\' ;;\n'
                               '*) echo OK ;; esac' % (hook, log, self.source_answer))
        self.stub('service', 'echo "service $*" >> %s' % log)
        self.stub('mktemp', 'if [ "$1" = -d ] && [ "$2" = -t ]; then exec /usr/bin/env mktemp -d '
                            '"${TMPDIR:-/tmp}/$3.XXXXXX"; fi\nexec /usr/bin/env mktemp "$@"', real='mktemp')
        self.stub('install', 'a=""\nwhile [ $# -gt 0 ]; do case "$1" in -o|-g) shift 2 ;; *) a="$a \'$1\'"; shift ;; '
                             'esac; done\neval exec /usr/bin/env install $a', real='install')
        os.makedirs(self.fake + '/sbin')
        self.write(self.fake + '/sbin/pfctl', '#!/bin/sh\necho "pfctl $*" >> %s\n'
                   'case "$*" in "-v -s Tables") cat %s 2>/dev/null ;; esac\n' % (log, self.tables), 0o755)
        os.makedirs(self.fake + '/bin')
        self.write(self.fake + '/bin/pkill', '#!/bin/sh\necho "pkill $*" >> %s\nexit 1\n' % log, 0o755)
        self.write(self.fake + '/usr/sbin/daemon', '#!/bin/sh\necho "daemon $*" >> %s\n' % log, 0o755)
        self.write(self.fake + '/etc/rc.subr', RC_SUBR)
        os.makedirs(self.fake + '/conf')
        self.config(OFF)

    def config(self, text):
        self.write(self.fake + '/conf/config.xml', text)

    def source_changes(self, changed):
        self.write(self.source_answer, '{"written": %s, "changed": %s}\n' % (('true',) * 2 if changed else ('false',) * 2))

    def stub(self, name, body, real=None):
        path = os.path.join(self.bin, name)
        if real:
            # the stand-in must not find itself: the real one is looked for past this directory
            body = body.replace('/usr/bin/env %s' % real, shutil.which(real, path=os.defpath) or '/usr/bin/' + real)
        self.write(path, '#!/bin/sh\n' + body + '\n', 0o755)

    @staticmethod
    def write(path, text, mode=0o644):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8', newline='\n') as handle:
            handle.write(text)
        os.chmod(path, mode)

    def run(self, script, *args, env=None):
        return self.sh(os.path.join(self.repo, script), *args, env=env)

    def sh(self, path, *args, env=None):
        environ = dict(os.environ, PATH=self.bin + os.pathsep + os.environ.get('PATH', ''),
                       TMPDIR=os.path.dirname(self.fake))
        environ.update(env or {})
        done = subprocess.run(['sh', path] + list(args), env=environ, capture_output=True, text=True, timeout=300)
        return done.returncode, done.stdout + done.stderr

    def called(self, prefix=''):
        try:
            return [c for c in open(self.calls, encoding='utf-8').read().splitlines() if c.startswith(prefix)]
        except OSError:
            return []

    def forget(self):
        if os.path.exists(self.calls):
            os.remove(self.calls)

    def plugin_files(self):
        """Every file under the root that the plugin has a hand in."""
        out = []
        for base, _, files in os.walk(self.fake):
            for name in files:
                path = os.path.join(base, name)[len(self.fake):]
                if 'useridentity' in path.lower():
                    out.append(path)
        return sorted(out)

    def mode(self, path):
        return stat.S_IMODE(os.stat(self.fake + path).st_mode)

    def read(self, path):
        try:
            return open(self.fake + path, encoding='utf-8').read()
        except OSError:
            return None

    def python3(self):
        """/usr/local/bin/python3 of the root: the test's own python3."""
        self.write(self.fake + '/usr/local/bin/python3', '#!/bin/sh\nexec %s "$@"\n' % sys.executable, 0o755)


def source_files():
    out = []
    for base, _, files in os.walk(os.path.join(ROOT, 'src')):
        for name in files:
            if name.endswith('.pyc') or '__pycache__' in base:
                continue
            out.append(LOCAL + os.path.join(base, name)[len(os.path.join(ROOT, 'src')):].replace(os.sep, '/'))
    return sorted(out)


with tempfile.TemporaryDirectory() as tmp:
    box = Box(tmp)
    menu_own = open(os.path.join(ROOT, 'src/opnsense/scripts/useridentity/menu/own.xml'), encoding='utf-8').read()
    menu_xgs = open(os.path.join(ROOT, 'src/opnsense/scripts/useridentity/menu/xgs.xml'), encoding='utf-8').read()
    place = 'src/opnsense/scripts/useridentity/place-menu.sh'

    # place-menu.sh: XGS where os-xgs-npu's menu is, Firewall where it is not
    for cache in CACHES:
        box.write(box.fake + cache, 'cached')
    rc, out = box.run(place)
    check('place-menu.sh without os-xgs-npu: own, the Firewall menu file', (rc, out.strip(), box.read(MENU)),
          (0, 'own', menu_own))
    check('place-menu.sh: the menu caches cleared', [c for c in CACHES[::2] if os.path.exists(box.fake + c)], [])
    box.write(box.fake + XGS, '<menu/>')
    rc, out = box.run(place)
    check('place-menu.sh with os-xgs-npu: xgs, the XGS menu file, order 60', (rc, out.strip(), box.read(MENU),
          'order="60"' in menu_xgs), (0, 'xgs', menu_xgs, True))
    os.remove(box.fake + XGS)
    shutil.rmtree(box.fake + LOCAL)

    # install.sh: nothing copied when a file of the tree has a syntax error
    for broken, bad in (('src/opnsense/mvc/app/library/OPNsense/UserIdentity/Aliases.php', lambda t: t.replace('class Aliases', 'class Aliases {', 1)),
                        ('src/opnsense/scripts/useridentity/collector.py', lambda t: t + '\ndef broken(:\n')):
        path = os.path.join(box.repo, broken)
        kept = open(path, encoding='utf-8').read()
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(bad(kept))
        rc, out = box.run('install/install.sh')
        check('install.sh, %s with a syntax error: stopped, nothing copied, nothing asked' % os.path.basename(broken),
              (rc != 0, box.plugin_files(), box.called()), (True, [], []))
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(kept)

    # install.sh, a fresh install: off by default
    for cache in CACHES:
        box.write(box.fake + cache, 'cached')
    box.write(os.path.join(box.repo, '.source-commit'), COMMIT + ' 2026-11-17T12:00:00+00:00\n')
    box.forget()
    rc, out = box.run('install/install.sh')
    check('install.sh: done, where the page is, and that it is off', (rc, out.strip().splitlines()[-1:]),
          (0, ['User Identity installed: Firewall > User Identity (off until domain controllers and groups are named in Settings)']))
    laid = [f for f in box.plugin_files() if f.startswith(LOCAL) and not f.startswith('/usr/local/share/') and f != MENU]
    check('install.sh: every file of src/ laid down, and nothing else', laid, source_files())
    check('install.sh: the menu file placed, the caches cleared', (box.read(MENU), [c for c in CACHES if os.path.exists(box.fake + c)]),
          (menu_own, []))
    check('install.sh, off: the collector stopped and the map forgotten, then the aliases, the source, the filter, cron, '
          'the tables gone - syslog-ng left alone, its source unchanged', box.called('configctl') + box.called('service'),
          APPLY_OFF + ['service configd restart'])
    check('install.sh: the modes', [box.mode(p) for p in (
        '/usr/local/opnsense/scripts/useridentity/collector.py', '/usr/local/opnsense/scripts/useridentity/aliases.php',
        '/usr/local/opnsense/scripts/useridentity/place-menu.sh', RC, HOOK, '/usr/local/etc/cron.d/useridentity',
        '/usr/local/opnsense/service/conf/actions.d/actions_useridentity.conf',
        '/usr/local/opnsense/scripts/useridentity/i18n/ui/source.json',
        '/usr/local/opnsense/scripts/useridentity/release-keys/xgs-release-key-13ed7f86.pub')],
        [0o755, 0o755, 0o755, 0o755, 0o644, 0o644, 0o644, 0o644, 0o644])
    check('install.sh: the state directory, 0750', box.mode(STATE), 0o750)
    check('install.sh: the commit recorded for the self-update',
          '"commit": "%s"' % COMMIT in (box.read('/usr/local/share/os-useridentity/installed.json') or ''), True)

    # install.sh again: on, its source changed, os-xgs-npu there
    box.config(ON)
    box.source_changes(True)
    box.write(box.fake + XGS, '<menu/>')
    box.forget()
    rc, out = box.run('install/install.sh')
    check('install.sh, on: XGS > User Identity, mapping', (rc, out.strip().splitlines()[-1:]),
          (0, ['User Identity installed: XGS > User Identity (mapping)']))
    check('install.sh, on: the aliases, the source, syslog-ng restarted as its source changed, the filter, cron, the '
          'tables gone, the collector started', box.called('configctl'),
          ['configctl useridentity apply hook=yes', 'configctl useridentity source hook=yes', 'configctl syslog restart hook=yes',
           'configctl filter reload skip_alias hook=yes', 'configctl cron restart hook=yes', 'configctl useridentity gone hook=yes',
           'configctl useridentity restart hook=yes'])

    # the rc script, as installed
    run_dir = box.fake + '/var/run'
    box.forget()
    rc, out = box.sh(box.fake + RC, 'onestart')
    check('rc.d/useridentity onestart: the collector under daemon(8), started again 10 s after it ends',
          (rc, box.called()), (0, ['daemon -f -R 10 -t useridentity -P %s/useridentity.daemon.pid -p %s/useridentity.pid '
                                   '%s/usr/local/opnsense/scripts/useridentity/collector.py run' % (run_dir, run_dir, box.fake)]))
    box.write(run_dir + '/useridentity.sock', '')
    rc, out = box.sh(box.fake + RC, 'onestop')
    check('rc.d/useridentity onestop, nothing running: said, the socket taken away',
          (rc, out.strip(), os.path.exists(run_dir + '/useridentity.sock')), (0, 'useridentity is not running.', False))
    # daemon(8) supervising the collector, as ps shows it
    daemon = subprocess.Popen(['daemon: useridentity[1]', '60'], executable=shutil.which('sleep'))
    threading.Thread(target=daemon.wait, daemon=True).start()
    box.write(run_dir + '/useridentity.daemon.pid', str(daemon.pid))
    box.write(run_dir + '/useridentity.sock', '')
    rc, out = box.sh(box.fake + RC, 'onestop')
    check('rc.d/useridentity onestop, the collector running: stopped, its pidfiles and socket taken away',
          (rc, daemon.poll() is not None, os.path.exists(run_dir + '/useridentity.daemon.pid'),
           os.path.exists(run_dir + '/useridentity.sock')), (0, True, False, False))
    box.write(run_dir + '/useridentity.pid', '1')
    rc, out = box.sh(box.fake + RC, 'onestatus')
    check('rc.d/useridentity status: a pidfile naming a process that is not the collector is not believed',
          (rc, out.strip()), (1, 'useridentity is not running.'))

    # uninstall.sh: the collector, the map and the aliases first, then syslog-ng's source, then the files
    os.remove(box.fake + XGS)
    box.write(box.fake + RC, '#!/bin/sh\necho "rc.d useridentity $* hook=$([ -f %s ] && echo yes || echo no)" >> %s\n'
              % (box.fake + HOOK, box.calls), 0o755)
    box.write(box.fake + SOURCE, 'source s_useridentity {};\n')
    box.write(box.fake + STATE + '/map.json', '{}')
    box.write(run_dir + '/useridentity.sock', '')
    os.makedirs(box.fake + '/usr/local/opnsense/scripts/useridentity/__pycache__', exist_ok=True)
    box.write(box.tables, '-pa----\tuid_grp_Gone\n-pa-r--\tuid_grp_Used\n-pa----\tuid_grp_Staff\n-pa----\tbogons\n')
    box.config(ON.replace('</OPNsense>', '<Firewall><Alias><aliases><alias><name>uid_grp_Staff</name></alias>'
                                         '</aliases></Alias></Firewall></OPNsense>'))
    box.forget()
    rc, out = box.run('install/uninstall.sh')
    calls = box.called()
    check('uninstall.sh: the collector stopped, the map forgotten and the aliases taken out while the hook is there, first',
          calls[:5], ['rc.d useridentity onestop hook=yes', 'pkill -f daemon: [u]seridentity\\[',
                      'pkill -f %s/usr/local/opnsense/scripts/[u]seridentity/' % box.fake,
                      'configctl useridentity flush hook=yes', 'configctl useridentity remove hook=yes'])
    check('uninstall.sh: syslog-ng\'s source taken away, syslog-ng restarted to let its port go',
          (os.path.exists(box.fake + SOURCE), calls[5]), (False, 'configctl syslog restart hook=yes'))
    check('uninstall.sh: nothing of the plugin left - files, state, pidfiles, socket', box.plugin_files(), [])
    check('uninstall.sh: then configd, the filter and cron, without the hook',
          [c for c in calls if c.startswith(('service', 'configctl filter', 'configctl cron'))],
          ['service configd restart', 'configctl filter reload skip_alias hook=no', 'configctl cron restart hook=no'])
    check('uninstall.sh: the table of an alias gone taken out of pf; one a rule uses, one whose alias is there, pf\'s own left',
          box.called('pfctl -t'), ['pfctl -t uid_grp_Gone -T kill'])
    check('uninstall.sh: said', (rc, out.strip().splitlines()[-1]), (0, 'User Identity removed; its settings stay in config.xml'))
    box.forget()
    rc, out = box.run('install/uninstall.sh')
    check('uninstall.sh again, nothing there: no syslog-ng restart, ends 0', (rc, box.called('configctl syslog')), (0, []))

    # the package: pkg lays down the files of src/; post-install does the Apply; the old package's
    # pre-deinstall does nothing in an upgrade; a removal: the collector, the map, the aliases, the source,
    # then post-deinstall
    shutil.copytree(os.path.join(box.repo, 'src'), box.fake + LOCAL, dirs_exist_ok=True)
    for path in source_files():
        os.chmod(box.fake + path, 0o755 if open(box.fake + path, 'rb').read(2) == b'#!' else 0o644)
    box.write(box.fake + '/usr/local/sbin/configctl', '#!/bin/sh\nexec configctl "$@"\n', 0o755)
    box.write(box.fake + '/usr/local/etc/rc.d/configd', '#!/bin/sh\nservice configd "$@"\n', 0o755)
    box.python3()
    box.config(OFF)
    box.source_changes(False)
    box.forget()
    rc, out = box.run('pkg/post-install.sh')
    check('post-install.sh: the menu placed, said, off', (rc, box.read(MENU) == menu_own, out.strip().splitlines()[-1]),
          (0, True, 'User Identity installed: the page is at Firewall > User Identity (off until domain controllers and '
                    'groups are named in Settings)'))
    check('post-install.sh, off: configd, then the Apply in its order', box.called('service') + box.called('configctl'),
          ['service configd restart'] + APPLY_OFF)
    check('post-install.sh: the state directory', box.mode(STATE), 0o750)
    box.config(ON)
    box.forget()
    rc, out = box.run('pkg/post-install.sh')
    check('post-install.sh, on (an upgrade): the collector started again on the new code',
          box.called('configctl useridentity')[-1:], ['configctl useridentity restart hook=yes'])
    box.write(box.fake + RC, '#!/bin/sh\necho "rc.d useridentity $*" >> %s\n' % box.calls, 0o755)
    box.write(box.fake + SOURCE, 'source s_useridentity {};\n')
    box.forget()
    rc, out = box.run('pkg/pre-deinstall.sh', env={'PKG_UPGRADE': 'true'})
    check('pre-deinstall.sh in an upgrade: nothing done', (rc, box.called(), os.path.exists(box.fake + SOURCE)), (0, [], True))
    rc, out = box.run('pkg/pre-deinstall.sh', env={'PKG_UPGRADE': ''})
    check('pre-deinstall.sh in a removal: the collector stopped, the map forgotten, the aliases taken out, the source '
          'taken away and syslog-ng restarted', (box.called(), os.path.exists(box.fake + SOURCE)),
          (['rc.d useridentity onestop', 'pkill -f daemon: [u]seridentity\\[',
            'pkill -f %s/usr/local/opnsense/scripts/[u]seridentity/' % box.fake, 'configctl useridentity flush hook=yes',
            'configctl useridentity remove hook=yes', 'configctl syslog restart hook=yes'], False))
    os.makedirs(box.fake + '/usr/local/opnsense/scripts/useridentity/__pycache__', exist_ok=True)
    box.write(box.fake + '/usr/local/opnsense/scripts/useridentity/__pycache__/collector.cpython-311.pyc', 'x')
    for path in source_files():
        os.remove(box.fake + path)
    box.write(box.fake + '/var/run/useridentity.pid', '12345')
    box.write(box.fake + STATE + '/map.json', '{}')
    box.config(OFF)
    box.forget()
    rc, out = box.run('pkg/post-deinstall.sh')
    check('post-deinstall.sh: nothing of the plugin left - the menu file, Python\'s caches, the state, the pidfile',
          box.plugin_files(), [])
    check('post-deinstall.sh: configd, the filter and cron, the tables of aliases gone taken out of pf',
          box.called('service') + box.called('configctl') + box.called('pfctl -t'),
          ['service configd restart', 'configctl filter reload skip_alias hook=no', 'configctl cron restart hook=no',
           'pfctl -t uid_grp_Gone -T kill', 'pfctl -t uid_grp_Staff -T kill'])

print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
