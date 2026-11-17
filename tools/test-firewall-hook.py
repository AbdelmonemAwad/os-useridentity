#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""The firewall hook in src/etc/inc/plugins.inc.d/useridentity.inc against the rule-registering object of
every OPNsense it runs on, with PHP and no OPNsense - os-xgs-npu's tools/test-firewall-hook.py, for this
plugin's redirect: 26.7 to 26.7.2 name the port-forward method registerForwardRule() alone; 26.7.3 to
26.7.8 have registerDestinationNatRule() and keep the old name as glue; 27.1, from which their source
says the glue goes. Each gets one redirect for each named domain controller on each chosen interface,
through a name it has; a bad domain controller entry is left out and the others registered; an object
that refuses a rule leaves the hook returning, not stopping the reload (os-xgs-npu issue 969); nothing
is registered while the plugin is off, with no domain controller, or with syslog-ng's source not there;
no redirect either for a port the firewall itself serves - SSH, DNS, the web GUI, and where System:
Settings: Administration moves the web GUI or SSH - nor without the plugin's library that says which
those are; and the hook calls by name only methods every one of them has.

A refused rule is logged with syslog() as the hook does at run time, so a run of this leaves a
"useridentity: ... left out" line in the system log of the machine it runs on.

    python3 tools/test-firewall-hook.py"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(ROOT, 'src', 'etc', 'inc', 'plugins.inc.d', 'useridentity.inc')
# The plugin's library that says which ports the firewall serves: OPNsense's autoloader finds it there
PORTS = os.path.join(ROOT, 'src', 'opnsense', 'mvc', 'app', 'library', 'OPNsense', 'UserIdentity', 'Ports.php')

# What OPNsense\Firewall\Plugin offers for registering rules, by release - os-xgs-npu's reading of
# opnsense/core's Plugin.php at the tags 26.7, 26.7.3 and 26.7.8 (2026-11-02); 27.1 is 26.7.8 without the
# methods its source marks "backwards glue to be removed in 27.1".
CORE_26_7 = ['registerAnchor', 'registerFilterRule', 'registerForwardRule', 'registerDNatRule',
             'registerSNatRule', 'registerNptRule', 'registerTable']
CORE_26_7_3 = CORE_26_7 + ['registerDestinationNatRule', 'registerStaticNatRule', 'registerSourceNatRule']
CORE_27_1 = [m for m in CORE_26_7_3 if m not in ('registerForwardRule', 'registerDNatRule', 'registerSNatRule')]

HARNESS = r'''
$c = json_decode($argv[2], true);
define('USERIDENTITY_SOURCE', $c['source']);
$config = $c['config'];
$body = '';
foreach ($c['methods'] as $m) {
    $body .= "public function $m(...\$a) { " . ($c['refuse'] === $m ? "throw new RuntimeException('refused'); " : '')
        . "\$this->calls[] = ['$m', \$a]; }\n";
}
eval("class FakePlugin { public \$calls = [];\n$body}");
if ($c['ports'] !== '' && is_file($c['ports'])) {
    require $c['ports'];
}
include $argv[1];
$fw = new FakePlugin();
$out = useridentity_firewall($fw);
echo json_encode(['same' => $out === $fw, 'calls' => $fw->calls]);
'''

failures = 0
checks = 0


def check(name, got, want):
    global failures, checks
    checks += 1
    ok = got == want
    failures += 0 if ok else 1
    print('%s %s%s' % ('ok  ' if ok else 'FAIL', name, '' if ok else ' - got %r, want %r' % (got, want)))


def config(general=None, interfaces=None, system=None):
    base = {'enabled': '1', 'domain_controllers': '192.0.2.10,192.0.2.11', 'interfaces': 'lan,opt1', 'port': '514'}
    base.update(general or {})
    out = {'interfaces': interfaces if interfaces is not None else
           {'lan': {'if': 'igb1', 'enable': '1'}, 'opt1': {'if': 'igb2', 'enable': '1'}, 'wan': {'if': 'igb0', 'enable': '1'}},
           'OPNsense': {'UserIdentity': {'general': base}}}
    if system is not None:
        out['system'] = system
    return out


def hook(methods, conf=None, source=None, refuse=None, ports=None):
    path = os.path.join(TMP, 'syslog.json')
    if source is None:
        source = {'written': True, 'port': 5141}
    if source == 'absent':
        if os.path.exists(path):
            os.remove(path)
    else:
        with open(path, 'w', encoding='utf-8') as handle:
            json.dump(source, handle)
    case = json.dumps({'methods': methods, 'config': conf or config(), 'refuse': refuse, 'source': path,
                       'ports': PORTS if ports is None else ports})
    out = subprocess.run(['php', '-r', HARNESS, '--', HOOK, case], capture_output=True, text=True)
    if out.returncode != 0 or not out.stdout.startswith('{'):
        return 'php failed: ' + (out.stderr or out.stdout).strip()[:300]
    return json.loads(out.stdout)


def names(result):
    return [c[0] for c in result['calls']] if isinstance(result, dict) else result


if shutil.which('php') is None:
    print('FAIL php is not installed, so the firewall hook cannot be checked')
    sys.exit(1)

TMP = tempfile.mkdtemp(prefix='test-firewall-hook.')
try:
    def redirect(interface, dc):
        return [1, {'interface': interface, 'ipprotocol': 'inet', 'protocol': 'tcp', 'from': dc, 'to': '(self)',
                    'to_port': '514', 'target': '127.0.0.1', 'local-port': '5141', 'pass': 'pass',
                    'descr': 'User Identity: logon events from a domain controller'}]

    for release, methods, rdr in (('26.7', CORE_26_7, 'registerForwardRule'),
                                  ('26.7.3 to 26.7.8', CORE_26_7_3, 'registerDestinationNatRule'),
                                  ('27.1', CORE_27_1, 'registerDestinationNatRule')):
        got = hook(methods)
        check('OPNsense %s: a redirect for each domain controller on each chosen interface, through %s' % (release, rdr),
              names(got), [rdr] * 4)
        if isinstance(got, dict) and len(got['calls']) == 4:
            check('OPNsense %s: from the domain controller alone, to the firewall, port 514, to 127.0.0.1:5141' % release,
                  [c[1] for c in got['calls']], [redirect('lan', '192.0.2.10'), redirect('lan', '192.0.2.11'),
                                                 redirect('opt1', '192.0.2.10'), redirect('opt1', '192.0.2.11')])
            check('OPNsense %s: the hook hands back the object it was given' % release, got['same'], True)

    got = hook(CORE_26_7_3, config({'domain_controllers': '192.0.2.10, dc3.example.test;2001:db8::10\n192.0.2.300,192.0.2.10'}))
    check('bad domain controller entries - a name, IPv6, no address - left out; the good one once',
          [c[1][1]['from'] for c in got['calls']] if isinstance(got, dict) else got, ['192.0.2.10', '192.0.2.10'])
    got = hook(CORE_26_7_3, config({'port': '1514'}), source={'written': True, 'port': 5142})
    check('the port Settings gives, to the port syslog-ng\'s source is on',
          {(c[1][1]['to_port'], c[1][1]['local-port']) for c in got['calls']} if isinstance(got, dict) else got,
          {('1514', '5142')})
    for refuse in ('registerForwardRule', 'registerDestinationNatRule'):
        methods = CORE_26_7 if refuse == 'registerForwardRule' else CORE_26_7_3
        got = hook(methods, refuse=refuse)
        check('a refused %s does not stop the reload' % refuse, got['same'] if isinstance(got, dict) else got, True)
    check('off: no rule', names(hook(CORE_26_7_3, config({'enabled': '0'}))), [])
    check('no setting at all (a fresh install): no rule',
          names(hook(CORE_26_7_3, {'interfaces': {'lan': {'if': 'igb1', 'enable': '1'}}, 'OPNsense': {}})), [])
    check('no domain controller named: no rule', names(hook(CORE_26_7_3, config({'domain_controllers': ''}))), [])
    check('syslog-ng\'s source not written: no rule', names(hook(CORE_26_7_3, source={'written': False, 'port': 5141,
                                                                                      'reason': 'port 5141 in use'})), [])
    check('syslog-ng\'s source never applied: no rule', names(hook(CORE_26_7_3, source='absent')), [])
    check('a source on a port it may not have: no rule', names(hook(CORE_26_7_3, source={'written': True, 'port': 80})), [])
    check('a port that is none: no rule', names(hook(CORE_26_7_3, config({'port': 'syslog'}))), [])
    for port, what in (('22', 'SSH'), ('53', 'DNS'), ('80', 'the web GUI over HTTP'), ('443', 'the web GUI')):
        check('port %s, %s: no rule - the domain controllers would lose it' % (port, what),
              names(hook(CORE_26_7_3, config({'port': port}))), [])
    check('the web GUI moved to the port Settings gives: no rule',
          names(hook(CORE_26_7_3, config({'port': '8443'}, system={'webgui': {'port': '8443'}}))), [])
    check('SSH moved to it: no rule',
          names(hook(CORE_26_7_3, config({'port': '2222'}, system={'ssh': {'port': '2222'}}))), [])
    check('the web GUI moved to another port: the port taken',
          names(hook(CORE_26_7_3, config({'port': '8443'}, system={'webgui': {'port': '10443'}, 'ssh': ''}))),
          ['registerDestinationNatRule'] * 4)
    got = hook(CORE_26_7_3, ports='')
    check('the plugin\'s library not there: no rule, the reload not stopped',
          (names(got), got['same']) if isinstance(got, dict) else got, ([], True))
    got = hook(CORE_26_7_3, config({'interfaces': 'lan,opt2,opt3'},
                                   {'lan': {'if': 'igb1', 'enable': '1'}, 'opt3': {'if': 'igb3'}}))
    check('an interface not there, one not enabled: none on them, the rest registered',
          [c[1][1]['interface'] for c in got['calls']] if isinstance(got, dict) else got, ['lan', 'lan'])
    got = hook(CORE_26_7_3, {'interfaces': {'lan': {'if': 'igb1', 'enable': '1'}},
                             'OPNsense': {'UserIdentity': {'general': {'enabled': '1', 'domain_controllers': '192.0.2.10'}}}})
    check('no interface chosen in config.xml (as the model\'s default): LAN',
          [c[1][1]['interface'] for c in got['calls']] if isinstance(got, dict) else got, ['lan'])

    # Read from the source: every method the hook calls by its name is one every release above has, and a
    # name chosen at run time is chosen by method_exists().
    with open(HOOK, encoding='utf-8') as f:
        source = f.read()
    named = sorted(set(re.findall(r'\$fw->(\w+)\s*\(', source)))
    everywhere = sorted(set(CORE_26_7) & set(CORE_26_7_3) & set(CORE_27_1))
    check('the hook calls by name only methods every OPNsense has', [m for m in named if m not in everywhere], [])
    check('a name chosen at run time is chosen by method_exists()',
          bool(re.search(r'\$fw->\$\w+\s*\(', source)) <= ('method_exists($fw' in source), True)
finally:
    shutil.rmtree(TMP, ignore_errors=True)

print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
