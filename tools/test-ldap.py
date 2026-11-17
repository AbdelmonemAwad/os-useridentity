#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
"""ldap_groups.py against a stand-in of ldap3 that answers as the lab's domain controller did (phase
0's A3) - and, where ldap3 itself is installed (checks.yml installs 2.9.1, OPNsense 26.7's), against
its own constructors: what is asked, how, and what is made of the answers.

What is checked: the filter's escaping - a user's name from an event and a group's DN can hold any of
* ( ) \\ NUL / - and the filters built from the entry of System: Access: Servers (its user attribute,
extended query, containers and scope); TLS as OPNsense's connector does it, StartTLS, SSL or none,
the certificate against /usr/local/etc/ssl/cert.pem; a user in a group directly, through a group in
it by the in-chain rule, or not; a group named by its name or its DN, or not there; a server refusing
the in-chain rule asked it no more, memberOf deciding; Nested groups off asking nothing more; and the
bind password in no answer and no error.

    python3 tools/test-ldap.py"""
import os
import re
import ssl
import sys
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src', 'opnsense', 'scripts', 'useridentity'))
import ldap_groups                                                       # noqa: E402
import settings                                                          # noqa: E402

failures = 0
checks = 0
SECRET = 'not-a-real-one'


def check(name, got, want):
    global failures, checks
    checks += 1
    ok = got == want
    failures += 0 if ok else 1
    print('%s %s%s' % ('ok  ' if ok else 'FAIL', name, '' if ok else ' - got %r, want %r' % (got, want)))


class Refused(Exception):
    pass


def standin(directory, refuse_chain=False, fail_bind=None):
    """A module that looks like ldap3 as far as ldap_groups.py uses it. directory: {dn: {'memberOf': [...],
    'cn': ..., 'sAMAccountName': ..., 'objectClass': ..., 'chain': [group DNs it is in, nested included]}}.
    Every call is written down in module.calls."""
    module = types.SimpleNamespace(NONE='NO_INFO', SIMPLE='SIMPLE', ANONYMOUS='ANONYMOUS', BASE='BASE', LEVEL='LEVEL',
                                   SUBTREE='SUBTREE', calls=[])

    def tls(**kw):
        module.calls.append(('Tls', kw))
        return ('tls', tuple(sorted(kw.items())))

    def server(host, **kw):
        module.calls.append(('Server', host, kw))
        return ('server', host)

    class Connection:
        def __init__(self, srv, **kw):
            module.calls.append(('Connection', srv, kw))
            self.response = []

        def open(self):
            module.calls.append(('open',))

        def start_tls(self):
            module.calls.append(('start_tls',))

        def bind(self):
            module.calls.append(('bind',))
            if fail_bind:
                raise Refused(fail_bind)

        def unbind(self):
            module.calls.append(('unbind',))

        def search(self, base, query, scope, attributes=None):
            module.calls.append(('search', base, query, scope, tuple(attributes or ())))
            self.response = [{'type': 'searchResDone'}]
            if query.startswith('(memberOf:%s:=' % ldap_groups.IN_CHAIN):
                if refuse_chain:
                    raise Refused('inappropriateMatching')
                group = unescape(query[len('(memberOf:%s:=' % ldap_groups.IN_CHAIN):-1])
                entry = directory.get(base)
                if entry and any(ldap_groups.same_dn(group, g) for g in entry.get('chain', [])):
                    self.response.insert(0, {'type': 'searchResEntry', 'dn': base, 'attributes': {'cn': entry['cn']}})
                return True
            for dn, entry in directory.items():
                if matches(entry, query, dn, base, scope):
                    attrs = {a: entry.get(a, []) for a in attributes or ()}
                    self.response.insert(0, {'type': 'searchResEntry', 'dn': dn, 'attributes': attrs})
            return True

    module.Tls, module.Server, module.Connection = tls, server, Connection
    return module


def unescape(text):
    out, i = '', 0
    while i < len(text):
        if text[i] == '\\':
            out += chr(int(text[i + 1:i + 3], 16))
            i += 3
        else:
            out += text[i]
            i += 1
    return out


def matches(entry, query, dn, base, scope):
    """Enough of a filter for the queries ldap_groups.py makes: its (attr=value) terms - one of the
    objectClass ones, one of the cn and sAMAccountName ones, and all the others must hold."""
    if not dn.lower().endswith(base.lower()):
        return False
    if scope == 'LEVEL' and dn.lower().split(',', 1)[1] != base.lower():
        return False
    terms = re.findall(r'\(([A-Za-z]+)=([^()]*)\)', query)
    need_class = [v for a, v in terms if a == 'objectClass']
    names = [unescape(v) for a, v in terms if a in ('cn', 'sAMAccountName')]
    plain = [(a, unescape(v)) for a, v in terms if a not in ('objectClass', 'cn', 'sAMAccountName')]
    if need_class and entry.get('objectClass') not in need_class:
        return False
    if names and not any(entry.get('cn') == n or entry.get('sAMAccountName') == n for n in names):
        return False
    return all(str(entry.get(a, '')).lower() == v.lower() for a, v in plain)


BASE_DN = 'DC=example,DC=test'
STAFF = 'CN=G-Staff,CN=Users,DC=example,DC=test'
SALES = 'CN=G-Sales,CN=Users,DC=example,DC=test'
ODD = 'CN=Odd \\(group\\)\\, one,CN=Users,DC=example,DC=test'
DIRECTORY = {
    'CN=user1,CN=Users,DC=example,DC=test': {'sAMAccountName': 'user1', 'cn': 'user1', 'objectClass': 'user',
                                             'memberOf': [STAFF], 'chain': [STAFF]},
    'CN=user3,CN=Users,DC=example,DC=test': {'sAMAccountName': 'user3', 'cn': 'user3', 'objectClass': 'user',
                                             'memberOf': [SALES], 'chain': [SALES, STAFF]},
    'CN=a*b(c),CN=Users,DC=example,DC=test': {'sAMAccountName': 'a*b(c)', 'cn': 'a*b(c)', 'objectClass': 'user',
                                              'memberOf': [ODD], 'chain': [ODD]},
    STAFF: {'cn': 'G-Staff', 'sAMAccountName': 'G-Staff', 'objectClass': 'group'},
    SALES: {'cn': 'G-Sales', 'sAMAccountName': 'G-Sales', 'objectClass': 'group'},
}
ENTRY = {'name': 'Example directory', 'type': 'ldap', 'host': 'dc1.example.test', 'ldap_port': '389',
         'ldap_urltype': 'StartTLS', 'ldap_basedn': BASE_DN, 'ldap_authcn': '', 'ldap_scope': 'subtree',
         'ldap_attr_user': 'sAMAccountName', 'ldap_extended_query': '',
         'ldap_binddn': 'CN=svc-bind,CN=Users,DC=example,DC=test', 'ldap_bindpw': SECRET}
ROWS = [{'enabled': True, 'name': 'G-Staff', 'alias': 'uid_grp_G_Staff'},
        {'enabled': True, 'name': SALES, 'alias': 'uid_grp_G_Sales'},
        {'enabled': True, 'name': 'G-Nowhere', 'alias': 'uid_grp_G_Nowhere'},
        {'enabled': False, 'name': 'G-Off', 'alias': 'uid_grp_G_Off'}]

# escaping
check('escape: each of * ( ) \\ NUL and / as \\xx, the rest as it is',
      ldap_groups.escape('a*b(c)\\d\x00e/f g'), 'a\\2ab\\28c\\29\\5cd\\00e\\2ff g')
check('escape: a DN\'s own backslashes escaped too', ldap_groups.escape('CN=Smith\\, Ann,DC=example,DC=test'),
      'CN=Smith\\5c, Ann,DC=example,DC=test')
check('escape: letters of any script kept', ldap_groups.escape('Jürgen Ελένη'), 'Jürgen Ελένη')
check('escape: the result has no unescaped special character left',
      any(c in ldap_groups.escape('*()\\\x00/') .replace('\\5c', '').replace('\\2a', '').replace('\\28', '')
          .replace('\\29', '').replace('\\00', '').replace('\\2f', '') for c in '*()\\\x00/'), False)
check('same_dn: case and spaces aside', ldap_groups.same_dn('cn=G-Staff, CN = Users,DC=example,dc=test', STAFF), True)
check('same_dn: another group', ldap_groups.same_dn(SALES, STAFF), False)

# connecting: TLS as OPNsense's connector does it
module = standin(DIRECTORY)
directory = ldap_groups.Directory(ENTRY, ldap3=module)
directory.connect()
check('StartTLS: TLS made with the certificate checked against OPNsense\'s CA file',
      module.calls[0], ('Tls', {'validate': ssl.CERT_REQUIRED, 'ca_certs_file': '/usr/local/etc/ssl/cert.pem'}))
check('StartTLS: the server by its name, port 389, no SSL, no schema read, a timeout',
      (module.calls[1][1], {k: module.calls[1][2][k] for k in ('port', 'use_ssl', 'get_info', 'connect_timeout')}),
      ('dc1.example.test', {'port': 389, 'use_ssl': False, 'get_info': 'NO_INFO', 'connect_timeout': 5}))
kw = module.calls[2][2]
check('the connection: the bind DN and its password, a simple bind, read only, exceptions raised',
      (kw['user'], kw['password'] == SECRET, kw['authentication'], kw['read_only'], kw['raise_exceptions'],
       kw['auto_referrals']), (ENTRY['ldap_binddn'], True, 'SIMPLE', True, True, False))
check('StartTLS: opened, TLS started, then bound', [c[0] for c in module.calls[3:]], ['open', 'start_tls', 'bind'])
module = standin(DIRECTORY)
ldap_groups.Directory(dict(ENTRY, ldap_urltype='SSL - Encrypted', ldap_port=''), ldap3=module).connect()
check('SSL: port 636 by default, SSL on, no StartTLS',
      (module.calls[1][2]['port'], module.calls[1][2]['use_ssl'], [c[0] for c in module.calls[3:]]),
      (636, True, ['open', 'bind']))
module = standin(DIRECTORY)
ldap_groups.Directory(dict(ENTRY, ldap_urltype='TCP - Standard', ldap_binddn=''), ldap3=module).connect()
check('Standard, no bind DN: no TLS, an anonymous bind with no password',
      (module.calls[0][0], module.calls[0][2]['tls'], module.calls[1][2]['authentication'], module.calls[1][2]['password']),
      ('Server', None, 'ANONYMOUS', None))
try:
    ldap_groups.Directory(dict(ENTRY, host=''), ldap3=standin(DIRECTORY)).connect()
    said = None
except ValueError as error:
    said = str(error)
check('an entry with no host: said, nothing asked', said, 'the System: Access: Servers entry names no host')

# the filters
module = standin(DIRECTORY)
directory = ldap_groups.Directory(dict(ENTRY, ldap_extended_query='objectClass=user',
                                       ldap_authcn='OU=Staff,DC=example,DC=test;CN=Users,DC=example,DC=test',
                                       ldap_scope='one'), ldap3=module)
directory.connect()
check('user: its entry and memberOf, under the second container', directory.user('user1'),
      ('CN=user1,CN=Users,DC=example,DC=test', [STAFF]))
searches = [c for c in module.calls if c[0] == 'search']
check('user: each container in turn, one level, the user attribute and the extended query, memberOf asked',
      searches, [('search', 'OU=Staff,DC=example,DC=test', '(&(sAMAccountName=user1)(objectClass=user))', 'LEVEL', ('memberOf',)),
                 ('search', 'CN=Users,DC=example,DC=test', '(&(sAMAccountName=user1)(objectClass=user))', 'LEVEL', ('memberOf',))])
module.calls.clear()
check('user: a name with * and ( ) asked escaped, and found as it is', directory.user('a*b(c)'),
      ('CN=a*b(c),CN=Users,DC=example,DC=test', [ODD]))
check('user: the filter it was asked by', module.calls[0][2], '(&(sAMAccountName=a\\2ab\\28c\\29)(objectClass=user))')
module.calls.clear()
check('user: one that is not there', directory.user('*'), (None, []))
check('user: "*" asked as a name, never as a wildcard', module.calls[0][2], '(&(sAMAccountName=\\2a)(objectClass=user))')
check('group: by its name, under the base DN', directory.group('G-Staff'), STAFF)
check('group: its filter, the name escaped', [c[2] for c in module.calls if c[0] == 'search'][-1],
      '(&' + ldap_groups.GROUP_CLASSES + '(|(cn=G-Staff)(sAMAccountName=G-Staff)))')
module.calls.clear()
check('group: asked once a connection', (directory.group('G-Staff'), module.calls), (STAFF, []))
check('group: a DN taken as it is, nothing asked', (directory.group(SALES), module.calls), (SALES, []))
check('group: one that is not there', directory.group('G-Nowhere'), None)

# membership
module = standin(DIRECTORY)
directory = ldap_groups.Directory(ENTRY, ldap3=module)
directory.connect()
found = ldap_groups.lookup(directory, 'user1', ROWS, nested=True)
check('user1: in G-Staff directly, not in G-Sales, G-Nowhere no group, a row switched off not asked',
      (found['found'], found['in'], found['groups']),
      (True, ['g-staff'], {'G-Staff': 'direct', SALES: 'no', 'G-Nowhere': 'no group'}))
chain = [c for c in module.calls if c[0] == 'search' and c[2].startswith('(memberOf:')]
check('user1: the in-chain rule asked of its own entry, for G-Sales alone, the DN escaped',
      chain, [('search', 'CN=user1,CN=Users,DC=example,DC=test',
               '(memberOf:1.2.840.113556.1.4.1941:=CN=G-Sales,CN=Users,DC=example,DC=test)', 'BASE', ('cn',))])
found = ldap_groups.lookup(directory, 'user3', ROWS, nested=True)
check('user3 (the lab\'s A3): in G-Sales directly, in G-Staff only through it - by the in-chain rule',
      (found['in'], found['groups']['G-Staff'], found['groups'][SALES], directory.chain),
      (['g-staff', 'cn=g-sales,cn=users,dc=example,dc=test'], 'nested', 'direct', 'used'))
module.calls.clear()
found = ldap_groups.lookup(directory, 'user3', ROWS, nested=False)
check('Nested groups off: memberOf alone, the in-chain rule never asked',
      (found['in'], [c for c in module.calls if c[0] == 'search' and c[2].startswith('(memberOf:')]),
      (['cn=g-sales,cn=users,dc=example,dc=test'], []))
found = ldap_groups.lookup(directory, 'nobody', ROWS, nested=True)
check('a user the directory does not hold: found false, in no group', (found['found'], found['in']), (False, []))
check('the in-chain filter for an odd DN: every special character escaped',
      ldap_groups.escape(ODD), 'CN=Odd \\5c\\28group\\5c\\29\\5c, one,CN=Users,DC=example,DC=test')
module = standin(DIRECTORY, refuse_chain=True)
directory = ldap_groups.Directory(ENTRY, ldap3=module)
directory.connect()
found = ldap_groups.lookup(directory, 'user3', ROWS, nested=True)
check('a server that refuses the in-chain rule: memberOf decides, said as refused',
      (found['in'], found['groups']['G-Staff'], directory.chain),
      (['cn=g-sales,cn=users,dc=example,dc=test'], 'no', 'refused'))
module.calls.clear()
ldap_groups.lookup(directory, 'user1', ROWS, nested=True)
check('and it is asked the rule no more',
      [c for c in module.calls if c[0] == 'search' and c[2].startswith('(memberOf:')], [])

# the page's Test
conf = settings.read(os.path.join(ROOT, 'tools', 'fixtures', 'config.xml'))
conf['groups'] = ROWS
ticks = iter([10.0, 10.048])
out = ldap_groups.test('user3', conf=dict(conf, server=dict(conf['server'], ldap_authcn='')),
                       ldap3=standin(DIRECTORY), clock=lambda: next(ticks))
check('Test: the user\'s DN, each row with its verdict, the in-chain rule used, the time it took',
      (out['status'], out['dn'], [(r['group'], r['member']) for r in out['groups']], out['nested'], out['took_ms']),
      ('ok', 'CN=user3,CN=Users,DC=example,DC=test',
       [('G-Staff', 'nested'), (SALES, 'direct'), ('G-Nowhere', 'no group'), ('G-Off', 'off')], 'used', 48))
check('Test: the bind password in no part of the answer', SECRET in repr(out), False)
out = ldap_groups.test('user3', conf=conf, ldap3=standin(DIRECTORY, fail_bind='invalidCredentials for %s' % SECRET),
                       clock=lambda: 0.0)
check('Test: a bind refused - said, the password taken out of what the server said',
      (out['status'], out['error']), ('failed', 'Refused: invalidCredentials for ***'))
check('Test: no server chosen', ldap_groups.test('user1', conf=dict(conf, ldap_server=''))['error'],
      'no LDAP server is chosen in Settings')
check('Test: the server chosen is not LDAP', ldap_groups.test('user1', conf=dict(conf, server=None))['error'],
      'the server chosen is not an LDAP entry of System: Access: Servers')
check('Test: no user named', ldap_groups.test('  ', conf=conf, ldap3=standin(DIRECTORY))['error'], 'no user named')

# ldap3 itself, where it is installed: its constructors take what Directory gives them, and what
# ldap3 makes of an escaped value
try:
    import ldap3                                                         # noqa: E402
    from ldap3.protocol.convert import prepare_filter_for_sending, validate_assertion_value  # noqa: E402
except ImportError:
    ldap3 = None
if ldap3 is None:
    print('skip ldap3 is not installed here: its own constructors not checked (checks.yml installs it)')
else:
    import tempfile                                                      # noqa: E402
    made = {}

    class Recorder:
        """ldap3 itself, with Connection.open() and what follows stopped before the network."""
        def __getattr__(self, name):
            return getattr(ldap3, name)

        def Connection(self, *args, **kw):
            conn = ldap3.Connection(*args, lazy=True, **kw)
            made['conn'] = conn
            conn.open = lambda: None
            conn.start_tls = lambda: True
            conn.bind = lambda: True
            return conn

    # ldap3's Tls refuses a CA file that is not there; a runner has no OPNsense's, so one stands in
    with tempfile.NamedTemporaryFile(suffix='.pem') as authorities:
        ldap_groups.CA_FILE = authorities.name
        for kind in ('StartTLS', 'SSL - Encrypted', 'TCP - Standard'):
            try:
                ldap_groups.Directory(dict(ENTRY, ldap_urltype=kind), ldap3=Recorder()).connect()
                conn = made['conn']
                said = (conn.server.host, conn.server.ssl, conn.user, conn.read_only, conn.raise_exceptions,
                        conn.server.tls.validate if conn.server.tls else None)
            except Exception as error:                                   # noqa: BLE001
                said = repr(error)
            check('ldap3 %s: its own Server, Tls and Connection take what Directory gives them (%s)'
                  % (ldap3.__version__, kind), said,
                  ('dc1.example.test', kind.startswith('SSL'), ENTRY['ldap_binddn'], True, True,
                   None if kind.startswith('TCP') else ssl.CERT_REQUIRED))
    value = ldap_groups.escape('a*b(c)\\')
    check('ldap3: an escaped value not escaped again, and sent as the characters it stands for',
          (validate_assertion_value(None, 'sAMAccountName', value, True, True, None, False),
           prepare_filter_for_sending(value)), (value.encode(), b'a*b(c)\\'))

print('%d of %d checks failed' % (failures, checks) if failures else '%d checks passed' % checks)
sys.exit(1 if failures else 0)
