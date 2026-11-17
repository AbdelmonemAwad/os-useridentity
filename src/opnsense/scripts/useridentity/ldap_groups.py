#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""Which of the chosen groups a user is in, asked of the directory that System: Access: Servers names
in Settings (settled point 11), with ldap3 - a dependency of OPNsense's own core: py313-ldap3 2.9.1 is
installed with OPNsense 26.7 (phase 0's A0). LDAP gives the groups; the addresses come from the
domain controllers' events.

The entry's own settings, as OPNsense's connector reads them: host, ldap_port, ldap_urltype
(Standard, StartTLS or SSL), the bind DN and its password, the base DN, the containers (ldap_authcn,
separated by ;) and the scope, the user attribute and the extended query. TLS is checked as that
connector checks it: the certificate against /usr/local/etc/ssl/cert.pem - System: Trust's
authorities - and its name against the host. Phase 0's A3: Windows Server 2025 refuses a simple bind
in the clear (strongerAuthRequired); StartTLS on 389 and LDAPS on 636 work with the domain's CA in
System: Trust and the domain controller named as its certificate names it, not by its address. The
bind password is never written anywhere, nor said in an error.

For a user: its entry under the containers, or the base DN, with its memberOf; then for each group
row: the group's DN - the row's name is one, or the group of that name (cn or sAMAccountName) under
the base DN - and whether the user is in it: in memberOf, or, with Nested groups on, by Active
Directory's in-chain rule (LDAP_MATCHING_RULE_IN_CHAIN, 1.2.840.113556.1.4.1941) asked of the user's
own entry, one question a group - A3 found a user in a group only through a group inside it this way,
and OPNsense's own connector reads memberOf alone. A server that refuses the rule is asked it no more,
and memberOf alone decides.

    ldap_groups.py test <user>    what the page's Test shows: the user's DN and each group row, as JSON
"""

import importlib
import json
import os
import ssl
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import settings                                                          # noqa: E402

CA_FILE = '/usr/local/etc/ssl/cert.pem'
IN_CHAIN = '1.2.840.113556.1.4.1941'
# The result codes a server answers a matching rule it does not know with (RFC 4511): protocolError,
# unavailableCriticalExtension, undefinedAttributeType, inappropriateMatching, unwillingToPerform. ldap3
# raises an LDAPOperationResult carrying the code in its result.
REFUSED_CODES = (2, 12, 17, 18, 53)
TIMEOUT = 5
GROUP_CLASSES = '(|(objectClass=group)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))'

_ESCAPE = {'\\': r'\5c', '*': r'\2a', '(': r'\28', ')': r'\29', '\x00': r'\00', '/': r'\2f'}


def escape(value):
    """A value made safe inside a search filter (RFC 4515, and / as Microsoft's filter syntax lists it):
    a user's name from an event, or a group's DN, can hold any of these."""
    return ''.join(_ESCAPE.get(char, char) for char in str(value))


def same_dn(one, other):
    """Two DNs as the same, whatever their case and the spaces around , and =."""
    def plain(dn):
        return ','.join('='.join(part.strip() for part in rdn.split('=', 1)) for rdn in dn.split(',')).lower()
    return plain(one) == plain(other)


def quiet(message, entry):
    """An error's text, the bind password taken out should it ever be in it."""
    secret = (entry or {}).get('ldap_bindpw') or ''
    text = str(message)
    return text.replace(secret, '***') if secret else text


def library():
    return importlib.import_module('ldap3')


class Directory:
    """One bound connection to the entry's server; ldap3 itself is given in the tests."""

    def __init__(self, entry, ldap3=None, timeout=TIMEOUT):
        self.entry = entry
        self.ldap3 = ldap3 or library()
        self.timeout = timeout
        self.conn = None
        self.chain = 'unknown'      # used, refused - by this server, since the connection was made
        self.groups = {}            # row name -> DN or None, asked once a connection

    def settings(self):
        """(host, port, use_ssl, starttls) of the entry."""
        kind = self.entry.get('ldap_urltype') or ''
        starttls = 'StartTLS' in kind
        use_ssl = not starttls and 'Standard' not in kind
        try:
            port = int(self.entry.get('ldap_port') or 0)
        except ValueError:
            port = 0
        return self.entry.get('host') or '', port or (636 if use_ssl else 389), use_ssl, starttls

    def connect(self):
        """Bind, or raise. TLS as OPNsense's connector does it: certificate and name checked."""
        ldap3 = self.ldap3
        host, port, use_ssl, starttls = self.settings()
        if not host:
            raise ValueError('the System: Access: Servers entry names no host')
        tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=CA_FILE) if (use_ssl or starttls) else None
        server = ldap3.Server(host, port=port, use_ssl=use_ssl, tls=tls, get_info=ldap3.NONE,
                              connect_timeout=self.timeout)
        who = self.entry.get('ldap_binddn') or None
        conn = ldap3.Connection(server, user=who, password=self.entry.get('ldap_bindpw') if who else None,
                                authentication=ldap3.SIMPLE if who else ldap3.ANONYMOUS, read_only=True,
                                receive_timeout=self.timeout * 2, raise_exceptions=True, auto_referrals=False)
        conn.open()
        if starttls:
            conn.start_tls()
        conn.bind()
        self.conn = conn
        self.chain = 'unknown'
        self.groups = {}
        return conn

    def close(self):
        if self.conn is not None:
            try:
                self.conn.unbind()
            except Exception:                                            # noqa: BLE001
                pass
        self.conn = None

    def entries(self, base, query, scope, attributes):
        self.conn.search(base, query, scope, attributes=attributes)
        return [r for r in (self.conn.response or []) if r.get('type') == 'searchResEntry']

    def user(self, name):
        """(DN, [memberOf]) of the user, or (None, []) when it is not there."""
        attribute = self.entry.get('ldap_attr_user') or 'cn'
        memberof = self.entry.get('ldap_attr_memberof') or 'memberOf'
        query = '(%s=%s)' % (attribute, escape(name))
        extended = (self.entry.get('ldap_extended_query') or '').strip()
        if extended:
            query = '(&%s(%s))' % (query, extended)
        bases = [b.strip() for b in (self.entry.get('ldap_authcn') or '').split(';') if b.strip()]
        scope = self.ldap3.LEVEL if self.entry.get('ldap_scope') == 'one' else self.ldap3.SUBTREE
        for base in bases or [self.entry.get('ldap_basedn') or '']:
            found = self.entries(base, query, scope, [memberof])
            if found:
                values = found[0].get('attributes', {}).get(memberof) or []
                return found[0]['dn'], [str(v) for v in (values if isinstance(values, list) else [values])]
        return None, []

    def group(self, name):
        """The group row's DN: the name when it is one, else the group of that name under the base DN."""
        if name in self.groups:
            return self.groups[name]
        if '=' in name:
            found = name
        else:
            query = '(&%s(|(cn=%s)(sAMAccountName=%s)))' % (GROUP_CLASSES, escape(name), escape(name))
            hits = self.entries(self.entry.get('ldap_basedn') or '', query, self.ldap3.SUBTREE, ['cn'])
            found = hits[0]['dn'] if hits else None
        self.groups[name] = found
        return found

    def in_chain(self, user_dn, group_dn):
        """True or False by the in-chain rule; None when the server refuses it - by one of REFUSED_CODES,
        and then it is not asked again. Any other error - a timeout, a server busy or gone - is not a
        refusal of the rule: it is raised, so the connection is made again and the rule asked next time."""
        if self.chain == 'refused':
            return None
        try:
            hits = self.entries(user_dn, '(memberOf:%s:=%s)' % (IN_CHAIN, escape(group_dn)), self.ldap3.BASE, ['cn'])
        except Exception as error:                                       # noqa: BLE001
            if getattr(error, 'result', None) in REFUSED_CODES:
                self.chain = 'refused'
                return None
            raise
        self.chain = 'used'
        return bool(hits)


def lookup(directory, name, rows, nested):
    """{'found', 'dn', 'in': [row names, lower case], 'groups': {row name: direct, nested, no or no group}}
    for the user and the group rows switched on. Raises what the directory raises."""
    dn, memberof = directory.user(name)
    out = {'found': dn is not None, 'dn': dn or '', 'in': [], 'groups': {}}
    for row in rows:
        if not row['enabled'] or not row['name']:
            continue
        group = directory.group(row['name'])
        if group is None:
            out['groups'][row['name']] = 'no group'
            continue
        if dn is None:
            out['groups'][row['name']] = 'no'
            continue
        if any(same_dn(g, group) for g in memberof):
            verdict = 'direct'
        elif nested and directory.in_chain(dn, group):
            verdict = 'nested'
        else:
            verdict = 'no'
        out['groups'][row['name']] = verdict
        if verdict != 'no':
            out['in'].append(row['name'].lower())
    return out


def test(name, conf=None, ldap3=None, clock=time.monotonic):
    """What the page's Test shows for one user, as a dict: never the bind password."""
    conf = conf or settings.read()
    entry = conf.get('server')
    if not conf.get('ldap_server'):
        return {'status': 'failed', 'error': 'no LDAP server is chosen in Settings'}
    if entry is None:
        return {'status': 'failed', 'error': 'the server chosen is not an LDAP entry of System: Access: Servers'}
    name = (name or '').strip()
    if not name:
        return {'status': 'failed', 'error': 'no user named'}
    started = clock()
    directory = None
    try:
        directory = Directory(entry, ldap3=ldap3)
        directory.connect()
        found = lookup(directory, name, conf['groups'], conf['nested'])
    except Exception as error:                                           # noqa: BLE001
        return {'status': 'failed', 'server': conf['ldap_server'], 'user': name,
                'error': quiet('%s: %s' % (type(error).__name__, error), entry),
                'took_ms': int((clock() - started) * 1000)}
    finally:
        if directory is not None:
            directory.close()
    rows = [{'group': row['name'], 'alias': row['alias'], 'member': found['groups'].get(row['name'], 'off')}
            for row in conf['groups']]
    return {'status': 'ok', 'server': conf['ldap_server'], 'user': name, 'found': found['found'], 'dn': found['dn'],
            'groups': rows, 'nested': directory.chain if conf['nested'] else 'off',
            'took_ms': int((clock() - started) * 1000)}


def main(argv):
    if len(argv) >= 2 and argv[1] == 'test':
        print(json.dumps(test(argv[2] if len(argv) > 2 else '')))
        return 0
    print('usage: ldap_groups.py test <user>', file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
