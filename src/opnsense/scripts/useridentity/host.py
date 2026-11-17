#!/usr/local/bin/python3
#-
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
#
"""What the firewall itself knows that the map needs: its own addresses, never mapped (ifconfig -a,
read as os-appcontrol reads it), and which device holds each address on the networks it is attached
to - its ARP table for IPv4 (arp -an), its neighbour table for IPv6 (ndp -an) - for the MAC check.

Each reader takes the program's text, so the tests give them FreeBSD's own output; run() asks the
program itself.
"""

import ipaddress
import re
import subprocess

IFCONFIG = '/sbin/ifconfig'
ARP = '/usr/sbin/arp'
NDP = '/usr/sbin/ndp'

HEAD = re.compile(r'^(\S+?):\s+flags=')
MAC = re.compile(r'^([0-9a-f]{1,2}:){5}[0-9a-f]{1,2}$')


def run(program, *args):
    """The program's output, or '' when it cannot be run or fails."""
    try:
        done = subprocess.run([program] + list(args), capture_output=True, text=True, errors='replace', timeout=30)
    except (OSError, subprocess.SubprocessError):
        return ''
    return done.stdout if done.returncode == 0 else ''


def interface(words):
    """The address and its network of one inet or inet6 line of ifconfig, in any of the ways it writes
    them - 'inet 192.0.2.1 netmask 0xffffff00', 'inet 192.0.2.1/24', 'inet6 fe80::1%em0 prefixlen 64';
    None for a line read as none of them."""
    text, prefix = words[1], None
    if '/' in text:
        text, prefix = text.rsplit('/', 1)
    text = text.split('%')[0]
    for i, word in enumerate(words[2:-1], 2):
        if word == 'netmask':
            try:
                mask = words[i + 1]
                prefix = bin(int(mask, 16) if mask.startswith('0x') else int(ipaddress.IPv4Address(mask))).count('1')
            except ValueError:
                return None
        elif word == 'prefixlen':
            prefix = words[i + 1]
    try:
        return ipaddress.ip_interface(text if prefix is None else '%s/%s' % (text, prefix))
    except ValueError:
        return None


def own(text):
    """(addresses, broadcasts): the firewall's own addresses, and the broadcast addresses of its IPv4
    networks, from ifconfig -a's text."""
    addresses, broadcasts, dev = set(), set(), None
    for line in text.splitlines():
        head = HEAD.match(line)
        if head:
            dev = head.group(1)
            continue
        words = line.split()
        if dev is None or len(words) < 2 or words[0] not in ('inet', 'inet6'):
            continue
        found = interface(words)
        if found is None:
            continue
        addresses.add(str(found.ip))
        if found.version == 4:
            if 'broadcast' in words[:-1]:
                try:
                    broadcasts.add(str(ipaddress.ip_address(words[words.index('broadcast') + 1])))
                except ValueError:
                    pass
            if found.network.prefixlen <= 30:
                broadcasts.add(str(found.network.broadcast_address))
    return addresses, broadcasts


def mac(text):
    """The MAC in one form - six pairs of lower-case digits - or None when text is no MAC."""
    text = text.lower()
    if not MAC.match(text):
        return None
    return ':'.join('%02x' % int(part, 16) for part in text.split(':'))


def arp(text):
    """{IPv4 address: MAC} of arp -an's text; an entry with no MAC yet, (incomplete), left out."""
    out = {}
    for line in text.splitlines():
        found = re.match(r'^\S+ \(([0-9.]+)\) at (\S+) ', line)
        if found and mac(found.group(2)):
            out[found.group(1)] = mac(found.group(2))
    return out


def ndp(text):
    """{IPv6 address: MAC} of ndp -an's text; the header and entries with no MAC left out."""
    out = {}
    for line in text.splitlines():
        words = line.split()
        if len(words) < 2 or not mac(words[1]):
            continue
        try:
            where = ipaddress.ip_address(words[0].split('%')[0])
        except ValueError:
            continue
        out[str(where)] = mac(words[1])
    return out


def macs():
    """{address: MAC} the firewall's tables hold now, both families."""
    found = arp(run(ARP, '-an'))
    found.update(ndp(run(NDP, '-an')))
    return found


def addresses():
    """(own addresses, broadcasts) as ifconfig -a gives them now."""
    return own(run(IFCONFIG, '-a'))
