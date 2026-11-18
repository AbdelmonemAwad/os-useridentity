<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The redirect that lets the domain controllers' lines in, the collector as one of the firewall's
 * services, and its start at boot.
 *
 * OPNsense starts a plugin's daemons from rc.bootup through plugins_configure('bootup'), which calls
 * the 'bootup' tasks a plugin returns from its _configure() - an rc.conf.d switch alone is read by
 * nothing at boot (os-fanctl, measured on two appliances). So the start is here, guarded by the one
 * setting that decides it: enabled, off by default. Settings are read out of $config, not through the
 * model, as os-appcontrol's hook reads its own.
 */

if (!defined('USERIDENTITY_SOURCE')) {
    /* what syslogng.py wrote: whether syslog-ng's source is there, and on which port */
    define('USERIDENTITY_SOURCE', '/var/db/os-useridentity/syslog.json');
}

function useridentity_general()
{
    global $config;

    $general = $config['OPNsense']['UserIdentity']['general'] ?? [];
    return is_array($general) ? $general : [];
}

function useridentity_enabled()
{
    return (useridentity_general()['enabled'] ?? '0') === '1';
}

function useridentity_firewall($fw)
{
    /*
     * The receiving end (settled point 1): an "rdr pass" on each chosen interface, from each domain
     * controller named in Settings and from no other address, TCP to the firewall's own addresses on the
     * port Settings gives (514 by default), to syslog-ng's source of the plugin's on 127.0.0.1 - the way
     * os-xgs-npu lets the coprocessor's log in. syslog-ng cannot listen on an interface's address: it
     * starts before the interfaces have them, and one source that cannot bind stops it whole. The
     * redirect is the gate (settled point 3): a line from any other machine never reaches the source.
     *
     * Registered only while the source is there (syslogng.py's syslog.json), and to the port it is on,
     * so no line is sent to a port another program holds. IPv4 alone: the source listens on 127.0.0.1.
     *
     * A rule this hook cannot register must not stop the ruleset from loading: the hook runs inside
     * filter_configure_sync(), so an error escaping it ends the reload, and at boot leaves the machine
     * at a single-user prompt (os-xgs-npu issue 969). A bad entry is left out and said in the system
     * log; the reload goes on. OPNsense 26.7.3 renamed registerForwardRule() to
     * registerDestinationNatRule() and keeps the old name only until 27.1, while 26.7 itself has only
     * the old one: the redirect goes through whichever this OPNsense has (tools/test-firewall-hook.py).
     */
    global $config;

    if (!useridentity_enabled()) {
        return $fw;
    }
    $general = useridentity_general();
    $source = json_decode((string)@file_get_contents(USERIDENTITY_SOURCE), true);
    if (!is_array($source) || empty($source['written'])) {
        syslog(LOG_NOTICE, 'useridentity: syslog-ng\'s source is not written (' .
            (is_array($source) ? (string)($source['reason'] ?? '') : 'not applied yet') . '): no redirect registered');
        return $fw;
    }
    $local = (int)($source['port'] ?? 0);
    $port = (string)($general['port'] ?? '514');
    if ($local < 1024 || $local > 65535 || !ctype_digit($port) || (int)$port < 1 || (int)$port > 65535) {
        syslog(LOG_ERR, 'useridentity: the port ' . $port . ' or the source\'s ' . $local . ' cannot be used: no redirect registered');
        return $fw;
    }
    /*
     * Not a port the firewall itself serves: the domain controllers would lose SSH, DNS or the web GUI
     * on it. Settings refuses one, but the web GUI or SSH may be moved onto the port after it was saved.
     * The library that says which is found by OPNsense's autoloader; were it not there, no redirect.
     */
    if (!class_exists('OPNsense\UserIdentity\Ports')) {
        syslog(LOG_ERR, 'useridentity: its library is not there, so the ports the firewall serves are not known: no redirect registered');
        return $fw;
    }
    if (in_array((int)$port, \OPNsense\UserIdentity\Ports::served($config['system'] ?? []), true)) {
        syslog(LOG_ERR, 'useridentity: the port ' . $port . ' is one the firewall itself serves (SSH, DNS or the web GUI): no redirect registered');
        return $fw;
    }
    $dcs = [];
    foreach (preg_split('/[\s,;]+/', (string)($general['domain_controllers'] ?? ''), -1, PREG_SPLIT_NO_EMPTY) as $dc) {
        if (filter_var($dc, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            $dcs[$dc] = true;
        } else {
            syslog(LOG_ERR, 'useridentity: the domain controller "' . $dc . '" is not an IPv4 address: left out');
        }
    }
    $rdr = method_exists($fw, 'registerDestinationNatRule') ? 'registerDestinationNatRule' : 'registerForwardRule';
    foreach (preg_split('/[\s,]+/', (string)($general['interfaces'] ?? 'lan'), -1, PREG_SPLIT_NO_EMPTY) as $key) {
        $intf = $config['interfaces'][$key] ?? null;
        if (!is_array($intf) || empty($intf['enable']) || empty($intf['if'])) {
            syslog(LOG_NOTICE, 'useridentity: the interface ' . $key . ' is not there or not enabled: no redirect on it');
            continue;
        }
        foreach (array_keys($dcs) as $dc) {
            try {
                $fw->$rdr(1, [
                    'interface' => $key,
                    'ipprotocol' => 'inet',
                    'protocol' => 'tcp',
                    'from' => $dc,
                    'to' => '(self)',
                    'to_port' => $port,
                    'target' => '127.0.0.1',
                    'local-port' => (string)$local,
                    /* "rdr pass": no filter rule needed. A string, as os-xgs-npu found: true is dropped */
                    'pass' => 'pass',
                    'descr' => 'User Identity: logon events from a domain controller',
                ]);
            } catch (\Throwable $e) {
                syslog(LOG_ERR, 'useridentity: the redirect from ' . $dc . ' on ' . $key . ' was left out: ' . $e->getMessage());
            }
        }
    }

    return $fw;
}

function useridentity_services()
{
    if (!useridentity_enabled()) {
        return [];
    }

    return [[
        'description' => gettext('User Identity collector'),
        'configd' => [
            'restart' => ['useridentity restart'],
            'start' => ['useridentity start'],
            'stop' => ['useridentity stop'],
        ],
        'name' => 'useridentity',
        'pidfile' => '/var/run/useridentity.pid',
    ]];
}

function useridentity_configure()
{
    return [
        'bootup' => ['useridentity_configure_do'],
    ];
}

function useridentity_configure_do($verbose = false)
{
    if (!useridentity_enabled()) {
        return;
    }

    if ($verbose) {
        echo 'Starting the User Identity collector...';
        flush();
    }

    configd_run('useridentity start');

    if ($verbose) {
        echo "done.\n";
    }
}
