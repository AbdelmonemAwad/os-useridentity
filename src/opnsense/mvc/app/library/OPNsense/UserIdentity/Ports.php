<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The TCP ports the firewall itself serves on its own addresses. The redirect that lets the domain
 * controllers' lines in takes the port Settings gives on the firewall's addresses, from each domain
 * controller named: were it one of these, that domain controller's SSH, DNS over TCP or web GUI
 * connections to the firewall would go to syslog-ng instead. Settings refuses them (the model), and the
 * firewall hook registers no redirect on one, since the web GUI or SSH may be moved onto the port after
 * it was saved.
 */

namespace OPNsense\UserIdentity;

class Ports
{
    /* SSH, DNS, and the web GUI on 80 - its redirect to HTTPS - and 443 */
    const SERVED = [22, 53, 80, 443];

    /**
     * The ports served, with those System: Settings: Administration moves the web GUI and SSH to.
     * @param mixed $system config.xml's <system> as an array, as legacy code's $config holds it
     * @return int[] in order
     */
    public static function served($system)
    {
        $ports = self::SERVED;
        foreach (['webgui', 'ssh'] as $section) {
            $port = trim((string)($system[$section]['port'] ?? ''));
            if (ctype_digit($port) && !in_array((int)$port, $ports, true)) {
                $ports[] = (int)$port;
            }
        }
        sort($ports);
        return $ports;
    }
}
