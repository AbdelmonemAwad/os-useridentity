<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\UserIdentity\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;
use OPNsense\UserIdentity\UserIdentity;

class ServiceController extends ApiControllerBase
{
    private function json($action, $params = null)
    {
        $backend = new Backend();
        $text = $params === null ? $backend->configdRun('useridentity ' . $action) :
            $backend->configdpRun('useridentity ' . $action, $params);
        $result = json_decode((string)$text, true);
        return is_array($result) ? $result : ['error' => gettext('No answer could be read.')];
    }

    public function statusAction()
    {
        return $this->json('status');
    }

    /**
     * the Users tab's grid: the live map, an address a row - which source mapped it, and the other
     * users within the lifetime with the source each came from (a clash when that is another)
     */
    public function searchMapAction()
    {
        $rows = [];
        foreach (($this->json('map')['rows'] ?? []) as $row) {
            if (!is_array($row)) {
                continue;
            }
            $others = [];
            foreach ((array)($row['others'] ?? []) as $other) {
                if (is_array($other)) {
                    $others[] = ['user' => (string)($other['user'] ?? ''), 'kind' => self::kind($other['kind'] ?? '')];
                }
            }
            $rows[] = [
                'address' => (string)($row['address'] ?? ''),
                'user' => (string)($row['user'] ?? ''),
                'domain' => (string)($row['domain'] ?? ''),
                'groups' => implode(', ', array_map('strval', (array)($row['groups'] ?? []))),
                'known' => !empty($row['known']),
                'kind' => self::kind($row['kind'] ?? ''),
                'source' => (string)($row['source'] ?? ''),
                'source_name' => (string)($row['source_name'] ?? ''),
                'first' => isset($row['first']) ? (int)$row['first'] : null,
                'last' => isset($row['last']) ? (int)$row['last'] : null,
                'expires' => isset($row['expires']) ? (int)$row['expires'] : null,
                'mac' => (string)($row['mac'] ?? ''),
                'shared' => implode(', ', array_map('strval', (array)($row['shared'] ?? []))),
                'others' => $others,
                'clash' => !empty($row['clash']),
            ];
        }
        return $this->searchRecordsetBase(
            $rows,
            ['address', 'user', 'groups', 'kind', 'source', 'source_name', 'mac', 'shared'],
            'address'
        );
    }

    /**
     * a source's kind as the page knows them: ad, radius or portal - a map the first part wrote names
     * none, and every mapping of it was a domain controller's
     */
    private static function kind($kind)
    {
        return in_array((string)$kind, ['ad', 'radius', 'portal'], true) ? (string)$kind : 'ad';
    }

    /**
     * the Sources tab's grid: each domain controller named, then any other sender heard, then the
     * RADIUS clients heard and the captive portal's zones - in that order unless sorted otherwise
     */
    public function searchSourcesAction()
    {
        $rows = [];
        foreach (($this->json('status')['sources'] ?? []) as $row) {
            if (!is_array($row)) {
                continue;
            }
            $reasons = [];
            foreach ((array)($row['reasons'] ?? []) as $reason => $count) {
                $reasons[] = ['reason' => (string)$reason, 'count' => (int)$count];
            }
            $rows[] = [
                'order' => count($rows),
                'kind' => self::kind($row['kind'] ?? ''),
                'address' => (string)($row['address'] ?? ''),
                'named' => !empty($row['named']),
                'hostname' => (string)($row['hostname'] ?? ''),
                'last_line' => isset($row['last_line']) ? (int)$row['last_line'] : null,
                'last_event' => isset($row['last_event']) ? (int)$row['last_event'] : null,
                'late' => isset($row['late']) ? (float)$row['late'] : null,
                'accepted' => (int)($row['accepted'] ?? 0),
                'joined' => (int)($row['joined'] ?? 0),
                'renewed' => (int)($row['renewed'] ?? 0),
                'ended' => (int)($row['ended'] ?? 0),
                'stale' => (int)($row['stale'] ?? 0),
                'refused' => (int)($row['refused'] ?? 0),
                'reasons' => $reasons,
                'other' => (int)($row['other'] ?? 0),
            ];
        }
        return $this->searchRecordsetBase($rows, ['kind', 'address', 'hostname'], 'order');
    }

    /**
     * The settings saved put into the firewall, in this order: off, the collector stopped and every
     * mapping forgotten first, the tables emptied while their aliases are there; the aliases
     * (aliases.php, and the cut list where os-xgs-npu is installed); syslog-ng's source (syslogng.py),
     * syslog-ng restarted only when it changed; the filter reloaded, so the redirect and the tables are
     * pf's; the tables of aliases gone taken out of pf; then, on, the collector started again. When the
     * aliases could not be written nothing more is done - a plugin turned off is stopped all the same:
     * off means it maps nothing.
     */
    public function reconfigureAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        $backend = new Backend();
        $on = $this->enabled();
        if (!$on) {
            $backend->configdRun('useridentity stop');
            $backend->configdRun('useridentity flush');
        }
        $result = json_decode((string)$backend->configdRun('useridentity apply'), true);
        if (!is_array($result) || ($result['status'] ?? '') !== 'ok') {
            $result = is_array($result) ? $result : ['status' => 'failed', 'errors' => [gettext('No answer could be read.')]];
            $result['enabled'] = $on;
            return $result;
        }
        $source = json_decode((string)$backend->configdRun('useridentity source'), true);
        if (is_array($source) && !empty($source['changed'])) {
            $backend->configdRun('syslog restart');
        }
        $result['source'] = is_array($source) ? $source : null;
        $backend->configdRun('filter reload skip_alias');
        $result['gone_tables'] = json_decode((string)$backend->configdRun('useridentity gone'), true);
        if ($on) {
            $backend->configdRun('useridentity restart');
        }
        $result['enabled'] = $on;
        return $result;
    }

    /**
     * Forget every mapping now: the map emptied and the tables with it
     */
    public function flushAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        return $this->json('flush');
    }

    /**
     * Ask the directory about one user, as the collector would: Groups' Test
     */
    public function ldaptestAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        $user = trim((string)$this->request->getPost('user', null, ''));
        if (!preg_match('/^[\p{L}\p{N} ._@$-]{1,64}$/u', $user)) {
            return ['status' => 'failed', 'error' => gettext('A user\'s logon name, as the domain writes it.')];
        }
        return $this->json('ldaptest', [$user]);
    }

    /**
     * whether User Identity is on in the settings just saved
     */
    private function enabled()
    {
        return (string)(new UserIdentity())->general->enabled === '1';
    }
}
