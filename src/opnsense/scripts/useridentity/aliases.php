#!/usr/local/bin/php
<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * Make the firewall's aliases say what Settings says (library OPNsense\UserIdentity\Aliases): an
 * External alias for each group row and each user row switched on, while User Identity is on; none of
 * this plugin's while it is off. Where os-xgs-npu is installed, its cut list - XGS: Settings, "Cut open
 * connections when listed" - then holds the plugin's aliases wanted, beside the owner's own entries,
 * which stay as they are (settled point 9): each put there once and recorded in the plugin's settings
 * (general.cut_added), so one the owner takes out stays out. Without os-xgs-npu nothing is cut, and the
 * page says so.
 *
 * Nothing is saved unless the models take every change; the configuration is saved once.
 *
 *   aliases.php            print a JSON summary; the page's Apply then reloads the filter
 *   aliases.php --remove   every alias of this plugin's taken out, and out of the cut list (its removal)
 */

require_once('script/load_phalcon.php');

use OPNsense\Core\Config;
use OPNsense\Firewall\Alias;
use OPNsense\UserIdentity\Aliases;
use OPNsense\UserIdentity\UserIdentity;

function answer($result)
{
    echo json_encode($result) . "\n";
    exit(0);
}

$remove = in_array('--remove', $argv, true);
$wanted = [];
$settings = new UserIdentity();
if (!$remove) {
    if ((string)$settings->general->enabled === '1') {
        foreach (['groups' => 'group', 'users' => 'user'] as $list => $kind) {
            foreach ($settings->$list->$kind->iterateItems() as $row) {
                $alias = (string)$row->alias;
                if ((string)$row->enabled === '1' && $alias !== '' && !isset($wanted[$alias])) {
                    $wanted[$alias] = ['description' => Aliases::describe($kind, (string)$row->name)];
                }
            }
        }
    }
}

$model = new Alias();
/* config.xml's text, read for what else names an alias; the tests give it another */
$config = (string)@file_get_contents(getenv('USERIDENTITY_CONFIG') ?: '/conf/config.xml');
$before = Aliases::ours($model);
$done = Aliases::reconcile($model, Aliases::references($config, array_column($before, 'uuid')), $wanted);
$changes = $done['changes'];

$messages = [];
foreach ($model->performValidation() as $message) {
    $messages[] = $message->getField() . ': ' . $message->getMessage();
}
if (!empty($messages)) {
    answer(['status' => 'failed', 'changes' => [], 'errors' => $messages]);
}
if (!empty($changes)) {
    $model->serializeToConfig();
}

/* XGS: Settings' cut list, where os-xgs-npu is installed - read after the aliases are in the
   configuration, so the uuids of those just added are known to its relation field */
$cut = ['xgs' => false, 'changed' => false];
if (class_exists('OPNsense\XGS\XGS')) {
    $xgs = new \OPNsense\XGS\XGS();
    $node = $xgs->getNodeByReference('general.cut_lists');
    if ($node !== null) {
        $cut['xgs'] = true;
        $current = array_values(array_filter(explode(',', (string)$node)));
        /* what the plugin put in the cut list itself: one the owner took out is not put back */
        $added = array_values(array_filter(explode(',', (string)$settings->general->cut_added)));
        [$after, $record] = Aliases::cutLists($current, Aliases::ours($model) + $before, $wanted, $added);
        if ($record !== $added) {
            $settings->general->cut_added = implode(',', $record);
            $refused = [];
            foreach ($settings->performValidation() as $message) {
                $refused[] = $message->getField() . ': ' . $message->getMessage();
            }
            if (!empty($refused)) {
                answer(['status' => 'failed', 'changes' => [], 'errors' => $refused]);
            }
            $settings->serializeToConfig();
            $cut['recorded'] = true;
        }
        if ($after !== $current) {
            $node->setValue(implode(',', $after));
            $refused = [];
            foreach ($xgs->performValidation() as $message) {
                $refused[] = $message->getField() . ': ' . $message->getMessage();
            }
            if (!empty($refused)) {
                answer(['status' => 'failed', 'changes' => [], 'errors' => $refused]);
            }
            $xgs->serializeToConfig();
            $cut['changed'] = true;
            $changes[] = 'XGS: Settings, cut open connections when listed: ' . count($after) . ' list(s)';
        }
        $cut['lists'] = count(array_intersect($after, array_column(Aliases::ours($model), 'uuid')));
    }
}

if (!empty($changes) || !empty($cut['recorded'])) {
    Config::getInstance()->save();
}
answer(['status' => 'ok', 'changes' => $changes, 'notes' => $done['notes'], 'aliases' => count($wanted), 'cut' => $cut]);
