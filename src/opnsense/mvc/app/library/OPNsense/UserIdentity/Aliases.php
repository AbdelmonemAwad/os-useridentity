<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The aliases behind User Identity's pf tables (settled point 4): of type External, written in
 * config.xml through OPNsense's own Alias model, as os-blocklists and os-appcontrol write theirs - the
 * kind Firewall: Rules offers in a rule's source and destination, and the kind os-xgs-npu's
 * lists_cut.py can find, which resolves XGS: Settings' cut list from config.xml. No Expire: the plugin
 * keeps each address's time itself and empties the tables from its own map.
 *
 * The aliases this plugin owns are named uid_ and described 'User Identity: '; any other is the
 * owner's and is never touched, whatever its name. One for each group row and each user row switched
 * on, by the alias name the row gives (settled points 5 and 6), while the plugin is on.
 *
 * Where os-xgs-npu is installed its cut list holds them (settled point 9): an address that joins one
 * of these tables has its open connections cut at lists_cut.py's next minute, in hardware first. The
 * owner's own entries there are kept as they are; the plugin's aliases no longer wanted leave it.
 */

namespace OPNsense\UserIdentity;

class Aliases
{
    const PREFIX = 'uid_';
    const DESCRIPTION = 'User Identity: ';
    const LONGEST = 31;

    /**
     * An alias this plugin made: its name and its description both say so.
     */
    public static function owned($name, $description)
    {
        return strpos((string)$name, self::PREFIX) === 0 && strpos((string)$description, self::DESCRIPTION) === 0;
    }

    /**
     * The alias name proposed for a group or a user row (settled point 5): $prefix and the name with
     * every character but letters, digits and _ made _, at most 31 characters as OPNsense allows
     * (AliasNameField); a name with letters that are not Latin, or too long to keep, ends with _ and six
     * hex digits of its SHA-1, so it stays its own. One in $taken gets _2, _3 and on.
     */
    public static function propose($prefix, $name, array $taken = [])
    {
        $name = trim((string)$name);
        $plain = trim(preg_replace('/_+/', '_', preg_replace('/[^A-Za-z0-9_]/', '_', $name)), '_');
        $latin = preg_match('/^[\x20-\x7e]*$/', $name) === 1;
        $whole = $prefix . $plain;
        if (!$latin || $plain === '' || strlen($whole) > self::LONGEST) {
            $suffix = '_' . substr(sha1($name), 0, 6);
            $whole = rtrim($prefix . substr($plain, 0, self::LONGEST - strlen($prefix) - strlen($suffix)), '_') . $suffix;
        }
        $taken = array_flip(array_map('strtolower', $taken));
        $found = $whole;
        for ($n = 2; isset($taken[strtolower($found)]); $n++) {
            $tail = '_' . $n;
            $found = rtrim(substr($whole, 0, self::LONGEST - strlen($tail)), '_') . $tail;
        }
        return $found;
    }

    /**
     * $config with the plugin's own aliases' uuids taken out of XGS: Settings' cut list: they are put
     * there by this plugin, and must not count as something else holding the alias.
     */
    public static function withoutOwnCuts($config, array $uuids)
    {
        return preg_replace_callback('/<cut_lists>([^<]*)<\/cut_lists>/', function ($m) use ($uuids) {
            $kept = array_diff(array_filter(explode(',', $m[1])), $uuids);
            return '<cut_lists>' . implode(',', $kept) . '</cut_lists>';
        }, (string)$config);
    }

    /**
     * Make the model's aliases say what $wanted says - [name => ['description' => text]], each External,
     * switched on - and return ['changes' => what changed, 'notes' => what was left as it is and why],
     * one line each. An alias of this plugin's no longer wanted is removed; when something else in the
     * configuration names it or holds its uuid - a rule, a setting - it is switched off instead, as
     * os-blocklists does, so nothing of the owner's is left pointing at nothing. $config is config.xml's
     * text, its cut list without the plugin's own entries (withoutOwnCuts()). Nothing is saved here.
     */
    public static function reconcile($model, $config, array $wanted)
    {
        $changes = [];
        $notes = [];
        foreach (iterator_to_array($model->aliases->alias->iterateItems()) as $uuid => $alias) {
            $name = (string)$alias->name;
            if (!self::owned($name, (string)$alias->description) || isset($wanted[$name])) {
                continue;
            }
            $named = preg_match_all('/\b' . preg_quote($name, '/') . '\b/', (string)$config) > 1;
            $held = substr_count((string)$config, (string)$uuid) > 1;
            if ($named || $held) {
                if ((string)$alias->enabled !== '0') {
                    $alias->enabled = '0';
                    $changes[] = $name . ': no longer wanted, but named elsewhere in the configuration - switched off, not removed';
                }
            } else {
                $model->aliases->alias->del($uuid);
                $changes[] = $name . ': removed';
            }
        }
        foreach ($wanted as $name => $want) {
            $values = [
                'enabled' => '1',
                'type' => 'external',
                'description' => (string)($want['description'] ?? (self::DESCRIPTION . $name)),
            ];
            $node = $model->getByName($name);
            if ($node === null) {
                $node = $model->aliases->alias->Add();
                $node->setNodes(['name' => $name] + $values);
                $changes[] = $name . ': added';
                continue;
            }
            if (!self::owned($name, (string)$node->description)) {
                $notes[] = $name . ': an alias of this name is not one of this plugin\'s - left as it is, and no table written';
                continue;
            }
            $was = [];
            foreach (array_keys($values) as $field) {
                $was[$field] = (string)$node->$field;
            }
            if ($was !== $values) {
                $node->setNodes($values);
                $changes[] = $name . ': updated';
            }
        }
        return ['changes' => $changes, 'notes' => $notes];
    }

    /**
     * The uuids of the plugin's aliases in the model: [name => uuid], and whether each is switched on.
     */
    public static function ours($model)
    {
        $out = [];
        foreach ($model->aliases->alias->iterateItems() as $uuid => $alias) {
            if (self::owned((string)$alias->name, (string)$alias->description)) {
                $out[(string)$alias->name] = ['uuid' => (string)$uuid, 'enabled' => (string)$alias->enabled === '1'];
            }
        }
        return $out;
    }

    /**
     * XGS: Settings' cut list as it should be: the owner's entries as they are, in their order, then
     * the uuids of the plugin's aliases wanted and switched on; none of the plugin's others.
     */
    public static function cutLists(array $current, array $ours, array $wanted)
    {
        $mine = [];
        foreach ($ours as $alias) {
            $mine[$alias['uuid']] = true;
        }
        $out = [];
        foreach ($current as $uuid) {
            if ($uuid !== '' && !isset($mine[$uuid]) && !in_array($uuid, $out, true)) {
                $out[] = $uuid;
            }
        }
        foreach ($wanted as $name => $want) {
            if (isset($ours[$name]) && $ours[$name]['enabled'] && !in_array($ours[$name]['uuid'], $out, true)) {
                $out[] = $ours[$name]['uuid'];
            }
        }
        return $out;
    }
}
