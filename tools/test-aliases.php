<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The aliases behind the tables (library OPNsense\UserIdentity\Aliases, and scripts/useridentity/
 * aliases.php that runs it), with stand-ins for what they reach of OPNsense: the Alias model - its
 * aliases, Add(), del(), getByName(), setNodes(), performValidation(), serializeToConfig() - Config's
 * save(), the plugin's own model and os-xgs-npu's XGS model, whose cut list is a relation to aliases.
 *
 * The Alias stand-in validates what is written as OPNsense 26.7's Alias model does the fields this
 * plugin writes (Alias.xml, AliasNameField.php, DescriptionField.php): a name that begins with a letter
 * or one underscore, letters, digits and underscores, at most 31 characters, not one of pf's reserved
 * words (AliasNameField's list, all of them), no service or protocol name, no other alias's; enabled 0
 * or 1; a type of its list; a description of one line, at most 255 bytes. The XGS stand-in's cut list
 * takes only uuids of aliases there, as a ModelRelationField does.
 *
 * What is checked: the alias name proposed for a group or a user - from a Latin name, one with spaces
 * and hyphens, one in another script, one too long, one taken - and every one of them taken by that
 * validation and by the plugin's own field; an External alias made for each row, refreshed, the
 * owner's alias of the same name left; on removal an alias nothing names removed, one a rule names
 * switched off, one only the plugin put in the cut list removed all the same; the cut list holding
 * the plugin's aliases wanted beside the owner's entries, kept as they are, and losing those no longer
 * wanted; and aliases.php run as configd runs it: saving once, nothing when nothing changed, nothing
 * when a model refuses, and no cut list where os-xgs-npu is not installed.
 *
 *   php tools/test-aliases.php
 */

namespace OPNsense\Base\Messages {
    class Message
    {
        private $message;
        private $field;

        public function __construct($message, $field = '')
        {
            $this->message = $message;
            $this->field = $field;
        }

        public function getMessage()
        {
            return $this->message;
        }

        public function getField()
        {
            return $this->field;
        }
    }
}

namespace OPNsense\Firewall {
    class AliasNode
    {
        public $fields = [];

        public function __construct($fields = [])
        {
            $this->fields = $fields;
        }

        public function __get($name)
        {
            return (string)($this->fields[$name] ?? '');
        }

        public function __set($name, $value)
        {
            $this->fields[$name] = (string)$value;
        }

        public function setNodes($values)
        {
            foreach ($values as $name => $value) {
                $this->fields[$name] = (string)$value;
            }
        }
    }

    class AliasList
    {
        public $nodes = [];
        public static $next = 100;

        public function iterateItems()
        {
            foreach ($this->nodes as $uuid => $node) {
                yield $uuid => $node;
            }
        }

        public function Add()
        {
            $uuid = sprintf('00000000-0000-4000-8000-%012d', self::$next++);
            return $this->nodes[$uuid] = new AliasNode();
        }

        public function del($uuid)
        {
            unset($this->nodes[$uuid]);
        }
    }

    class Alias
    {
        public static $given = [];
        public $aliases;

        public function __construct()
        {
            $list = new AliasList();
            foreach (self::$given as $uuid => $fields) {
                $list->nodes[$uuid] = new AliasNode($fields);
            }
            $this->aliases = (object)['alias' => $list];
        }

        public function getByName($name)
        {
            foreach ($this->aliases->alias->nodes as $node) {
                if ($node->name === $name) {
                    return $node;
                }
            }
            return null;
        }

        public function performValidation()
        {
            $nodes = [];
            foreach ($this->aliases->alias->nodes as $uuid => $node) {
                $nodes[$uuid] = $node->fields;
            }
            $out = [];
            foreach (\standin_alias_messages($nodes) as [$field, $message]) {
                $out[] = new \OPNsense\Base\Messages\Message($message, $field);
            }
            return $out;
        }
    }
}

namespace {
    $root = dirname(__DIR__);
    require $root . '/src/opnsense/mvc/app/library/OPNsense/UserIdentity/Aliases.php';

    use OPNsense\Firewall\Alias;
    use OPNsense\UserIdentity\Aliases;

    $failed = 0;
    $checks = 0;

    /* The validation of the stand-ins, here and in aliases.php's run below: [[field, message]] of the
       aliases given (uuid => fields), as OPNsense 26.7's Alias model checks the fields this plugin writes. */
    $validation = <<<'VALIDATION'
<?php
const STANDIN_RESERVED = ['af-to', 'all', 'allow-opts', 'allow-related', 'altq', 'anchor', 'antispoof', 'any', 'bandwidth',
    'binat', 'binat-anchor', 'binat-to', 'bitmask', 'block', 'block-policy', 'bridge-to', 'buckets', 'cbq', 'code',
    'codelq', 'debug', 'divert-reply', 'divert-to', 'dnpipe', 'dnqueue', 'drop', 'dup-to', 'endpoint-independent', 'ether',
    'fail-policy', 'fairq', 'fastroute', 'file', 'fingerprints', 'flags', 'floating', 'flush', 'for', 'fragment', 'from',
    'global', 'group', 'hfsc', 'hogs', 'hostid', 'icmp-type', 'icmp6-type', 'if-bound', 'in', 'include', 'inet', 'inet6',
    'interval', 'keep', 'keepcounters', 'l3', 'label', 'limit', 'linkshare', 'load', 'log', 'loginterface', 'map-e-portset',
    'match', 'matches', 'max', 'max-mss', 'max-pkt-rate', 'max-pkt-size', 'max-src-conn', 'max-src-conn-rate',
    'max-src-nodes', 'max-src-states', 'min-ttl', 'modulate', 'nat', 'nat-anchor', 'nat-to', 'no', 'no-df', 'no-route',
    'no-sync', 'on', 'optimization', 'os', 'out', 'overload', 'pass', 'pflow', 'port', 'prefer-ipv6-nexthop', 'prio',
    'priority', 'priq', 'probability', 'proto', 'qlimit', 'queue', 'quick', 'random', 'random-id', 'rdr', 'rdr-anchor',
    'rdr-to', 'realtime', 'reassemble', 'received-on', 'reply-to', 'require-order', 'return', 'return-icmp',
    'return-icmp6', 'return-rst', 'ridentifier', 'round-robin', 'route', 'route-to', 'rtable', 'rule',
    'ruleset-optimization', 'scrub', 'set', 'set-tos', 'skip', 'sloppy', 'source-hash', 'source-track', 'state',
    'state-defaults', 'state-policy', 'static-port', 'sticky-address', 'syncookies', 'synproxy', 'table', 'tag', 'tagged',
    'target', 'tbrsize', 'timeout', 'to', 'tos', 'ttl', 'upperlimit', 'urpf-failed', 'user'];
function standin_alias_messages(array $nodes)
{
    static $services = null;
    if ($services === null) {
        $services = [];
        foreach (explode("\n", (string)@file_get_contents('/etc/services')) as $line) {
            if (strlen($line) > 1 && $line[0] != '#') {
                foreach (preg_split('/\s+/', $line) as $idx => $word) {
                    if ($word === '' || $word[0] == '#') {
                        break;
                    } elseif ($idx != 1) {
                        $services[$word] = true;
                    }
                }
            }
        }
    }
    $types = ['host', 'network', 'port', 'url', 'urltable', 'urljson', 'geoip', 'networkgroup', 'mac', 'asn',
        'dynipv6host', 'authgroup', 'internal', 'external'];
    $named = [];
    foreach ($nodes as $uuid => $fields) {
        $named[(string)($fields['name'] ?? '')][] = $uuid;
    }
    $out = [];
    foreach ($nodes as $uuid => $fields) {
        $at = 'aliases.alias.' . $uuid . '.';
        $name = (string)($fields['name'] ?? '');
        if ($name === '') {
            $out[] = [$at . 'name', 'A value is required.'];
        } elseif (!preg_match('/^([a-zA-Z]|(([_a-zA-Z][a-zA-Z0-9]|[a-zA-Z][_a-zA-Z0-9])[_a-zA-Z0-9]{0,29}))$/', $name)) {
            $out[] = [$at . 'name', 'The name must start with a letter or single underscore, be less than 32 characters ' .
                'and only consist of alphanumeric characters or underscores.'];
        }
        if (in_array($name, STANDIN_RESERVED, true)) {
            $out[] = [$at . 'name', sprintf('The name cannot be the internally reserved keyword "%s".', $name)];
        }
        if ($name !== '' && (isset($services[$name]) || getprotobyname($name) !== false)) {
            $out[] = [$at . 'name', 'Reserved protocol or service names may not be used'];
        }
        if (count($named[$name]) > 1) {
            $out[] = [$at . 'name', 'An alias with this name already exists.'];
        }
        if (!in_array((string)($fields['enabled'] ?? ''), ['0', '1'], true)) {
            $out[] = [$at . 'enabled', 'Value should be a boolean (0,1).'];
        }
        if (!in_array((string)($fields['type'] ?? ''), $types, true)) {
            $out[] = [$at . 'type', sprintf('Option [%s] not in list.', (string)($fields['type'] ?? ''))];
        }
        $text = (string)($fields['description'] ?? '');
        if ($text !== '' && !preg_match('/^(.){1,255}$/', $text)) {
            $out[] = [$at . 'description', 'Description should be a string between 1 and 255 characters.'];
        }
    }
    return $out;
}
VALIDATION;
    $tmp = sys_get_temp_dir() . '/test-aliases.' . getmypid();
    @mkdir($tmp . '/script', 0755, true);
    file_put_contents($tmp . '/validation.php', $validation);
    require $tmp . '/validation.php';

    function refused($model)
    {
        $out = [];
        foreach ($model->performValidation() as $message) {
            $out[] = $message->getField() . ': ' . $message->getMessage();
        }
        return $out;
    }

    function check($ok, $what)
    {
        global $failed, $checks;
        $checks++;
        if (!$ok) {
            $failed++;
            echo "FAIL $what\n";
        } else {
            echo "ok   $what\n";
        }
    }

    function ours($name, $kind, $more = [])
    {
        return $more + ['enabled' => '1', 'name' => $name, 'type' => 'external', 'description' => 'User Identity: ' . $kind];
    }

    /* the names proposed */
    $field = '/^uid_[A-Za-z0-9_]{1,27}$/';  /* the plugin's own alias field, UserIdentity.xml */
    $arabic = "\u{0645}\u{0648}\u{0638}\u{0641}\u{0648}\u{0646}";
    $cases = [
        ['uid_grp_', 'G-Staff', [], 'uid_grp_G_Staff'],
        ['uid_grp_', 'Domain Users', [], 'uid_grp_Domain_Users'],
        ['uid_usr_', 'user1', [], 'uid_usr_user1'],
        ['uid_usr_', 'first.last', [], 'uid_usr_first_last'],
        ['uid_grp_', '  -Sales--Team-  ', [], 'uid_grp_Sales_Team'],
        ['uid_grp_', $arabic, [], 'uid_grp_' . substr(sha1($arabic), 0, 6)],
        ['uid_grp_', 'Staff ' . $arabic, [], 'uid_grp_Staff_' . substr(sha1('Staff ' . $arabic), 0, 6)],
        ['uid_grp_', 'Accounting and Finance Department', [], 'uid_grp_Accounting_and_F_' . substr(sha1('Accounting and Finance Department'), 0, 6)],
        ['uid_grp_', 'G-Staff', ['uid_grp_G_Staff'], 'uid_grp_G_Staff_2'],
        ['uid_grp_', 'G-Staff', ['UID_GRP_G_STAFF', 'uid_grp_G_Staff_2'], 'uid_grp_G_Staff_3'],
        ['uid_grp_', 'Accounting and Finance Department', ['uid_grp_Accounting_and_F_' . substr(sha1('Accounting and Finance Department'), 0, 6)],
            'uid_grp_Accounting_and_F_' . substr(substr(sha1('Accounting and Finance Department'), 0, 6), 0, 4) . '_2'],
        ['uid_grp_', '***', [], 'uid_grp_' . substr(sha1('***'), 0, 6)],
    ];
    $all = [];
    foreach ($cases as [$prefix, $name, $taken, $want]) {
        $got = Aliases::propose($prefix, $name, $taken);
        check($got === $want, sprintf('the name proposed for "%s"%s: %s (got %s)', addcslashes($name, "\x80..\xff"),
            $taken ? ' with ' . implode(', ', $taken) . ' taken' : '', $want, $got));
        $all['u' . count($all)] = ours($got, 'group ' . $name);
    }
    Alias::$given = $all;
    check(refused(new Alias()) === [], 'every name proposed taken by the Alias model\'s validation: the 31 characters, the ' .
        'characters, no reserved word, no service or protocol name');
    check(count(array_filter($all, function ($a) use ($field) {
        return preg_match($field, $a['name']) !== 1 || strlen($a['name']) > 31;
    })) === 0, 'every name proposed taken by the plugin\'s own field, uid_ and at most 31 characters');
    Alias::$given = ['r1' => ours('table', 'x'), 'r2' => ours('user', 'x'), 'r3' => ours('9uid', 'x'),
        'r4' => ours('uid_' . str_repeat('x', 28), 'x'), 'r5' => ours('ssh', 'x')];
    $said = refused(new Alias());
    check(count($said) === 5 && strpos($said[0], 'internally reserved keyword "table"') !== false &&
        strpos($said[1], 'internally reserved keyword "user"') !== false && strpos($said[2], 'must start with') !== false &&
        strpos($said[3], 'must start with') !== false && strpos($said[4], 'Reserved protocol or service') !== false,
        'and what the model refuses refused by the stand-in: two reserved words, a digit first, 32 characters, a service');

    /* made, refreshed, the owner's left */
    $want = ['uid_grp_G_Staff' => ['description' => 'User Identity: group G-Staff'],
        'uid_usr_user1' => ['description' => 'User Identity: user user1']];
    Alias::$given = [];
    $model = new Alias();
    $done = Aliases::reconcile($model, '', $want);
    check($done['changes'] === ['uid_grp_G_Staff: added', 'uid_usr_user1: added'], 'two rows, no alias: both added');
    check($model->getByName('uid_grp_G_Staff')->fields === ['name' => 'uid_grp_G_Staff', 'enabled' => '1',
        'type' => 'external', 'description' => 'User Identity: group G-Staff'],
        'an alias made: switched on, External, no Expire, described as the plugin\'s');
    check(refused($model) === [], 'the aliases made taken by the validation');
    Alias::$given = ['u1' => ours('uid_grp_G_Staff', 'group G-Staff', ['enabled' => '0']), 'u2' => ours('uid_usr_user1', 'user user1')];
    $model = new Alias();
    $done = Aliases::reconcile($model, '', $want);
    check($done['changes'] === ['uid_grp_G_Staff: updated'] && $model->getByName('uid_grp_G_Staff')->enabled === '1',
        'one switched off before, wanted again: switched on; one as it should be: nothing');
    Alias::$given = ['o1' => ['enabled' => '1', 'name' => 'uid_usr_user1', 'type' => 'host', 'description' => 'mine']];
    $model = new Alias();
    $done = Aliases::reconcile($model, '', $want);
    check($model->getByName('uid_usr_user1')->type === 'host' && count($done['notes']) === 1 &&
        strpos($done['notes'][0], 'not one of this plugin') !== false && $done['changes'] === ['uid_grp_G_Staff: added'],
        'the owner\'s alias by a row\'s name: left as it is, said in the notes');

    /* removed, or switched off */
    Alias::$given = [
        'a1' => ours('uid_grp_Gone', 'group Gone'),
        'a2' => ours('uid_grp_Ruled', 'group Ruled'),
        'a3' => ours('uid_grp_Cut', 'group Cut'),
        'a4' => ['enabled' => '1', 'name' => 'uid_mine', 'type' => 'host', 'description' => 'my own list'],
        'a5' => ['enabled' => '1', 'name' => 'office', 'type' => 'host', 'description' => 'User Identity: not mine'],
    ];
    $config = '<alias uuid="a1"><name>uid_grp_Gone</name></alias><alias uuid="a2"><name>uid_grp_Ruled</name></alias>'
        . '<alias uuid="a3"><name>uid_grp_Cut</name></alias><rule><source><network>uid_grp_Ruled</network></source></rule>'
        . '<cut_lists>o9,a3,a2</cut_lists>';
    $model = new Alias();
    $done = Aliases::reconcile($model, Aliases::withoutOwnCuts($config, ['a1', 'a2', 'a3']), []);
    $left = [];
    foreach ($model->aliases->alias->nodes as $node) {
        $left[$node->name] = $node->enabled;
    }
    check($left === ['uid_grp_Ruled' => '0', 'uid_mine' => '1', 'office' => '1'],
        'off: one nothing names removed, one only the plugin put in the cut list removed too, one a rule names switched off, the owner\'s left');
    check($done['changes'] === ['uid_grp_Gone: removed', 'uid_grp_Ruled: no longer wanted, but named elsewhere in the ' .
        'configuration - switched off, not removed', 'uid_grp_Cut: removed'], 'off: said one line each');
    check(Aliases::withoutOwnCuts('<x/><cut_lists>o9,a3,o8</cut_lists>', ['a3']) === '<x/><cut_lists>o9,o8</cut_lists>',
        'the cut list read without the plugin\'s own entries');
    check(Aliases::references('<a/><UserIdentity version="1.0.0"><groups><group uuid="g1"><alias>uid_grp_X</alias></group>' .
        '</groups><general><cut_added>a3</cut_added></general></UserIdentity><rule>uid_grp_X</rule><cut_lists>o9,a3</cut_lists>',
        ['a3']) === '<a/><UserIdentity/><rule>uid_grp_X</rule><cut_lists>o9</cut_lists>',
        'what is read for references: the plugin\'s own section left out - its rows name its aliases - and its cut entries');
    check(Aliases::owned('uid_grp_G_Staff', 'User Identity: group G-Staff') && !Aliases::owned('uid_grp_G_Staff', 'mine') &&
        !Aliases::owned('office', 'User Identity: x'), 'an alias is the plugin\'s by its name and its description together');

    /* the cut list */
    $ours = ['uid_grp_G_Staff' => ['uuid' => 'p1', 'enabled' => true], 'uid_usr_user1' => ['uuid' => 'p2', 'enabled' => true],
        'uid_grp_Old' => ['uuid' => 'p3', 'enabled' => true], 'uid_grp_Off' => ['uuid' => 'p4', 'enabled' => false]];
    check(Aliases::cutLists(['o1', 'p3', 'o2', 'o1', ''], $ours, ['uid_grp_G_Staff' => [], 'uid_usr_user1' => [],
        'uid_grp_Off' => []]) === [['o1', 'o2', 'p1', 'p2'], ['p1', 'p2']],
        'the cut list: the owner\'s entries kept in their order, once; the plugin\'s wanted added and recorded; one no ' .
        'longer wanted out; one switched off not in');
    check(Aliases::cutLists(['p1', 'o1', 'p2'], $ours, [], ['p1', 'p2']) === [['o1'], []],
        'the plugin off: only the owner\'s left, nothing recorded');
    check(Aliases::cutLists(['o1', 'p1'], $ours, ['uid_grp_G_Staff' => []], ['p1']) === [['o1', 'p1'], ['p1']],
        'nothing to change: the same list, the same record');

    /* aliases.php, run as configd runs it */
    $state = $tmp . '/state.json';
    file_put_contents($tmp . '/script/load_phalcon.php', '<?php
namespace OPNsense\Base\Messages { class Message { private $m; private $f;
    public function __construct($m, $f) { $this->m = $m; $this->f = $f; }
    public function getMessage() { return $this->m; } public function getField() { return $this->f; } } }
namespace OPNsense\Firewall {
    class AliasNode { public $fields = []; public function __construct($f = []) { $this->fields = $f; }
        public function __get($n) { return (string)($this->fields[$n] ?? ""); }
        public function __set($n, $v) { $this->fields[$n] = (string)$v; }
        public function setNodes($v) { foreach ($v as $k => $x) { $this->fields[$k] = (string)$x; } } }
    class AliasList { public $nodes = []; public function iterateItems() { foreach ($this->nodes as $u => $n) { yield $u => $n; } }
        public function Add() { $u = "n" . (count($this->nodes) + 100); return $this->nodes[$u] = new AliasNode(); }
        public function del($u) { unset($this->nodes[$u]); } }
    class Alias { public $aliases;
        public function __construct() { $l = new AliasList(); $s = json_decode((string)@file_get_contents(getenv("STATE")), true);
            foreach (($s["aliases"] ?? []) as $u => $f) { $l->nodes[$u] = new AliasNode($f); } $this->aliases = (object)["alias" => $l]; }
        public function getByName($n) { foreach ($this->aliases->alias->nodes as $x) { if ($x->name === $n) { return $x; } } return null; }
        public function performValidation() { $n = []; foreach ($this->aliases->alias->nodes as $u => $x) { $n[$u] = $x->fields; }
            $o = []; foreach (\standin_alias_messages($n) as $m) { $o[] = new \OPNsense\Base\Messages\Message($m[1], $m[0]); } return $o; }
        public function serializeToConfig() { $s = json_decode((string)@file_get_contents(getenv("STATE")), true) ?: [];
            $s["aliases"] = []; foreach ($this->aliases->alias->nodes as $u => $n) { $s["aliases"][$u] = $n->fields; }
            file_put_contents(getenv("STATE"), json_encode($s)); } } }
namespace OPNsense\UserIdentity {
    class Rows { public $rows; public function __construct($r) { $this->rows = $r; }
        public function iterateItems() { foreach ($this->rows as $u => $r) { yield $u => (object)$r; } } }
    class UserIdentity { public $general; public $groups; public $users;
        public function __construct() { $s = json_decode((string)@file_get_contents(getenv("STATE")), true);
            $this->general = (object)["enabled" => $s["enabled"] ?? "0", "cut_added" => $s["cut_added"] ?? ""];
            $this->groups = (object)["group" => new Rows($s["groups"] ?? [])];
            $this->users = (object)["user" => new Rows($s["users"] ?? [])]; }
        public function performValidation() { return []; }
        public function serializeToConfig() { $s = json_decode((string)@file_get_contents(getenv("STATE")), true);
            $s["cut_added"] = (string)$this->general->cut_added; file_put_contents(getenv("STATE"), json_encode($s)); } } }
namespace OPNsense\XGS {
    if (getenv("XGS") === "1") {
        class Node { public $value; public $changed = false; public function __construct($v) { $this->value = $v; }
            public function __toString() { return $this->value; }
            public function setValue($v) { $this->value = $v; $this->changed = true; } }
        class XGS { public $node;
            public function __construct() { $s = json_decode((string)@file_get_contents(getenv("STATE")), true);
                $this->node = new Node($s["cut_lists"] ?? ""); }
            public function getNodeByReference($r) { return $r === "general.cut_lists" ? $this->node : null; }
            public function performValidation() { $s = json_decode((string)@file_get_contents(getenv("STATE")), true); $o = [];
                foreach (array_filter(explode(",", $this->node->value)) as $u) {
                    if (!isset($s["aliases"][$u]) && strpos($u, "owner") !== 0) {
                        $o[] = new \OPNsense\Base\Messages\Message("Option not in list.", "general.cut_lists"); } } return $o; }
            public function serializeToConfig() { $s = json_decode((string)@file_get_contents(getenv("STATE")), true);
                $s["cut_lists"] = $this->node->value; file_put_contents(getenv("STATE"), json_encode($s)); } } } }
namespace OPNsense\Core { class Config { public static function getInstance() { return new self(); }
    public function save() { $s = json_decode((string)file_get_contents(getenv("STATE")), true);
        $s["saved"] = ($s["saved"] ?? 0) + 1; file_put_contents(getenv("STATE"), json_encode($s)); } } }
namespace { require "' . $root . '/src/opnsense/mvc/app/library/OPNsense/UserIdentity/Aliases.php"; require "' . $tmp . '/validation.php"; }
');
    copy($root . '/src/opnsense/scripts/useridentity/aliases.php', $tmp . '/aliases.php');

    /* config.xml as OPNsense would hold what the stand-ins' state says: the plugin's own section - its
       rows carry the alias names, and its record of the cut list the uuids - the aliases, XGS: Settings'
       cut list, and $more, a rule say */
    function config_text($s, $more = '')
    {
        $rows = '';
        foreach (['groups' => 'group', 'users' => 'user'] as $list => $kind) {
            $rows .= '<' . $list . '>';
            foreach ($s[$list] ?? [] as $uuid => $row) {
                $rows .= sprintf('<%s uuid="%s"><enabled>%s</enabled><name>%s</name><alias>%s</alias><description/></%s>',
                    $kind, $uuid, $row['enabled'], $row['name'], $row['alias'], $kind);
            }
            $rows .= '</' . $list . '>';
        }
        $aliases = '';
        foreach ($s['aliases'] ?? [] as $uuid => $a) {
            $aliases .= sprintf('<alias uuid="%s"><enabled>%s</enabled><name>%s</name><type>%s</type>' .
                '<description>%s</description></alias>', $uuid, $a['enabled'] ?? '1', $a['name'] ?? '', $a['type'] ?? '',
                $a['description'] ?? '');
        }
        return '<?xml version="1.0"?>' . "\n" . '<opnsense><OPNsense><UserIdentity version="1.0.0"><general><enabled>' .
            ($s['enabled'] ?? '0') . '</enabled><cut_added>' . ($s['cut_added'] ?? '') . '</cut_added></general>' . $rows .
            '</UserIdentity><Firewall><Alias><aliases>' . $aliases . '</aliases></Alias></Firewall><XGS><general><cut_lists>' .
            ($s['cut_lists'] ?? '') . '</cut_lists></general></XGS></OPNsense>' . $more . '</opnsense>' . "\n";
    }

    /* aliases.php run as configd runs it, with config.xml written from the state first */
    function run_script($tmp, $state, $env, $args = '', $more = '')
    {
        $config = $tmp . '/config.xml';
        file_put_contents($config, config_text(json_decode((string)@file_get_contents($state), true) ?: [], $more));
        $prefix = 'USERIDENTITY_CONFIG=' . escapeshellarg($config) . ' ';
        foreach ($env as $k => $v) {
            $prefix .= $k . '=' . escapeshellarg($v) . ' ';
        }
        $out = shell_exec($prefix . 'STATE=' . escapeshellarg($state) . ' ' . escapeshellarg(PHP_BINARY) .
            ' -d include_path=' . escapeshellarg($tmp) . ' ' . escapeshellarg($tmp . '/aliases.php') . ' ' . $args);
        return [json_decode((string)$out, true), json_decode((string)@file_get_contents($state), true)];
    }

    $rows = ['enabled' => '1',
        'groups' => ['g1' => ['enabled' => '1', 'name' => 'G-Staff', 'alias' => 'uid_grp_G_Staff'],
            'g2' => ['enabled' => '0', 'name' => 'Guests', 'alias' => 'uid_grp_Guests']],
        'users' => ['s1' => ['enabled' => '1', 'name' => 'user1', 'alias' => 'uid_usr_user1']],
        'cut_lists' => 'owner-1,owner-2',
        'aliases' => ['owner-1' => ['enabled' => '1', 'name' => 'blocked', 'type' => 'host', 'description' => 'mine']]];
    file_put_contents($state, json_encode($rows));
    [$out, $saved] = run_script($tmp, $state, ['XGS' => '1']);
    $names = array_column($saved['aliases'] ?? [], 'name');
    check(($out['status'] ?? '') === 'ok' && $names === ['blocked', 'uid_grp_G_Staff', 'uid_usr_user1'] &&
        ($saved['saved'] ?? 0) === 1, 'aliases.php, on: an alias for each row switched on, the owner\'s left, saved once');
    check(($saved['cut_lists'] ?? '') === 'owner-1,owner-2,n101,n102' && ($out['cut']['lists'] ?? 0) === 2,
        'aliases.php: the cut list holds the two, after the owner\'s entries kept as they were');
    check(($saved['cut_added'] ?? '') === 'n101,n102', 'aliases.php: the plugin\'s record says it put the two there');
    [$out, $saved] = run_script($tmp, $state, ['XGS' => '1']);
    check(($out['changes'] ?? null) === [] && ($saved['saved'] ?? 0) === 1, 'aliases.php again, nothing changed: nothing saved');
    /* the owner takes G-Staff's table out of XGS: Settings' cut list (the review's fourth finding) */
    $saved['cut_lists'] = 'owner-1,owner-2,n102';
    file_put_contents($state, json_encode($saved));
    [$out, $saved] = run_script($tmp, $state, ['XGS' => '1']);
    check(($saved['cut_lists'] ?? '') === 'owner-1,owner-2,n102' && ($out['changes'] ?? null) === [] &&
        ($saved['cut_added'] ?? '') === 'n101,n102',
        'aliases.php after the owner took a table out of the cut list: not put back - lists_cut.py would take all it holds as new');
    $saved['enabled'] = '0';
    file_put_contents($state, json_encode($saved));
    [$out, $saved] = run_script($tmp, $state, ['XGS' => '1']);
    check(($out['status'] ?? '') === 'ok' && array_column($saved['aliases'], 'name') === ['blocked'] &&
        ($saved['cut_lists'] ?? '') === 'owner-1,owner-2' && ($saved['saved'] ?? 0) === 2,
        'aliases.php, off, config.xml holding the plugin\'s rows: the plugin\'s aliases removed - its own rows and cut ' .
        'list entries are no one else\'s - and out of the cut list, saved once');
    check(($saved['cut_added'] ?? 'x') === '', 'aliases.php, off: the record forgets them with them');
    $saved['enabled'] = '1';
    file_put_contents($state, json_encode($saved));
    [$out, $saved] = run_script($tmp, $state, ['XGS' => '1']);
    $saved['enabled'] = '0';
    file_put_contents($state, json_encode($saved));
    [$out, $saved] = run_script($tmp, $state, ['XGS' => '1'], '',
        '<filter><rule><source><network>uid_grp_G_Staff</network></source></rule></filter>');
    $left = [];
    foreach ($saved['aliases'] as $alias) {
        $left[$alias['name']] = $alias['enabled'];
    }
    check($left === ['blocked' => '1', 'uid_grp_G_Staff' => '0'],
        'aliases.php, off, a rule naming one: that one switched off, the other removed');
    /* the owner deletes the alias the rule named, to go on with the rest */
    foreach ($saved['aliases'] as $uuid => $alias) {
        if ($alias['name'] === 'uid_grp_G_Staff') {
            unset($saved['aliases'][$uuid]);
        }
    }
    file_put_contents($state, json_encode($saved));
    $saved['enabled'] = '1';
    $saved['users']['s1']['alias'] = 'uid_usr_bad-name';
    file_put_contents($state, json_encode($saved));
    [$out, $after] = run_script($tmp, $state, ['XGS' => '1']);
    check(($out['status'] ?? '') === 'failed' && count($out['errors'] ?? []) === 1 &&
        strpos($out['errors'][0], 'must start with a letter') !== false && ($after['saved'] ?? 0) === ($saved['saved'] ?? 0) &&
        array_column($after['aliases'], 'name') === ['blocked'], 'aliases.php, a name the model refuses: said, nothing saved');
    $saved['users']['s1']['alias'] = 'uid_usr_user1';
    file_put_contents($state, json_encode($saved));
    [$out, $after] = run_script($tmp, $state, []);
    check(($out['status'] ?? '') === 'ok' && ($out['cut']['xgs'] ?? true) === false && ($after['cut_lists'] ?? '') ===
        'owner-1,owner-2' && count($after['aliases']) === 3 && ($after['cut_added'] ?? 'x') === '',
        'aliases.php without os-xgs-npu: the aliases made, no cut list or record touched');
    $made = array_keys(array_filter($after['aliases'], function ($a) {
        return strpos($a['name'], 'uid_') === 0;
    }));
    [$out, $after] = run_script($tmp, $state, ['XGS' => '1']);
    check(($after['cut_lists'] ?? '') === 'owner-1,owner-2,' . implode(',', $made) &&
        ($after['cut_added'] ?? '') === implode(',', $made),
        'os-xgs-npu installed after the aliases were made: each put in the cut list once, and recorded');
    [$out, $after] = run_script($tmp, $state, ['XGS' => '1'], '--remove');
    check(($out['status'] ?? '') === 'ok' && array_column($after['aliases'], 'name') === ['blocked'] &&
        ($after['cut_lists'] ?? '') === 'owner-1,owner-2' && ($after['cut_added'] ?? 'x') === '',
        'aliases.php --remove: every alias of the plugin\'s out, out of the cut list and of the record');
    $ours = ['a' => ['uuid' => 'p1', 'enabled' => true], 'b' => ['uuid' => 'p2', 'enabled' => true],
        'c' => ['uuid' => 'p3', 'enabled' => false]];
    check(Aliases::cutLists(['o1', 'p2'], $ours, ['a' => [], 'b' => [], 'c' => []], ['p2']) === [['o1', 'p2', 'p1'], ['p2', 'p1']],
        'the cut list and the record: one wanted and never put there added and recorded, one already there kept');
    check(Aliases::cutLists(['o1'], $ours, ['a' => [], 'b' => []], ['p1', 'p2']) === [['o1'], ['p1', 'p2']],
        'the cut list and the record: two the owner took out stay out, and stay recorded');
    check(Aliases::cutLists(['o1', 'p1', 'p3'], $ours, ['b' => []], ['p1', 'p2', 'p3']) === [['o1'], ['p2']],
        'the cut list and the record: no longer wanted, or switched off - out of both, so wanted again goes back in');

    foreach (glob($tmp . '/script/*') as $f) {
        unlink($f);
    }
    rmdir($tmp . '/script');
    foreach (glob($tmp . '/*') as $f) {
        unlink($f);
    }
    rmdir($tmp);

    echo $failed ? "$failed of $checks checks failed\n" : "$checks checks passed\n";
    exit($failed ? 1 : 0);
}
