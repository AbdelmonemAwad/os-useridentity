<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The plugin's model (models/OPNsense/UserIdentity/UserIdentity.php): its own checks, run as a Save runs
 * them, with stand-ins for what it reaches of OPNsense - BaseModel, whose fields' own checks give
 * nothing here, as for valid entries, and which says whether the port was changed; Message; and Config,
 * for the system's settings.
 *
 * What is checked: the port the domain controllers send to refused when the firewall itself serves it -
 * SSH, DNS, the web GUI on 80 and 443, and the ports System: Settings: Administration moves the web GUI
 * and SSH to - and only when it was changed or the whole model is checked, so a port saved before the
 * web GUI was moved onto it blocks no other change; any other port taken; and two rows giving one
 * alias name each told.
 *
 *   php tools/test-model.php
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

namespace OPNsense\Base {
    class Messages implements \IteratorAggregate
    {
        public $all = [];

        public function appendMessage($message)
        {
            $this->all[] = $message;
        }

        public function getIterator(): \Iterator
        {
            return new \ArrayIterator($this->all);
        }
    }

    class Field
    {
        private $value;
        private $changed;

        public function __construct($value, $changed)
        {
            $this->value = (string)$value;
            $this->changed = $changed;
        }

        public function __toString()
        {
            return $this->value;
        }

        public function isFieldChanged()
        {
            return $this->changed;
        }
    }

    class Rows
    {
        private $rows;

        public function __construct($rows)
        {
            $this->rows = $rows;
        }

        public function iterateItems()
        {
            foreach ($this->rows as $uuid => $alias) {
                yield $uuid => (object)['alias' => $alias];
            }
        }
    }

    abstract class BaseModel
    {
        public static $port = '514';
        public static $changed = true;
        public static $groupRows = [];
        public static $userRows = [];
        public $general;
        public $groups;
        public $users;

        public function __construct()
        {
            $this->general = (object)['port' => new Field(self::$port, self::$changed)];
            $this->groups = (object)['group' => new Rows(self::$groupRows)];
            $this->users = (object)['user' => new Rows(self::$userRows)];
        }

        public function performValidation($validateFullModel = false)
        {
            return new Messages();
        }
    }
}

namespace OPNsense\Core {
    class Config
    {
        public static $system = [];
        private static $instance = null;

        public static function getInstance()
        {
            return self::$instance ?? (self::$instance = new Config());
        }

        public function toArray($forceList = null, $node = null)
        {
            return ['system' => self::$system];
        }
    }
}

namespace {
    if (!function_exists('gettext')) {
        function gettext($text)
        {
            return $text;
        }
    }

    $root = dirname(__DIR__);
    $library = $root . '/src/opnsense/mvc/app/library/OPNsense/UserIdentity/Ports.php';
    if (is_file($library)) {
        require $library;
    }
    require $root . '/src/opnsense/mvc/app/models/OPNsense/UserIdentity/UserIdentity.php';

    use OPNsense\Base\BaseModel;
    use OPNsense\Core\Config;
    use OPNsense\UserIdentity\UserIdentity;

    const SERVED = 'The firewall itself serves this port (SSH, DNS or the web GUI): the domain controllers would '
        . 'no longer reach that service on it. Choose another, such as 514.';

    $failed = 0;
    $checks = 0;

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

    /* [field => message] of a Save with this port, the system's settings and the rows */
    function saved($port, $system = [], $changed = true, $full = false, $groups = [], $users = [])
    {
        BaseModel::$port = $port;
        BaseModel::$changed = $changed;
        BaseModel::$groupRows = $groups;
        BaseModel::$userRows = $users;
        Config::$system = $system;
        $out = [];
        foreach ((new UserIdentity())->performValidation($full) as $message) {
            $out[] = [$message->getField(), $message->getMessage()];
        }
        return $out;
    }

    $refused = [['general.port', SERVED]];

    check(saved('514') === [], 'port 514, the default: taken');
    foreach (['22' => 'SSH', '53' => 'DNS', '80' => 'the web GUI over HTTP', '443' => 'the web GUI'] as $port => $what) {
        check(saved($port) === $refused, "port $port, $what: refused on the port's field, said why");
    }
    check(saved('8443') === [], 'port 8443, the web GUI on 443: taken');
    check(saved('8443', ['webgui' => ['protocol' => 'https', 'port' => '8443']]) === $refused,
        'port 8443 with the web GUI moved to it: refused');
    check(saved('2222', ['ssh' => ['enabled' => 'enabled', 'port' => '2222']]) === $refused,
        'port 2222 with SSH moved to it: refused');
    check(saved('2222', ['ssh' => ['port' => ''], 'webgui' => ''], true) === [],
        'port 2222, the settings of SSH and the web GUI empty - 22 and 443: taken');
    check(saved('8443', ['webgui' => ['port' => '8443']], false) === [],
        'port 8443 not changed by this Save, the web GUI moved onto it since: no other change blocked');
    check(saved('8443', ['webgui' => ['port' => '8443']], false, true) === $refused,
        'the same with the whole model checked: refused');

    $both = saved('514', [], true, false, ['g1' => 'uid_staff'], ['u1' => 'UID_Staff']);
    check($both === [['groups.group.g1.alias', 'Another row gives this alias name.'],
        ['users.user.u1.alias', 'Another row gives this alias name.']],
        'a group row and a user row giving one alias name, case aside: each told');
    check(saved('514', [], true, false, ['g1' => 'uid_staff', 'g2' => ''], ['u1' => 'uid_alice']) === [],
        'every alias name its own, and a row with none: nothing said');

    echo $failed ? "$failed of $checks checks failed\n" : "$checks checks passed\n";
    exit($failed ? 1 : 0);
}
