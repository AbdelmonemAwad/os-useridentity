<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 *
 * The page's API (Api/ServiceController and Api/SettingsController), run as OPNsense runs it, with
 * stand-ins for what they reach of OPNsense's MVC: ApiControllerBase and ApiMutableModelControllerBase -
 * the request, the grids' search, the rows' add and set, which here hand back what they were given -
 * configd (Backend), the plugin's model and the Alias model.
 *
 * What is checked: the status script's answer passed on, and one that cannot be read said; the Users
 * and Sources grids' rows; Apply - the aliases, syslog-ng's source and syslog-ng restarted only when it
 * changed, the filter, the tables of aliases gone, the collector - in that order, and off the collector
 * stopped and every mapping forgotten, even when the aliases could not be written; nothing for a GET;
 * Forget all; the directory's Test, asked with the name quoted by configd and refused for a name that
 * is none; and the alias name proposed for a row saved without one, never one another row or alias has.
 *
 *   php tools/test-mvc.php
 */

namespace OPNsense\Base {
    class Request
    {
        public $post = true;
        public $data = [];

        public function isPost()
        {
            return $this->post;
        }

        public function getPost($name = null, $filter = null, $default = null)
        {
            return $this->data[$name] ?? $default;
        }
    }

    class ApiControllerBase
    {
        public $request;

        public function __construct()
        {
            $this->request = new Request();
        }

        protected function searchRecordsetBase($records, $fields = null, $defaultSort = null)
        {
            return ['rows' => $records, 'fields' => $fields, 'sort' => $defaultSort];
        }
    }

    class ApiMutableModelControllerBase extends ApiControllerBase
    {
        public $model;

        protected function getModel()
        {
            return $this->model;
        }

        public function searchBase($path, $fields = null, $sort = null)
        {
            return ['search', $path, $fields, $sort];
        }

        public function getBase($key, $path, $uuid = null)
        {
            return ['get', $key, $path, $uuid];
        }

        public function addBase($post, $path, $overlay = null)
        {
            return ['add', $post, $path, $overlay];
        }

        public function setBase($post, $path, $uuid, $overlay = null)
        {
            return ['set', $post, $path, $uuid, $overlay];
        }

        public function delBase($path, $uuid)
        {
            return ['del', $path, $uuid];
        }

        public function toggleBase($path, $uuid, $enabled = null)
        {
            return ['toggle', $path, $uuid, $enabled];
        }
    }
}

namespace OPNsense\Core {
    class Backend
    {
        public static $answers = [];
        public static $asked = [];

        public function configdRun($event, $detach = false)
        {
            self::$asked[] = $event;
            return self::$answers[$event] ?? null;
        }

        public function configdpRun($event, $params = [], $detach = false)
        {
            foreach ($params as $param) {
                $event .= ' ' . escapeshellarg($param);
            }
            return $this->configdRun($event, $detach);
        }
    }
}

namespace OPNsense\Firewall {
    class Alias
    {
        public static $names = [];
        public $aliases;

        public function __construct()
        {
            $list = new class {
                public function iterateItems()
                {
                    foreach (Alias::$names as $i => $name) {
                        yield 'a' . $i => (object)['name' => $name];
                    }
                }
            };
            $this->aliases = (object)['alias' => $list];
        }
    }
}

namespace OPNsense\UserIdentity {
    class Rows
    {
        public $rows;

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

    class UserIdentity
    {
        public static $enabled = '1';
        public static $groupRows = [];
        public static $userRows = [];
        public $general;
        public $groups;
        public $users;

        public function __construct()
        {
            $this->general = (object)['enabled' => self::$enabled];
            $this->groups = (object)['group' => new Rows(self::$groupRows)];
            $this->users = (object)['user' => new Rows(self::$userRows)];
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
    require $root . '/src/opnsense/mvc/app/library/OPNsense/UserIdentity/Aliases.php';
    require $root . '/src/opnsense/mvc/app/controllers/OPNsense/UserIdentity/Api/ServiceController.php';
    require $root . '/src/opnsense/mvc/app/controllers/OPNsense/UserIdentity/Api/SettingsController.php';

    use OPNsense\Core\Backend;
    use OPNsense\Firewall\Alias;
    use OPNsense\UserIdentity\Api\ServiceController;
    use OPNsense\UserIdentity\Api\SettingsController;
    use OPNsense\UserIdentity\UserIdentity;

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

    /* status */
    Backend::$answers = ['useridentity status' => json_encode(['enabled' => true, 'counts' => ['users' => 2]])];
    check((new ServiceController())->statusAction() === ['enabled' => true, 'counts' => ['users' => 2]],
        'status: the status script\'s answer passed on');
    foreach (['', 'not json', '"a string"', null] as $bad) {
        Backend::$answers = ['useridentity status' => $bad];
        check((new ServiceController())->statusAction() === ['error' => 'No answer could be read.'],
            'status: configd answering ' . json_encode($bad) . ': could not be read');
    }

    /* the grids */
    Backend::$answers = ['useridentity map' => json_encode(['rows' => [
        ['address' => '192.0.2.20', 'user' => 'user2', 'domain' => 'EXAMPLE', 'groups' => ['G-Staff', 'G-Sales'], 'known' => true,
            'source' => '192.0.2.10', 'first' => 1794940893, 'last' => 1794940900.5, 'expires' => 1794969700,
            'mac' => '02:00:00:00:00:14', 'shared' => ['user1']],
        'not a row',
        ['address' => '2001:db8::20', 'user' => 'user1'],
    ]])];
    $grid = (new ServiceController())->searchMapAction();
    check(count($grid['rows']) === 2 && $grid['rows'][0]['groups'] === 'G-Staff, G-Sales' && $grid['rows'][0]['shared'] === 'user1' &&
        $grid['rows'][0]['last'] === 1794940900 && $grid['rows'][1]['first'] === null && $grid['rows'][1]['known'] === false &&
        $grid['rows'][1]['groups'] === '', 'Users: each address\'s row, its groups and the users sharing it joined, what is missing empty');
    check($grid['sort'] === 'address' && $grid['fields'] === ['address', 'user', 'groups', 'source', 'mac', 'shared'],
        'Users: searched by address, user, group, domain controller, MAC and who shares it, by address');
    Backend::$answers = ['useridentity status' => json_encode(['sources' => [
        ['address' => '192.0.2.10', 'named' => true, 'hostname' => 'DC1.example.test', 'last_line' => 1794940900,
            'last_event' => 1794940898, 'late' => 2.0, 'accepted' => 5, 'joined' => 1, 'renewed' => 4, 'stale' => 1,
            'refused' => 3, 'reasons' => ['computer' => 2, 'not a user' => 1], 'other' => 7],
        ['address' => '192.0.2.2', 'named' => false, 'refused' => 1, 'reasons' => ['not a domain controller' => 1]],
    ]])];
    $grid = (new ServiceController())->searchSourcesAction();
    check(count($grid['rows']) === 2 && $grid['rows'][0]['reasons'] === [['reason' => 'computer', 'count' => 2],
        ['reason' => 'not a user', 'count' => 1]] && $grid['rows'][0]['late'] === 2.0 && $grid['rows'][1]['named'] === false &&
        $grid['rows'][1]['last_line'] === null, 'Sources: each sender\'s row, its refusals by reason');

    /* Apply */
    $controller = new ServiceController();
    $controller->request->post = false;
    Backend::$asked = [];
    check($controller->reconfigureAction() === ['status' => 'failed'] && Backend::$asked === [], 'Apply by GET: refused, nothing asked');
    $ok = ['useridentity apply' => json_encode(['status' => 'ok', 'changes' => ['uid_grp_G_Staff: added']]),
        'useridentity source' => json_encode(['written' => true, 'changed' => true, 'port' => 5141]),
        'useridentity gone' => json_encode(['killed' => ['uid_grp_Gone'], 'errors' => []])];
    Backend::$answers = $ok;
    Backend::$asked = [];
    UserIdentity::$enabled = '1';
    $result = (new ServiceController())->reconfigureAction();
    check(Backend::$asked === ['useridentity apply', 'useridentity source', 'syslog restart', 'filter reload skip_alias',
        'useridentity gone', 'useridentity restart'],
        'Apply, on: the aliases, the source, syslog-ng restarted as it changed, the filter, the tables gone, the collector');
    check($result['status'] === 'ok' && $result['enabled'] === true && $result['source']['written'] === true &&
        $result['gone_tables']['killed'] === ['uid_grp_Gone'] && $result['changes'] === ['uid_grp_G_Staff: added'],
        'Apply: what changed, the source and the tables gone passed on to the page');
    Backend::$answers['useridentity source'] = json_encode(['written' => true, 'changed' => false]);
    Backend::$asked = [];
    (new ServiceController())->reconfigureAction();
    check(!in_array('syslog restart', Backend::$asked, true), 'Apply, the source unchanged: syslog-ng left running');
    UserIdentity::$enabled = '0';
    Backend::$answers['useridentity source'] = json_encode(['written' => false, 'changed' => true, 'reason' => 'off']);
    Backend::$asked = [];
    (new ServiceController())->reconfigureAction();
    check(Backend::$asked === ['useridentity apply', 'useridentity source', 'syslog restart', 'filter reload skip_alias',
        'useridentity gone', 'useridentity stop', 'useridentity flush'],
        'Apply, off: the source taken away and syslog-ng restarted, then the collector stopped and every mapping forgotten');
    UserIdentity::$enabled = '1';
    Backend::$answers = ['useridentity apply' => json_encode(['status' => 'failed', 'errors' => ['refused']])];
    Backend::$asked = [];
    $result = (new ServiceController())->reconfigureAction();
    check(Backend::$asked === ['useridentity apply'] && $result['errors'] === ['refused'],
        'Apply, on, the aliases not written: nothing more done, the reason passed on');
    Backend::$answers = [];
    Backend::$asked = [];
    $result = (new ServiceController())->reconfigureAction();
    check(Backend::$asked === ['useridentity apply'] && $result['status'] === 'failed', 'Apply, on, no answer: failed, nothing more');
    UserIdentity::$enabled = '0';
    Backend::$answers = ['useridentity apply' => json_encode(['status' => 'failed', 'errors' => ['refused']])];
    Backend::$asked = [];
    $result = (new ServiceController())->reconfigureAction();
    check(Backend::$asked === ['useridentity apply', 'useridentity stop', 'useridentity flush'] && $result['enabled'] === false,
        'Apply, off, the aliases not written: the collector stopped and the map forgotten all the same');

    /* Forget all, Test */
    Backend::$answers = ['useridentity flush' => json_encode(['flushed' => 3])];
    Backend::$asked = [];
    check((new ServiceController())->flushAction() === ['flushed' => 3] && Backend::$asked === ['useridentity flush'],
        'Forget all: the map emptied by configd, its answer passed on');
    $controller = new ServiceController();
    $controller->request->post = false;
    Backend::$asked = [];
    check($controller->flushAction() === ['status' => 'failed'] && Backend::$asked === [], 'Forget all by GET: refused');
    foreach (['user1' => "useridentity ldaptest 'user1'", "first.last@example" => "useridentity ldaptest 'first.last@example'",
                 "J\u{00fc}rgen M" => "useridentity ldaptest 'J\u{00fc}rgen M'"] as $name => $want) {
        $controller = new ServiceController();
        $controller->request->data = ['user' => $name];
        Backend::$answers = [$want => json_encode(['status' => 'ok', 'user' => $name])];
        Backend::$asked = [];
        $result = $controller->ldaptestAction();
        check(Backend::$asked === [$want] && $result['status'] === 'ok', 'Test: ' . json_encode($name) . ' asked, quoted');
    }
    foreach (["a';reboot;'", 'a/b', '', str_repeat('x', 65), "a\nb"] as $name) {
        $controller = new ServiceController();
        $controller->request->data = ['user' => $name];
        Backend::$asked = [];
        $result = $controller->ldaptestAction();
        check(Backend::$asked === [] && $result['status'] === 'failed', 'Test: ' . json_encode($name) . ' refused, nothing asked');
    }

    /* the alias name proposed for a row saved without one */
    function settings_with($post, $groups = [], $users = [], $aliases = [])
    {
        $controller = new SettingsController();
        UserIdentity::$groupRows = $groups;
        UserIdentity::$userRows = $users;
        Alias::$names = $aliases;
        $controller->model = new UserIdentity();
        $controller->request->data = $post;
        return $controller;
    }

    $add = settings_with(['group' => ['enabled' => '1', 'name' => 'G-Staff', 'alias' => '']])->addGroupAction();
    check($add === ['add', 'group', 'groups.group', ['alias' => 'uid_grp_G_Staff']], 'a group row added with no alias: one proposed');
    $add = settings_with(['group' => ['name' => 'G-Staff', 'alias' => ' ']], ['g1' => 'uid_grp_G_Staff'])->addGroupAction();
    check($add[3] === ['alias' => 'uid_grp_G_Staff_2'], 'another row gives that name: _2');
    $add = settings_with(['group' => ['name' => 'G-Staff', 'alias' => '']], [], ['u1' => 'uid_grp_G_Staff_2'],
        ['uid_grp_G_Staff'])->addGroupAction();
    check($add[3] === ['alias' => 'uid_grp_G_Staff_3'], 'an alias of Firewall: Aliases and a user row give the names before: _3');
    $set = settings_with(['group' => ['name' => 'G-Staff', 'alias' => '']], ['g1' => 'uid_grp_G_Staff'])->setGroupAction('g1');
    check($set === ['set', 'group', 'groups.group', 'g1', ['alias' => 'uid_grp_G_Staff']], 'a row saved again: its own old name not counted');
    $add = settings_with(['group' => ['name' => 'G-Staff', 'alias' => 'uid_staff']])->addGroupAction();
    check($add[3] === null, 'a row that gives its alias: nothing proposed');
    $add = settings_with(['group' => ['name' => '', 'alias' => '']])->addGroupAction();
    check($add[3] === null, 'a row with no name: nothing proposed, the model says what is missing');
    $add = settings_with(['user' => ['name' => 'first.last', 'alias' => '']])->addUserAction();
    check($add === ['add', 'user', 'users.user', ['alias' => 'uid_usr_first_last']], 'a user row: uid_usr_ and its name');
    $c = settings_with([]);
    check($c->searchGroupsAction() === ['search', 'groups.group', ['enabled', 'name', 'alias', 'description'], 'name'] &&
        $c->delUserAction('u1') === ['del', 'users.user', 'u1'] && $c->toggleGroupAction('g1', '0') === ['toggle', 'groups.group', 'g1', '0'],
        'the rows\' grids: searched, deleted and switched through the model');

    echo $failed ? "$failed of $checks checks failed\n" : "$checks checks passed\n";
    exit($failed ? 1 : 0);
}
