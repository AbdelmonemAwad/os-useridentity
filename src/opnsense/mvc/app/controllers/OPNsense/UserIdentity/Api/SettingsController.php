<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\UserIdentity\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Firewall\Alias;
use OPNsense\UserIdentity\Aliases;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'useridentity';
    protected static $internalModelClass = '\OPNsense\UserIdentity\UserIdentity';

    /* the group rows (settled point 5): a table each */

    public function searchGroupsAction()
    {
        return $this->searchBase('groups.group', ['enabled', 'name', 'alias', 'description'], 'name');
    }

    public function getGroupAction($uuid = null)
    {
        return $this->getBase('group', 'groups.group', $uuid);
    }

    public function addGroupAction()
    {
        return $this->addBase('group', 'groups.group', $this->proposed('group', 'uid_grp_'));
    }

    public function setGroupAction($uuid)
    {
        return $this->setBase('group', 'groups.group', $uuid, $this->proposed('group', 'uid_grp_', $uuid));
    }

    public function delGroupAction($uuid)
    {
        return $this->delBase('groups.group', $uuid);
    }

    public function toggleGroupAction($uuid, $enabled = null)
    {
        return $this->toggleBase('groups.group', $uuid, $enabled);
    }

    /* the users the owner names (settled point 6): a table each */

    public function searchUsersAction()
    {
        return $this->searchBase('users.user', ['enabled', 'name', 'alias', 'description'], 'name');
    }

    public function getUserAction($uuid = null)
    {
        return $this->getBase('user', 'users.user', $uuid);
    }

    public function addUserAction()
    {
        return $this->addBase('user', 'users.user', $this->proposed('user', 'uid_usr_'));
    }

    public function setUserAction($uuid)
    {
        return $this->setBase('user', 'users.user', $uuid, $this->proposed('user', 'uid_usr_', $uuid));
    }

    public function delUserAction($uuid)
    {
        return $this->delBase('users.user', $uuid);
    }

    public function toggleUserAction($uuid, $enabled = null)
    {
        return $this->toggleBase('users.user', $uuid, $enabled);
    }

    /**
     * The alias name proposed for a row saved with none (settled point 5), as the overlay addBase()
     * and setBase() put on the row before it is validated: ['alias' => name], or null when the row
     * gives one, or no name to make one from. Not one another row gives, nor an alias of Firewall:
     * Aliases has.
     */
    protected function proposed($post, $prefix, $uuid = null)
    {
        $row = $this->request->getPost($post);
        if (!is_array($row) || trim((string)($row['alias'] ?? '')) !== '' || trim((string)($row['name'] ?? '')) === '') {
            return null;
        }
        $taken = [];
        $model = $this->getModel();
        foreach (['groups' => 'group', 'users' => 'user'] as $list => $kind) {
            foreach ($model->$list->$kind->iterateItems() as $key => $node) {
                if ((string)$key !== (string)$uuid && (string)$node->alias !== '') {
                    $taken[] = (string)$node->alias;
                }
            }
        }
        foreach ((new Alias())->aliases->alias->iterateItems() as $alias) {
            $taken[] = (string)$alias->name;
        }
        return ['alias' => Aliases::propose($prefix, (string)$row['name'], $taken)];
    }
}
