<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\UserIdentity;

use OPNsense\Base\BaseModel;
use OPNsense\Base\Messages\Message;

class UserIdentity extends BaseModel
{
    /**
     * Beside each field's own checks: an alias name is one table, so a group row and a user row - or
     * two of either - may not give the same one. Every row that gives it is said, so the one being
     * saved is told whichever it is.
     */
    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);
        $seen = [];
        foreach (['groups' => 'group', 'users' => 'user'] as $list => $kind) {
            foreach ($this->$list->$kind->iterateItems() as $uuid => $row) {
                $alias = strtolower((string)$row->alias);
                if ($alias !== '') {
                    $seen[$alias][] = $list . '.' . $kind . '.' . $uuid . '.alias';
                }
            }
        }
        foreach ($seen as $fields) {
            if (count($fields) > 1) {
                foreach ($fields as $field) {
                    $messages->appendMessage(new Message(gettext('Another row gives this alias name.'), $field));
                }
            }
        }
        return $messages;
    }
}
