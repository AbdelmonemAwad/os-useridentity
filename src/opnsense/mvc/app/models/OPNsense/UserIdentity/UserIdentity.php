<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\UserIdentity;

use OPNsense\Base\BaseModel;
use OPNsense\Base\Messages\Message;
use OPNsense\Core\Config;

class UserIdentity extends BaseModel
{
    /**
     * Beside each field's own checks: the port the domain controllers send to may not be one the
     * firewall itself serves (Ports) - checked when it is changed, or the whole model is, so one saved
     * before the web GUI or SSH was moved onto it blocks no other change; the firewall hook leaves that
     * one out. And an alias name is one table, so a group row and a user row - or two of either - may
     * not give the same one. Every row that gives it is said, so the one being saved is told whichever
     * it is.
     */
    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);
        if ($validateFullModel || $this->general->port->isFieldChanged()) {
            $port = trim((string)$this->general->port);
            $system = Config::getInstance()->toArray()['system'] ?? [];
            if (ctype_digit($port) && in_array((int)$port, Ports::served($system), true)) {
                $messages->appendMessage(new Message(
                    gettext('The firewall itself serves this port (SSH, DNS or the web GUI): the domain controllers would no longer reach that service on it. Choose another, such as 514.'),
                    'general.port'
                ));
            }
        }
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
