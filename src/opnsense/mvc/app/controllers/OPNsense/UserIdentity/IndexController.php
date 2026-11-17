<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\UserIdentity;

class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->generalForm = $this->getForm('general');
        $this->view->formDialogGroup = $this->getForm('dialogGroup');
        $this->view->formDialogUser = $this->getForm('dialogUser');
        $this->view->pick('OPNsense/UserIdentity/index');
    }
}
