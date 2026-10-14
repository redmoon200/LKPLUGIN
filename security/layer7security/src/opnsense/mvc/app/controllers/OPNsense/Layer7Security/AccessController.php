<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Layer7Security;

class AccessController extends \OPNsense\Base\IndexController
{
    use \OPNsense\Layer7Security\LicenseGate;

    public function indexAction()
    {
        $this->view->pick('OPNsense/Layer7Security/access');
        $this->view->authForm = $this->getForm('auth');
        $this->view->formDialogUser = $this->getForm('dialogUser');
    }
}
