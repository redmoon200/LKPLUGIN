<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Layer7Security;

class CfsController extends \OPNsense\Base\IndexController
{
    use \OPNsense\Layer7Security\LicenseGate;

    public function indexAction()
    {
        $this->view->pick('OPNsense/Layer7Security/cfs');
        $this->view->cfsForm = $this->getForm('cfs');
        $this->view->formDialogCfsRule = $this->getForm('dialogCfsRule');
    }
}
