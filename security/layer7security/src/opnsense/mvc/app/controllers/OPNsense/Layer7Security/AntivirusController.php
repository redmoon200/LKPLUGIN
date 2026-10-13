<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Layer7Security;

class AntivirusController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->pick('OPNsense/Layer7Security/antivirus');
        $this->view->antivirusForm = $this->getForm('antivirus');
    }
}
