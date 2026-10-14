<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Layer7Security;

class UsersController extends \OPNsense\Base\IndexController
{
    use \OPNsense\Layer7Security\LicenseGate;

    public function indexAction()
    {
        return $this->response->redirect('/ui/layer7security/access');
    }
}
