<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Layer7Security;

class DnsController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        return $this->response->redirect('/ui/layer7security/cfs');
    }
}
