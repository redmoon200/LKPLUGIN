<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Layer7Security\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\Layer7Security\Layer7Security';
    protected static $internalServiceEnabled = 'general.enabled';
    protected static $internalServiceName = 'layer7security';

    /**
     * Apply: regenerate engine, policy, pf and DNS-filter configuration and
     * (re)start or stop the engine. The work happens in apply.php so it can
     * resolve users and interfaces.
     */
    public function reconfigureAction()
    {
        if ($this->request->isPost()) {
            $result = trim((new Backend())->configdRun('layer7security apply'));
            if ($result !== 'OK') {
                return ['status' => 'failed', 'message' => $result];
            }
            return ['status' => 'ok'];
        }
        return ['status' => 'failed'];
    }
}
