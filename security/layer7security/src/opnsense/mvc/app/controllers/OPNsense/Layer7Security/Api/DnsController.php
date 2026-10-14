<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Layer7Security\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class DnsController extends ApiControllerBase
{
    use \OPNsense\Layer7Security\LicenseGate;

    /** download category lists from the configured feed */
    public function updateAction()
    {
        if ($this->request->isPost()) {
            $data = json_decode(trim((new Backend())->configdRun('layer7security feed-update')), true);
            return is_array($data) ? $data : ['result' => 'failed'];
        }
        return ['result' => 'failed'];
    }

    public function statusAction()
    {
        $data = json_decode(trim((new Backend())->configdRun('layer7security dns-status')), true);
        return is_array($data) ? $data : ['lists' => []];
    }
}
