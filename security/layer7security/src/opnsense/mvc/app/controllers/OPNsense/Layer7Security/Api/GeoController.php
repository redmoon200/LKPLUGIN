<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Layer7Security\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class GeoController extends ApiControllerBase
{
    use \OPNsense\Layer7Security\LicenseGate;

    /** download the country database and rebuild the policy tables */
    public function updateAction()
    {
        if ($this->request->isPost()) {
            $data = json_decode(trim((new Backend())->configdRun('layer7security geo-update')), true);
            return is_array($data) ? $data : ['result' => 'failed'];
        }
        return ['result' => 'failed'];
    }

    public function statusAction()
    {
        $data = json_decode(trim((new Backend())->configdRun('layer7security geo-status')), true);
        return is_array($data) ? $data : ['ready' => false, 'tables' => [], 'labels' => []];
    }
}
