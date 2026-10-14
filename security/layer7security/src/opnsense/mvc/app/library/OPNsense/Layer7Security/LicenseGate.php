<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Layer7Security;

/**
 * Locks a controller while there is no valid license: pages go to the license screen,
 * API calls answer "license required" (HTTP 402). Used by every controller except the
 * license one and the service control, which the license screen itself needs.
 */
trait LicenseGate
{
    public function beforeExecuteRoute($dispatcher)
    {
        $result = parent::beforeExecuteRoute($dispatcher);
        if ($result === false) {
            return false;
        }
        if (!License::locked()) {
            return $result;
        }
        if ($this instanceof \OPNsense\Base\ApiControllerBase) {
            $this->response->setStatusCode(402, 'Payment Required');
            $this->response->setContentType('application/json', 'UTF-8');
            $this->response->setContent(json_encode(['status' => 'locked', 'result' => 'failed',
                'message' => 'A license is required. Open Layer 7 > License.']));
        } else {
            $this->response->redirect('/ui/layer7security/license');
        }
        $this->response->send();
        return false;
    }
}
