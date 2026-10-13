<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Layer7Security\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Backend;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'layer7security';
    protected static $internalModelClass = '\OPNsense\Layer7Security\Layer7Security';

    public function searchPolicyAction()
    {
        return $this->searchBase(
            'policies.policy',
            ['enabled', 'sequence', 'name', 'action', 'applications', 'categories', 'interfaces',
             'sources', 'users', 'days', 'startTime', 'endTime', 'dnsCategories', 'description'],
            'sequence'
        );
    }

    public function getPolicyAction($uuid = null)
    {
        return $this->getBase('policy', 'policies.policy', $uuid);
    }

    public function addPolicyAction()
    {
        return $this->addBase('policy', 'policies.policy');
    }

    public function setPolicyAction($uuid)
    {
        return $this->setBase('policy', 'policies.policy', $uuid);
    }

    public function delPolicyAction($uuid)
    {
        return $this->delBase('policies.policy', $uuid);
    }

    public function togglePolicyAction($uuid, $enabled = null)
    {
        return $this->toggleBase('policies.policy', $uuid, $enabled);
    }

    public function searchUserAction()
    {
        return $this->searchBase('users.user', ['name', 'addresses', 'description'], 'name');
    }

    public function getUserAction($uuid = null)
    {
        return $this->getBase('user', 'users.user', $uuid);
    }

    public function addUserAction()
    {
        return $this->addBase('user', 'users.user');
    }

    public function setUserAction($uuid)
    {
        return $this->setBase('user', 'users.user', $uuid);
    }

    public function delUserAction($uuid)
    {
        return $this->delBase('users.user', $uuid);
    }

    /** rebuild the application/category catalog from the installed nDPI */
    public function catalogAction()
    {
        if ($this->request->isPost()) {
            return ['response' => trim((new Backend())->configdRun('layer7security catalog'))];
        }
        return ['response' => 'failed'];
    }
}
