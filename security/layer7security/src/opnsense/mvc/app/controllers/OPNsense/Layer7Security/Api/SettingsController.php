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

    public function searchBindingAction()
    {
        return $this->searchBase('bindings.binding', ['enabled', 'name', 'mac', 'ip', 'interface', 'description'], 'name');
    }

    public function getBindingAction($uuid = null)
    {
        return $this->getBase('binding', 'bindings.binding', $uuid);
    }

    public function addBindingAction()
    {
        return $this->addBase('binding', 'bindings.binding');
    }

    public function setBindingAction($uuid)
    {
        return $this->setBase('binding', 'bindings.binding', $uuid);
    }

    public function delBindingAction($uuid)
    {
        return $this->delBase('bindings.binding', $uuid);
    }

    public function toggleBindingAction($uuid, $enabled = null)
    {
        return $this->toggleBase('bindings.binding', $uuid, $enabled);
    }

    public function searchGeoAction()
    {
        return $this->searchBase(
            'geo.policy',
            ['enabled', 'name', 'action', 'direction', 'interfaces', 'countries', 'exceptions', 'log', 'description'],
            'name'
        );
    }

    public function getGeoAction($uuid = null)
    {
        return $this->getBase('geopolicy', 'geo.policy', $uuid);
    }

    public function addGeoAction()
    {
        return $this->addBase('geopolicy', 'geo.policy');
    }

    public function setGeoAction($uuid)
    {
        return $this->setBase('geopolicy', 'geo.policy', $uuid);
    }

    public function delGeoAction($uuid)
    {
        return $this->delBase('geo.policy', $uuid);
    }

    public function toggleGeoAction($uuid, $enabled = null)
    {
        return $this->toggleBase('geo.policy', $uuid, $enabled);
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
