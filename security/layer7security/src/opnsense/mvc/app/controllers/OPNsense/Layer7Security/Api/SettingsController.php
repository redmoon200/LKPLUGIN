<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Layer7Security\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;

class SettingsController extends ApiMutableModelControllerBase
{
    use \OPNsense\Layer7Security\LicenseGate;

    protected static $internalModelName = 'layer7security';
    protected static $internalModelClass = '\OPNsense\Layer7Security\Layer7Security';

    /** like the stock set action, but the audit section is only writable through the audit API */
    public function setAction()
    {
        $result = ['result' => 'failed'];
        if ($this->request->isPost()) {
            Config::getInstance()->lock();
            $mdl = $this->getModel();
            $post = $this->request->getPost(static::$internalModelName);
            if (is_array($post)) {
                unset($post['audit']);
            }
            $mdl->setNodes($post);
            $result = $this->validate();
            if (empty($result['result'])) {
                return $this->save(false, true);
            }
        }
        return $result;
    }

    public function searchPolicyAction()
    {
        $module = (string)$this->request->get('module', 'string', '');
        return $this->searchBase(
            'policies.policy',
            ['enabled', 'sequence', 'name', 'action', 'applications', 'categories', 'interfaces',
             'sources', 'users', 'days', 'startTime', 'endTime', 'dnsCategories', 'dnsDomains', 'module', 'description'],
            'sequence',
            function ($row) use ($module) {
                return $module === '' || (string)$row->module === $module;
            }
        );
    }

    /** a content-filter rule: the same record as a policy, marked for the CFS page */
    public function addCfsAction()
    {
        return $this->addBase('policy', 'policies.policy', ['module' => 'cfs']);
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

    public function searchAiAction()
    {
        return $this->searchBase('ai.service', ['enabled', 'service', 'action', 'inspect', 'sources', 'users',
            'days', 'startTime', 'endTime', 'description'], 'service');
    }

    public function getAiAction($uuid = null)
    {
        return $this->getBase('aiservice', 'ai.service', $uuid);
    }

    public function addAiAction()
    {
        return $this->addBase('aiservice', 'ai.service');
    }

    public function setAiAction($uuid)
    {
        return $this->setBase('aiservice', 'ai.service', $uuid);
    }

    public function delAiAction($uuid)
    {
        return $this->delBase('ai.service', $uuid);
    }

    public function toggleAiAction($uuid, $enabled = null)
    {
        return $this->toggleBase('ai.service', $uuid, $enabled);
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
