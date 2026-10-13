<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Layer7Security;

class MacbindingController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->pick('OPNsense/Layer7Security/macbinding');
        $this->view->macForm = $this->getForm('mac');
        $this->view->formDialogBinding = $this->getForm('dialogBinding');
    }
}
