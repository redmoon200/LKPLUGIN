<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Layer7Security;

class AiController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->pick('OPNsense/Layer7Security/ai');
        $this->view->aiForm = $this->getForm('ai');
        $this->view->formDialogAi = $this->getForm('dialogAi');
    }
}
