<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Layer7Security\FieldTypes;

use OPNsense\Base\FieldTypes\BaseListField;

/** AI services from the catalog shipped in /usr/local/share/layer7security/ai_services.json */
class AiServiceField extends BaseListField
{
    private static array $cache = [];
    protected $internalIsContainer = false;

    protected function actionPostLoadingEvent()
    {
        if (empty(self::$cache)) {
            $list = [];
            $data = json_decode(@file_get_contents('/usr/local/share/layer7security/ai_services.json') ?: '[]', true);
            foreach (is_array($data) ? $data : [] as $svc) {
                if (!empty($svc['id']) && !empty($svc['name'])) {
                    $list[$svc['id']] = $svc['name'];
                }
            }
            asort($list, SORT_NATURAL | SORT_FLAG_CASE);
            self::$cache = $list;
        }
        $this->internalOptionList = self::$cache;
    }
}
