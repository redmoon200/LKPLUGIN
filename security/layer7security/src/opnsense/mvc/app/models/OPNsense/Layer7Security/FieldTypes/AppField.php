<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Layer7Security\FieldTypes;

use OPNsense\Base\FieldTypes\BaseListField;

/**
 * Applications known to the nDPI build installed on this firewall. The list
 * is cached in apps.json by "configctl layer7security catalog".
 */
class AppField extends BaseListField
{
    private static array $cache = [];
    protected $internalIsContainer = false;

    protected function actionPostLoadingEvent()
    {
        if (empty(self::$cache)) {
            $list = [];
            $data = json_decode(@file_get_contents('/usr/local/etc/layer7security/apps.json') ?: '[]', true);
            if (is_array($data)) {
                foreach ($data as $app) {
                    if (!empty($app['name'])) {
                        $list[$app['name']] = $app['name'] . (empty($app['category']) ? '' : ' (' . $app['category'] . ')');
                    }
                }
            }
            ksort($list, SORT_NATURAL | SORT_FLAG_CASE);
            self::$cache = $list;
        }
        $this->internalOptionList = self::$cache;
    }
}
