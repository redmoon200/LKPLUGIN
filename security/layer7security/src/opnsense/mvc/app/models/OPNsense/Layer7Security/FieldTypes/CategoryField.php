<?php

/*
 * Copyright (c) 2026, redmoon200
 * All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 */

namespace OPNsense\Layer7Security\FieldTypes;

use OPNsense\Base\FieldTypes\BaseListField;

/**
 * nDPI application categories, cached in categories.json by
 * "configctl layer7security catalog".
 */
class CategoryField extends BaseListField
{
    private static array $cache = [];
    protected $internalIsContainer = false;

    protected function actionPostLoadingEvent()
    {
        if (empty(self::$cache)) {
            $list = [];
            $data = json_decode(@file_get_contents('/usr/local/etc/layer7security/categories.json') ?: '[]', true);
            if (is_array($data)) {
                foreach ($data as $cat) {
                    if (is_string($cat) && $cat !== '' && $cat !== 'Unspecified') {
                        $list[$cat] = $cat;
                    }
                }
            }
            ksort($list, SORT_NATURAL | SORT_FLAG_CASE);
            self::$cache = $list;
        }
        $this->internalOptionList = self::$cache;
    }
}
