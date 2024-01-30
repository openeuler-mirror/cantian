/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
 *
 * Cantian is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * cm_util.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_util.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_UTIL_H__
#define __CM_UTIL_H__
#include "cm_defs.h"
#include "cm_text.h"
#include "cm_charset.h"
#ifdef __cplusplus
extern "C" {
#endif

#define PATTERN_LEN 100
#define DESC_LEN    100

typedef struct st_keyword_map_item {
    char keyword_pattern[PATTERN_LEN];
    char type_desc[DESC_LEN];
} keyword_map_item_t;

extern keyword_map_item_t g_key_pattern[];
void cm_text_reg_match(text_t *text, const char *pattern, int32 *pos, charset_type_t charset);
void cm_text_try_map_key2type(const text_t *text, int32 *matched_pat_id, bool32 *matched);
void cm_text_star_to_one(text_t *text);
#ifdef __cplusplus
}
#endif

#endif
