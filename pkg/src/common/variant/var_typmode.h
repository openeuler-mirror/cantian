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
 * var_typmode.h
 *
 *
 * IDENTIFICATION
 * src/common/variant/var_typmode.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __VAR_TYPMODE_H__
#define __VAR_TYPMODE_H__

#include "cm_defs.h"
#include "cm_text.h"

typedef struct st_typmode {
    ct_type_t datatype;
    uint16 size;
    union {
        uint16 mode;
        // for decimal/timestamp
        struct {
            uint8 precision;
            int8 scale;
        };
        // for interval day to seconds
        struct {
            uint8 day_prec;
            uint8 frac_prec;
        };
        // for interval year to month
        struct {
            uint8 year_prec;
            int8 reserved;
        };
        // for string
        struct {
            uint8 is_char : 1;  // defined byte or char attr
            uint8 charset : 7;
            uint8 collate;
        };
    };

    uint8 is_array;     // for array type, e.g. int[], varchar(30)[]
    uint8 reserve[3];   // 4-byte align
} typmode_t;

#define CM_TYPMODE_IS_EQUAL(tm1, tm2) \
    (memcmp((void *)(tm1), (void *)(tm2), sizeof(typmode_t)) == 0)

status_t cm_typmode2text(const typmode_t *typmod, text_t *txt, uint32 max_len);
status_t cm_typmode2str(const typmode_t *typmod, unsigned char is_array, char *buf, uint32 max_len);
void     cm_adjust_typmode(typmode_t *typmod);
status_t cm_combine_typmode(typmode_t tm1, bool32 is_null1, typmode_t tm2, bool32 is_null2, typmode_t *tmr);

#endif