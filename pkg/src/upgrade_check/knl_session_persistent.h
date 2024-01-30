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
 * knl_session_persistent.h
 *
 *
 * IDENTIFICATION
 * src/upgrade_check/knl_session_persistent.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_SESSION_PERSISTENT_H__
#define __KNL_SESSION_PERSISTENT_H__

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(4)
typedef union st_xmap {
    uint32 value;
    struct {
        uint16 seg_id;
        uint16 slot;
    };
} xmap_t;
#pragma pack()

typedef union un_xid {
    uint64 value;
    struct {
        xmap_t xmap;
        uint32 xnum;
    };
} xid_t;

#ifdef __cplusplus
}
#endif

#endif