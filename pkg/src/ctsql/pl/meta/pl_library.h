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
 * pl_library.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/meta/pl_library.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_LIBRARY_H__
#define __PL_LIBRARY_H__

#include "cm_defs.h"
#include "cm_text.h"
#include "knl_interface.h"
#ifdef __cplusplus
extern "C" {
#endif

#define IDX_LIBRARY_001_ID 0

#define IX_COL_SYS_LIBRARY001_OWNER 0
#define IX_COL_SYS_LIBRARY001_NAME 1

typedef struct st_pl_library_def {
    text_t owner;
    text_t name;
    bool32 is_replace;
    uint32 flags;
    text_t path;
    text_t leaf_name;
    text_t agent;
} pl_library_def_t;

typedef struct st_pl_library {
    uint32 uid;
    char name[CT_NAME_BUFFER_SIZE];
    char path[CT_FILE_NAME_BUFFER_SIZE];
    char agent_name[CT_FILE_NAME_BUFFER_SIZE];
    char leaf_name[CT_NAME_BUFFER_SIZE];
    uint32 status;
    int64 chg_scn;
    int64 org_scn;
    union {
        uint32 flags;
        struct {
            uint32 is_dll : 1; /* dll library */
            uint32 unused_flag : 31;
        };
    };
} pl_library_t;

status_t pl_find_library(knl_handle_t se, uint32 uid, text_t *name, pl_library_t *library, bool32 *exists);
status_t pl_create_library(knl_handle_t se, pl_library_def_t *def);
status_t pl_drop_library(knl_handle_t se, knl_drop_def_t *def);

#ifdef __cplusplus
}
#endif

#endif
