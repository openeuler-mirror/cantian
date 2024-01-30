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
 * pl_logic_persist.h
 *
 *
 * IDENTIFICATION
 * src/upgrade_check/pl_logic_persist.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_LOGIC_PERSIST_H__
#define __PL_LOGIC_PERSIST_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_logic_log_plm_ddl {
    char user[CT_NAME_BUFFER_SIZE];
    char pack[CT_NAME_BUFFER_SIZE];
    char name[CT_NAME_BUFFER_SIZE];
    char trig_tab_user[CT_NAME_BUFFER_SIZE];
    char trig_tab[CT_NAME_BUFFER_SIZE];
    char syn_user[CT_NAME_BUFFER_SIZE];
    char syn_name[CT_NAME_BUFFER_SIZE];
    uint32 uid;
    uint32 user_len;
    uint32 pack_len;
    uint32 name_len;
    uint32 trig_tab_user_len;
    uint32 trig_tab_len;
    uint32 syn_user_len;
    uint32 syn_name_len;
    bool8 pack_sensitive;
    bool8 name_sensitive;
    uint8 pl_class;
    uint8 unused;
    uint32 type;
    bool32 trig_enable;
    bool32 need_deregister_trig;
    knl_scn_t chg_scn; /* last scn of this object */
    uint64 oid;        /* object id */
    union {
        uint32 flags;
        struct {
            uint32 is_aggr : 1;
            uint32 pipelined : 1;
            uint32 is_synonym : 1;
            uint32 lang_type : 2; /* is plsql or clang */
            uint32 unused_flag : 27;
        };
    };
} logic_log_plm_ddl_t;

#ifdef __cplusplus
}
#endif

#endif