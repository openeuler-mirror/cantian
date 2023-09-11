/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * cm_hba.h
 *
 *
 * IDENTIFICATION
 * src/common/cm_hba.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_HBA_H__
#define __CM_HBA_H__

#include "cm_defs.h"
#include "cm_ip.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ZHBA_FILENAME "zhba.conf"
#define ZHBA_SWAP_FILENAME "zhba_swaping.conf"

#define HBA_MAX_LINE_SIZE SIZE_K(1)

typedef struct st_zhba_context {
    list_t zhba_list;  // st_hba_conf_node
    bool32 is_found;
} zhba_context_t;

typedef struct st_ip_entry {
    char ip[CM_MAX_IP_LEN];
    cidr_t cidr;
    bool8 is_hit;
} hba_ip_entry_t;

typedef struct st_hba_conf_entry {
    char host_name[GS_MAX_NAME_LEN];
    char user_name[GS_MAX_NAME_LEN];
    list_t ip_entry_list;
    int32 left_count; // count without colored ip
} hba_conf_entry_t;
status_t get_format_user(text_t *user);
status_t cm_load_hba(white_context_t *ctx, const char *file_name);
status_t cm_write_hba_file(const char *file_name, const char *buf, uint32 buf_len, bool32 on_create);
status_t cm_check_hba_entry_legality(char *hba_str);

status_t cm_modify_hba_file(const char *origin_file_name, const char *swap_file_name, char *hba_entry_str);

#ifdef __cplusplus
}

#endif

#endif

