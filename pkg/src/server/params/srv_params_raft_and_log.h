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
 * srv_params_raft_and_log.h
 *
 *
 * IDENTIFICATION
 * src/server/params/srv_params_raft_and_log.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SRV_PARAMS_RAFT_AND_LOG_H__
#define __SRV_PARAMS_RAFT_AND_LOG_H__

#include "cm_config.h"
#include "cm_text.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_method_id {
    LONGSQL_ON,
    LONGSQL_OFF,
    LOG_LEVEL_FATAL,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_RUN,
    LOG_LEVEL_USER_DEFINE
} method_id_t;

typedef struct st_log_mode_map {
    text_t name;
    text_t value;
    method_id_t method;
} log_mode_map_t;

status_t sql_verify_als_black_box_depth(void *se, void *lex, void *def);
status_t sql_verify_als_file_dir(void *se, void *lex, void *def);
status_t sql_verify_als_log_backup_file_count(void *se, void *lex, void *def);
status_t sql_verify_log_file_size(void *se, void *lex, void *def);
status_t sql_verify_pbl_file_size(void *se, void *lex, void *def);
status_t sql_verify_als_log_level(void *se, void *lex, void *def);
status_t sql_verify_als_log_file(void *se, void *lex, void *def);
status_t sql_verify_als_log_path(void *se, void *lex, void *def);
status_t sql_verify_als_longsql_timeout(void *se, void *lex, void *def);
status_t sql_verify_als_size(void *se, void *lex, void *def);
status_t sql_verify_als_arch_size(void *se, void *lex, void *def);
status_t sql_verify_als_arch_file_size(void *se, void *lex, void *def);
status_t sql_verify_als_time(void *se, void *lex, void *def);
status_t sql_verify_als_log_archive_dest_n(void *se, void *lex, void *def);
status_t sql_verify_als_log_archive_dest_state_n(void *se, void *lex, void *def);

status_t sql_notify_als_log_backup_file_count(void *se, void *item, char *value);
status_t sql_notify_als_log_max_file_size(void *se, void *item, char *value);
status_t sql_notify_als_log_level(void *se, void *item, char *value);
status_t sql_notify_als_pbl_max_file_size(void *se, void *item, char *value);
status_t sql_notify_als_log_file_permissions(void *se, void *item, char *value);
status_t sql_notify_als_log_path_permissions(void *se, void *item, char *value);
status_t sql_notify_enable_longsql_print(void *se, void *item, char *value);
status_t sql_notify_als_longsql_timeout(void *se, void *item, char *value);
status_t sql_notify_als_arch_size(void *se, void *item, char *value);
status_t sql_notify_als_need_arch_size(void *se, void *item, char *value);
status_t sql_notify_als_need_arch_file_size(void *se, void *item, char *value);
status_t sql_notify_als_need_arch_time(void *se, void *item, char *value);
status_t sql_notify_als_ignore_backup(void *se, void *item, char *value);
status_t sql_notify_als_ignore_standby(void *se, void *item, char *value);
status_t sql_notify_als_archive_dest_n(void *se, void *item, char *value);
status_t sql_notify_als_archive_dest_state_n(void *se, void *item, char *value);
status_t sql_notify_als_archive_format(void *se, void *item, char *value);
status_t sql_notify_als_archive_format_with_lsn(void *se, void *item, char *value);
status_t sql_notify_als_entry_cache_memory_size(void *se, void *item, char *value);
status_t sql_notify_als_max_size_per_msg(void *se, void *item, char *value);

#ifdef __cplusplus
}
#endif

#endif
