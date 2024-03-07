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
 * cms_param.h
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_param.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef CMS_PARAM_H
#define CMS_PARAM_H

#include <unistd.h>
#include <string.h>
#include "cm_defs.h"
#include "cms_defs.h"
#include "cm_config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_cms_params {
    int64           max_log_file_size;
    int32           log_level;
    uint32          log_backup_file_count;
    uint32          worker_thread_count;
    uint32          uds_worker_thread_count;
    int64           wait_detect_file_num;
    uint32          detect_disk_timeout;
    uint32          cms_node_fault_thr;
    uint32          cms_mes_thread_num;
    uint32          cms_mes_max_session_num;
    uint32          cms_mes_msg_pool_count;
    uint32          cms_mes_msg_queue_count;
    uint32          cms_mes_msg_buff_count;
    uint32          cms_mes_msg_channel_num;
    char            cms_home[CMS_PATH_BUFFER_SIZE];
    char            gcc_home[CMS_FILE_NAME_BUFFER_SIZE];
    char            gcc_dir[CMS_FILE_NAME_BUFFER_SIZE];
    char            cms_gcc_bak[CMS_FILE_NAME_BUFFER_SIZE];
    char            wait_detect_file[CMS_MAX_DISK_DETECT_FILE][CMS_MAX_DETECT_FILE_NAME];
    char            stop_rerun_script[CMS_FILE_NAME_BUFFER_SIZE];
    char            exit_num_file[CMS_FILE_NAME_BUFFER_SIZE];
    char            fs_name[CMS_FILE_NAME_BUFFER_SIZE];
    char            cluster_name[CMS_FILE_NAME_BUFFER_SIZE];
    char            detect_file[CMS_FILE_NAME_BUFFER_SIZE];
    cms_split_brain_type_t split_brain;
    cms_dev_type_t  gcc_type;
    uint32          cms_mes_pipe_type;
    uint16          node_id;
    bool8           cms_mes_crc_check_switch;
    int8            unused;
}cms_param_t;

status_t cms_load_param(int64* time);
status_t cms_update_param(const char* param_name, const char* value);
status_t cms_get_gcc_dir(char *gcc_dir, uint32 gcc_dir_len, char *gcc_file, uint32 gcc_file_len);
status_t cms_get_detect_file(char *detect_file_all, uint32 detect_file_all_len, char *gcc_dir, uint32 gcc_dir_len);
status_t cms_init_detect_file(char *detect_file_all);
status_t cms_get_value_is_valid(char* value, uint32 *val_uint32);
void cms_get_mes_config_value(config_t *cfg);
status_t cms_get_dbstore_config_value(config_t *cfg);
status_t cms_load_keyfiles(void);

extern const cms_param_t* g_cms_param;
extern cms_param_t  g_param;

#ifdef __cplusplus
}
#endif

#endif
