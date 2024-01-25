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
 * ctbackup_factory.c
 *
 *
 * IDENTIFICATION
 * src/utils/ctbackup/ctbackup_factory.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctbackup_module.h"
#include "ctbackup_factory.h"
#include "ctbackup_backup.h"
#include "ctbackup_prepare.h"
#include "ctbackup_copyback.h"
#include "ctbackup_archivelog.h"
#include "ctbackup_reconciel_mysql.h"
#include "ctbackup_query.h"
#include "ctbackup_purge_logs.h"

const char* g_ctbak_cmd_name[] = {
    [CTBAK_INVALID] = "invalid",
    [CTBAK_VERSION] = "version",
    [CTBAK_HELP] = "help",
    [CTBAK_BACKUP] = "backup",
    [CTBAK_PREPARE] = "prepare",
    [CTBAK_COPYBACK] = "copyback",
    [CTBAK_ARCHIVE_LOG] = "archivelog",
    [CTBAK_RECONCIEL_MYSQL] = "reconciel_mysql",
    [CTBAK_QUERY_INCREMENTAL_MODE] = "query_incremental_mode",
    [CTBAK_PURGE_LOGS] = "purge_logs"
};

ctbak_cmd_generate_interface g_ctbak_cmd_generate_set[] = {
    [CTBAK_BACKUP] = (ctbak_cmd_generate_interface) ctbak_generate_backup_cmd,
    [CTBAK_PREPARE] = (ctbak_cmd_generate_interface) ctbak_generate_prepare_cmd,
    [CTBAK_COPYBACK] = (ctbak_cmd_generate_interface) ctbak_generate_copyback_cmd,
    [CTBAK_ARCHIVE_LOG] = (ctbak_cmd_generate_interface) ctbak_generate_archivelog_cmd,
    [CTBAK_RECONCIEL_MYSQL] = (ctbak_cmd_generate_interface) ctbak_generate_reconciel_mysql_cmd,
    [CTBAK_QUERY_INCREMENTAL_MODE] = (ctbak_cmd_generate_interface) ctbak_generate_query_incremental_mode_cmd,
    [CTBAK_PURGE_LOGS] = (ctbak_cmd_generate_interface) ctbak_generate_purge_logs_cmd
};

ctbak_cmd_t* ctbak_factory_generate_cmd(ctbak_topic_t ctbak_topic)
{
    ctbak_cmd_generate_interface cmd_generate = g_ctbak_cmd_generate_set[ctbak_topic];
    ctbak_cmd_t* cmd = cmd_generate();
    if (cmd == NULL) {
        printf("[ctbackup]failed to generate cmd!\n");
        return (ctbak_cmd_t*)NULL;
    }
    cmd->ctbak_topic = ctbak_topic;
    cmd->cmd_name = g_ctbak_cmd_name[ctbak_topic];
    return cmd;
}
