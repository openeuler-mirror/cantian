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
 * dbs_adp.h
 *
 *
 * IDENTIFICATION
 * src/dbstool/dbs_adp.h
 *
 * -------------------------------------------------------------------------
 */

#include "cm_defs.h"
#include "cm_log.h"

#ifndef MODULE_ID
#define MODULE_ID DBSTORE
#endif

status_t dbstool_init();
int32 dbs_arch_import(int32 argc, char *argv[]);
int32 dbs_arch_export(int32 argc, char *argv[]);
int32 dbs_arch_clean(int32 argc, char *argv[]);
int32 dbs_arch_query(int32 argc, char *argv[]);
int32 dbs_ulog_clean(int32 argc, char *argv[]);
int32 dbs_pagepool_clean(int32 argc, char *argv[]);
int32 dbs_create_path_or_file(int32 argc, char *argv[]);
int32 dbs_delete_path_or_file(int32 argc, char *argv[]);
int32 dbs_query_file(int32 argc, char *argv[]);
int32 dbs_ulog_export(int32 argc, char *argv[]);
int32 dbs_page_export(int32 argc, char *argv[]);