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
 * ct_miner.h
 *
 *
 * IDENTIFICATION
 * src/ctbox/ct_miner.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CTMINER_H__
#define __CTMINER_H__

#include "cm_defs.h"
#include "knl_log.h"
#include "knl_database.h"
#include "bak_common.h"
#include "knl_datafile.h"

typedef struct st_log_desc {
    const char *name;
    log_desc_proc desc_proc;
} log_desc_t;

typedef struct st_miner_tx_msg {
    xid_t xid;
    uint16 rmid;
} tx_msg_t;

extern int32 g_gm_optopt;
extern int32 g_gm_optind;
extern char *g_gm_optarg;
extern log_desc_t *g_log_desc;

#define MINER_DEF_PAGE_SIZE 8192
#define FUNC_DEF_PAGE_SIZE 8192
#define PAGE_SWITCH_SIZE    SIZE_M(64)

int32 miner_getopt(int nargc, char *nargv[], const char *ostr);
status_t miner_execute(int argc, char *argv[]);
status_t miner_read_page(int32 handle, char *buf, int64 offset, uint32 page_size);
status_t miner_verify_datafile_version(char *file_name, uint32 size);
void miner_calc_ctrlfile_checksum(database_ctrl_t *ctrl);
status_t miner_verify_ctrlfile(database_ctrl_t *ctrl, bool32 is_checksum);
void miner_init_ctrlfile(database_ctrl_t *ctrl);

#endif
