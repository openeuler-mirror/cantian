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
 * ct_miner_desc.h
 *
 *
 * IDENTIFICATION
 * src/ctbox/ct_miner_desc.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CT_MINER_DESC_H__
#define __CT_MINER_DESC_H__

#include "ct_miner.h"

#define CIPHER_RESERVE_SIZE  (uint8)(88)
#define TXN_PAGE_PER_LINE    (uint32)(8)
#define SPACE_FILES_PER_LINE (uint32)(80)

void miner_desc_group(log_group_t *group);
void miner_desc_group_xid(log_group_t *group, bool32 has_xid, tx_msg_t *tx_msg, uint8 xid_cnt);
void miner_desc_page(uint32 id, char *buf, uint32 page_size, bool32 is_checksum, bool32 is_force);
void miner_desc_ctrlfile(database_ctrl_t *ctrl);
void miner_desc_backup_info(bak_head_t *bak_head, const char *read_buf, uint32 offset);
void miner_compressed_page(uint32 id, page_head_t *head);

#endif
