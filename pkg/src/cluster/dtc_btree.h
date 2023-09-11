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
 * dtc_btree.h
 *
 *
 * IDENTIFICATION
 * src/cluster/dtc_btree.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DTC_BTREE_H__
#define __DTC_BTREE_H__
#include "pcr_btree.h"
#include "mes_func.h"

typedef struct st_msg_btree_broadcast {
    mes_message_head_t head;
    uint32 table_id;
    uint16 uid;
    uint8 index_id;
    bool8 is_shadow;
    knl_part_locate_t part_loc;
} msg_btree_broadcast_t;

status_t dtc_btree_construct_cr_page(knl_session_t *session, cr_cursor_t *cursor, btree_page_t *page);
void dtc_btree_broadcast_root_page(knl_session_t *session, btree_t *btree, btree_page_t *page,
                                   knl_part_locate_t part_loc);
EXTER_ATTACK void dtc_btree_process_root_page(void *sess, mes_message_t *msg);
void dtc_btree_send_ack(knl_session_t *session, mes_message_t *msg);

#endif
