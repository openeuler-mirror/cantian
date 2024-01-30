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
 * knl_comment.h
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/knl_comment.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_COMMENT_H__
#define __KNL_COMMENT_H__

#include "knl_session.h"
#include "knl_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

#define COMMENT_USER_COLUMN_ID   0
#define COMMENT_TABLE_COLUMN_ID  1
#define COMMENT_COLUMN_COLUMN_ID 2
#define COMMENT_TEXT_COLUMN_ID   3

status_t db_comment_on(knl_session_t *session, knl_comment_def_t *def);
status_t db_delete_comment(knl_session_t *session, knl_comment_def_t *def);

#ifdef __cplusplus
}
#endif

#endif
