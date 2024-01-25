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
 * dml.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/ast/dml.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DML_H__
#define __DML_H__

#include "cm_word.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PLC_NOT_NEED_NEXT_SPACE(word)                                                                         \
    ((word)->type == WORD_TYPE_COMPARE || (word)->type == WORD_TYPE_SPEC_CHAR ||                              \
        ((word)->type == WORD_TYPE_OPERATOR && (word)->id != OPER_TYPE_ROOT && (word)->id != OPER_TYPE_MUL && \
        (word)->id != OPER_TYPE_PRIOR))

#define PLC_IS_DML_WORD(word)                                                                           \
    ((word)->id == KEY_WORD_SELECT || (word)->id == KEY_WORD_INSERT || (word)->id == KEY_WORD_UPDATE || \
        (word)->id == KEY_WORD_DELETE || (word)->id == KEY_WORD_MERGE || (word)->id == KEY_WORD_REPLACE)

#define PLC_IS_RETURNING_WORD(word) \
    ((word)->id == KEY_WORD_RETURN || (word)->id == KEY_WORD_RETURNING || (word)->id == KEY_WORD_INTO)

#define PLC_IS_ALL_INTO_WORD(word) ((word)->id == KEY_WORD_INTO)

bool32 plc_dmlhook_none(word_t *word);
bool32 plc_dmlhook_spec_char(word_t *word);
bool32 plc_dmlhook_qrylist(word_t *word);
bool32 plc_dmlhook_current(word_t *word);
bool32 plc_dmlhook_insert_head(word_t *word);
bool32 plc_dmlhook_replace_head(word_t *word);
bool32 plc_dmlhook_update_head(word_t *word);
bool32 plc_dmlhook_merge_head(word_t *word);
bool32 plc_dmlhook_merge_when(word_t *word);
bool32 plc_dmlhook_end(word_t *word);
bool32 plc_dmlhook_merge_insert(word_t *word);
bool32 plc_dmlhook_return_returning(word_t *word);
bool32 plc_dmlhook_all_into(word_t *word);
bool32 plc_dmlhook_return_into(word_t *word);

#ifdef __cplusplus
}
#endif

#endif