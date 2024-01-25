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
 * dml.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/ast/dml.c
 *
 * -------------------------------------------------------------------------
 */
#include "dml.h"

bool32 plc_dmlhook_none(word_t *word)
{
    return CT_FALSE;
}

bool32 plc_dmlhook_merge_head(word_t *word)
{
    return (word->id == KEY_WORD_USING);
}

bool32 plc_dmlhook_spec_char(word_t *word)
{
    return word->text.len == 1 && word->text.str[0] == ',';
}

bool32 plc_dmlhook_qrylist(word_t *word)
{
    return (word->id == KEY_WORD_INTO || word->id == KEY_WORD_BULK || word->id == KEY_WORD_FROM);
}

bool32 plc_dmlhook_current(word_t *word)
{
    return (word->id == KEY_WORD_CURRENT || PLC_IS_RETURNING_WORD(word));
}

bool32 plc_dmlhook_insert_head(word_t *word)
{
    return (word->id == KEY_WORD_VALUES || word->id == KEY_WORD_SELECT);
}

bool32 plc_dmlhook_replace_head(word_t *word)
{
    return (word->id == KEY_WORD_VALUES || word->id == KEY_WORD_SELECT || word->id == KEY_WORD_SET);
}

bool32 plc_dmlhook_update_head(word_t *word)
{
    return (word->id == KEY_WORD_SET);
}

bool32 plc_dmlhook_merge_when(word_t *word)
{
    return (word->id == KEY_WORD_WHEN);
}

bool32 plc_dmlhook_end(word_t *word)
{
    return (word->id == KEY_WORD_END);
}

bool32 plc_dmlhook_merge_insert(word_t *word)
{
    return (word->id == KEY_WORD_VALUES);
}

bool32 plc_dmlhook_return_returning(word_t *word)
{
    return PLC_IS_RETURNING_WORD(word);
}

bool32 plc_dmlhook_all_into(word_t *word)
{
    return PLC_IS_ALL_INTO_WORD(word);
}

bool32 plc_dmlhook_return_into(word_t *word)
{
    return (word->id == KEY_WORD_INTO || word->id == KEY_WORD_BULK);
}
