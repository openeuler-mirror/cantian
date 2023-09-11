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
 * tse_debug.c
 *
 *
 * IDENTIFICATION
 * src/tse/tse_debug.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_instance.h"
#include "knl_interface.h"
#define DIFF_INT(var, v1, v2)                                           \
    do {                                                                \
        if ((v1) != (v2)) {                                             \
            GS_LOG_DEBUG_INF("PRINT_DIFF %s,%d != %d", var, v1, v2);    \
        }                                                               \
    } while (0)
#define DIFF_UINT(var, v1, v2)                                          \
    do {                                                                \
        if ((v1) != (v2)) {                                             \
            GS_LOG_DEBUG_INF("PRINT_DIFF %s:%u != %u", var, v1, v2);    \
        }                                                               \
    } while (0)
#define DIFF_INT64(var, v1, v2)                                          \
    do {                                                                 \
        if ((v1) != (v2)) {                                              \
            GS_LOG_DEBUG_INF("PRINT_DIFF %s:%lld != %lld", var, v1, v2); \
        }                                                                \
    } while (0)
#define DIFF_UINT64(var, v1, v2)                                         \
    do {                                                                 \
        if ((v1) != (v2)) {                                              \
            GS_LOG_DEBUG_INF("PRINT_DIFF %s:%llu != %llu", var, v1, v2); \
        }                                                                \
    } while (0)
#define DIFF_STR(var, v1, v2)                                           \
    do {                                                                \
        if (strcmp(v1, v2) != 0) {                                      \
            GS_LOG_DEBUG_INF("PRINT_DIFF %s:%s != %s", var, v1, v2);    \
        }                                                               \
    } while (0)

void diff_knl_column_def_t(knl_column_def_t *test_column, knl_column_def_t *column)
{
    if (test_column == NULL) {
        GS_LOG_DEBUG_INF("test_column NULL");
        return;
    }
    if (column == NULL) {
        GS_LOG_DEBUG_INF("column NULL");
        return;
    }
    GS_LOG_DEBUG_INF("diff_knl_column_def_t column_name:%s begin", T2S_EX(&column->name));
    DIFF_STR("column_name", T2S(&test_column->name), T2S_EX(&column->name));
    DIFF_INT("datatype", test_column->datatype, column->datatype);
    DIFF_UINT("size", test_column->size, column->size);
    DIFF_UINT("precision", test_column->precision, column->precision);
    DIFF_UINT("scale", test_column->scale, column->scale);
    DIFF_UINT("is_option_set", test_column->is_option_set, column->is_option_set);
    DIFF_UINT("col_id", test_column->col_id, column->col_id);

    DIFF_STR("inl_pri_cons_name", T2S(&test_column->inl_pri_cons_name), T2S_EX(&column->inl_pri_cons_name));
    DIFF_STR("inl_chk_cons_name", T2S(&test_column->inl_chk_cons_name), T2S_EX(&column->inl_chk_cons_name));
    DIFF_STR("inl_uq_cons_name", T2S(&test_column->inl_uq_cons_name), T2S_EX(&column->inl_uq_cons_name));
    DIFF_STR("inl_ref_cons_name", T2S(&test_column->inl_ref_cons_name), T2S_EX(&column->inl_ref_cons_name));
    DIFF_STR("ref_user", T2S(&test_column->ref_user), T2S_EX(&column->ref_user));
    DIFF_STR("ref_table", T2S(&test_column->ref_table), T2S_EX(&column->ref_table));

    DIFF_INT("refactor", test_column->refactor, column->refactor);
    DIFF_STR("default_text", T2S(&test_column->default_text), T2S_EX(&column->default_text));
    DIFF_STR("check_text", T2S(&test_column->check_text), T2S_EX(&column->check_text));
    DIFF_STR("comment", T2S(&test_column->comment), T2S_EX(&column->comment));
    GS_LOG_DEBUG_INF("diff_knl_column_def_t column_name:%s end", T2S_EX(&column->name));
}
void diff_knl_table_def(status_t test_status, knl_table_def_t *test_def, status_t status, knl_table_def_t *def)
{
    GS_LOG_DEBUG_INF("----------------diff_knl_table_def  begin----------------");
    DIFF_INT("ret_status", test_status, status);
    DIFF_STR("schema", T2S(&test_def->schema), T2S_EX(&def->schema));
    DIFF_STR("table_name", T2S(&test_def->name), T2S_EX(&def->name));
    DIFF_STR("space", T2S(&test_def->space), T2S_EX(&def->space));
    DIFF_INT("column_cnt", test_def->columns.count, def->columns.count);
    for (uint32_t i = 0; i < def->columns.count; i++) {
        knl_column_def_t *test_column = (knl_column_def_t *)cm_galist_get(&test_def->columns, i);
        knl_column_def_t *column = (knl_column_def_t *)cm_galist_get(&def->columns, i);
        diff_knl_column_def_t(test_column, column);
    }

    DIFF_UINT("initrans", test_def->initrans, def->initrans);
    DIFF_UINT("maxtrans", test_def->maxtrans, def->maxtrans);
    DIFF_UINT("pctfree", test_def->pctfree, def->pctfree);
    DIFF_UINT("parted", test_def->parted, def->parted);
    DIFF_UINT("sysid", test_def->sysid, def->sysid);
    DIFF_UINT("type", test_def->type, def->type);
    DIFF_UINT("appendonly", test_def->appendonly, def->appendonly);

    DIFF_UINT("pk_inline", test_def->pk_inline, def->pk_inline);
    DIFF_UINT("uq_inline", test_def->uq_inline, def->uq_inline);
    DIFF_UINT("rf_inline", test_def->rf_inline, def->rf_inline);
    DIFF_UINT("chk_inline", test_def->chk_inline, def->chk_inline);

    DIFF_UINT("options", test_def->options, def->options);
    DIFF_INT64("serial_start", test_def->serial_start, def->serial_start);
    DIFF_UINT("collate", test_def->collate, def->collate);
    DIFF_UINT("charset", test_def->charset, def->charset);
    DIFF_UINT("compress_type", test_def->compress_type, def->compress_type);
    GS_LOG_DEBUG_INF("----------------diff_knl_table_def  end------------------");
}
void print_knl_column_def_t(knl_column_def_t *column)
{
    if (column == NULL) {
        GS_LOG_DEBUG_INF("NULL COLUMN");
        return;
    }
    GS_LOG_DEBUG_INF("name:%s", T2S(&column->name));
    GS_LOG_DEBUG_INF("datatype:%d", column->datatype);
    GS_LOG_DEBUG_INF("size:%u", column->size);
    GS_LOG_DEBUG_INF("precision:%u", column->precision);
    GS_LOG_DEBUG_INF("scale:%u", column->scale);
    GS_LOG_DEBUG_INF("is_option_set:%x", column->is_option_set);
    GS_LOG_DEBUG_INF("col_id:%u", column->col_id);
    GS_LOG_DEBUG_INF("inl_pri_cons_name:%s", T2S(&column->inl_pri_cons_name));
    GS_LOG_DEBUG_INF("inl_chk_cons_name:%s", T2S(&column->inl_chk_cons_name));
    GS_LOG_DEBUG_INF("inl_uq_cons_name:%s", T2S(&column->inl_uq_cons_name));
    GS_LOG_DEBUG_INF("inl_ref_cons_name:%s", T2S(&column->inl_ref_cons_name));
    GS_LOG_DEBUG_INF("ref_user:%s", T2S(&column->ref_user));
    GS_LOG_DEBUG_INF("ref_table:%s", T2S(&column->ref_table));

    GS_LOG_DEBUG_INF("refactor:%d", column->refactor);
    GS_LOG_DEBUG_INF("default_text:%s", T2S(&column->default_text));
    GS_LOG_DEBUG_INF("check_text:%s", T2S(&column->check_text));
    GS_LOG_DEBUG_INF("comment:%s", T2S(&column->comment));
}

void print_knl_altable_def_t(knl_altable_def_t *def)
{
    GS_LOG_DEBUG_INF("----------------print_knl_altable_def_t  begin----------------");

    GS_LOG_DEBUG_INF("action:%u", def->action);
    GS_LOG_DEBUG_INF("options:%u", def->options);
    GS_LOG_DEBUG_INF("user:%s", T2S(&def->user));
    GS_LOG_DEBUG_INF("name:%s", T2S(&def->name));

    GS_LOG_DEBUG_INF("column_cnt:%d", def->column_defs.count);
    for (uint32_t i = 0; i < def->column_defs.count; i++) {
        knl_alt_column_prop_t *column_def = (knl_alt_column_prop_t *)cm_galist_get(&def->column_defs, i);
        knl_column_def_t *column = &column_def->new_column;
        print_knl_column_def_t(column);
    }

    GS_LOG_DEBUG_INF("----------------print_knl_altable_def_t  end------------------");
}

void print_knl_table_def_t(knl_table_def_t *def)
{
    GS_LOG_DEBUG_INF("----------------print_knl_table_def_t  begin----------------");
    GS_LOG_DEBUG_INF("schema:%s name:%s, space:%s", T2S(&def->schema), T2S(&def->name), T2S(&def->space));
    
    GS_LOG_DEBUG_INF("column_cnt:%d", def->columns.count);
    for (uint32_t i = 0; i < def->columns.count; i++) {
        knl_column_def_t *column = (knl_column_def_t *)cm_galist_get(&def->columns, i);
        print_knl_column_def_t(column);
    }
    GS_LOG_DEBUG_INF("initrans:%u", def->initrans);
    GS_LOG_DEBUG_INF("maxtrans:%u", def->maxtrans);
    GS_LOG_DEBUG_INF("pctfree:%u", def->pctfree);
    GS_LOG_DEBUG_INF("parted:%u", def->parted);
    GS_LOG_DEBUG_INF("sysid:%u", def->sysid);
    GS_LOG_DEBUG_INF("type:%d", def->type);
    GS_LOG_DEBUG_INF("appendonly:%d", def->appendonly);

    GS_LOG_DEBUG_INF("pk_inline:%d", def->pk_inline);
    GS_LOG_DEBUG_INF("uq_inline:%d", def->uq_inline);
    GS_LOG_DEBUG_INF("rf_inline:%d", def->rf_inline);
    GS_LOG_DEBUG_INF("chk_inline:%d", def->chk_inline);

    GS_LOG_DEBUG_INF("options:%u", def->options);
    GS_LOG_DEBUG_INF("serial_start:%lld", def->serial_start);
    GS_LOG_DEBUG_INF("collate:%u", def->collate);
    GS_LOG_DEBUG_INF("charset:%u", def->charset);
    GS_LOG_DEBUG_INF("compress_type:%u", def->compress_type);
    GS_LOG_DEBUG_INF("----------------print_knl_table_def_t  end------------------");
}