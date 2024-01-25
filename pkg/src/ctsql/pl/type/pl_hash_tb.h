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
 * pl_hash_tb.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/type/pl_hash_tb.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_HASH_TB_H__
#define __PL_HASH_TB_H__

#include "pl_rbt.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_entry_key {
    int16 type; // index's datatype
    bool8 unused[2];
    union {
        int32 int_idx;
        mtrl_rowid_t txt_idx;
    };
} entry_key_t;

typedef struct st_hstb_node {
    rbt_node_t rbt_node; // rbt_node must be the first member of hstb_node_t
    entry_key_t key;     // hash table's index
    mtrl_rowid_t value;  // element value
} hstb_node_t;

typedef struct st_pl_hash_table {
    rbt_tree_t rbt;
    int16 datatype; // element's datatype
    bool8 unused[2];
} pl_hash_table_t;

status_t udt_hash_table_init_var(sql_stmt_t *stmt, variant_t *value);
status_t udt_hash_table_record_init(sql_stmt_t *stmt, var_collection_t *var_coll, var_address_pair_t *pair,
                                    variant_t *index, variant_t *temp_obj);
void udt_reg_hash_table_method(void);
status_t udt_hash_table_address_write(sql_stmt_t *stmt, variant_t *var, variant_t *index, variant_t *right);

#ifdef __cplusplus
}
#endif

#endif
