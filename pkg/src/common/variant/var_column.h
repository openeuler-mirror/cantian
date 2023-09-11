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
 * var_column.h
 *
 *
 * IDENTIFICATION
 * src/common/variant/var_column.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __VAR_COLUMN_H__
#define __VAR_COLUMN_H__

#include "cm_defs.h"
#include "cm_text.h"

#ifdef Z_SHARDING
typedef struct st_column_info {
    /* col project id, for example, create table t1(f1, f2), select f2 from t1, col of f2 = 1, col_pro_id of f2 = 0 */
    uint32 col_pro_id;         /* column project id */
    text_t col_name;           /* column name */
    text_t tab_alias_name;     /* table alias name, such as select * from tbl_xxx a */
    text_t tab_name;           /* table name */
    text_t user_name;          /* table owner */
    uint16 org_tab;            /* v_col.tab of original query */
    uint16 org_col;            /* v_col.col of original table */
    bool8 col_name_has_quote;  /* origin col_name wrapped by double quotation or not */
    bool8 tab_name_has_quote;  /* origin tab_name wrapped by double quotation or not */
    bool8 reserved[2];
} column_info_t;
#endif

typedef struct st_var_column {
    gs_type_t datatype;
    uint16 tab;
    uint16 col; /* it is observed that "col" means the column index
                in the original table definition(starts from 0)
                of the "v_col" value appeared in rs_column_t */
#ifdef Z_SHARDING
    column_info_t *col_info_ptr;
    uint32 adjusted : 1;     // if col is adjusted, can't adjust again, see func: shd_walk_column_adjust_project
    uint32 has_adjusted : 1; // for subquery pullup
#endif
    uint32 is_ddm_col : 1;
    uint32 is_rowid : 1;
    uint32 is_rownodeid : 1;
    uint32 is_array : 1; // column is array type
    uint32 is_jsonb : 1; // column is jsonb type
    uint32 reserved : 25;
    uint32 ancestor;   // 0: not have ancestor, 1: parent, 2: grandfather, ...
    int32 ss_start;    // start subscript of array
    int32 ss_end;      // end subscript of array
} var_column_t;

#define VAR_COL_IS_ARRAY_ELEMENT(col)   ((col)->ss_start > 0 && (col)->ss_end == (int32)GS_INVALID_ID32)
#define VAR_COL_IS_ARRAY_ALL(col)       ((col)->ss_start == (int32)GS_INVALID_ID32 && (col)->ss_end == (int32)GS_INVALID_ID32)
#define QUERY_FIELD_IS_ELEMENT(query_field)  ((query_field)->start > 0 && (query_field)->end == (int32)GS_INVALID_ID32)

typedef struct st_var_vm_col {
    uint16 id;
    uint16 group_id;    // grouping set id
    uint32 ancestor;
    bool32 is_ddm_col;
    void  *origin_ref;
} var_vm_col_t;

#endif