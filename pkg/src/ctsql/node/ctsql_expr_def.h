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
 * ctsql_expr_def.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/node/ctsql_expr_def.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_EXPR_DEF_H__
#define __SQL_EXPR_DEF_H__

#ifdef __cplusplus
extern "C" {
#endif

/*
CAUTION!!!: don't change the value of expr_node_type
in column default value / check constraint, the id is stored in system table COLUMN$
*/
typedef enum en_expr_node_type {
    EXPR_NODE_PRIOR = OPER_TYPE_PRIOR, // for prior flag of connect by clause
    EXPR_NODE_ADD = OPER_TYPE_ADD,
    EXPR_NODE_SUB = OPER_TYPE_SUB,
    EXPR_NODE_MUL = OPER_TYPE_MUL,
    EXPR_NODE_DIV = OPER_TYPE_DIV,
    EXPR_NODE_BITAND = OPER_TYPE_BITAND,
    EXPR_NODE_BITOR = OPER_TYPE_BITOR,
    EXPR_NODE_BITXOR = OPER_TYPE_BITXOR,
    EXPR_NODE_CAT = OPER_TYPE_CAT, /* character string joint */
    EXPR_NODE_MOD = OPER_TYPE_MOD,
    EXPR_NODE_LSHIFT = OPER_TYPE_LSHIFT,
    EXPR_NODE_RSHIFT = OPER_TYPE_RSHIFT,
    EXPR_NODE_UNION = OPER_TYPE_SET_UNION,
    EXPR_NODE_UNION_ALL = OPER_TYPE_SET_UNION_ALL,
    EXPR_NODE_INTERSECT = OPER_TYPE_SET_INTERSECT,
    EXPR_NODE_INTERSECT_ALL = OPER_TYPE_SET_INTERSECT_ALL,
    EXPR_NODE_EXCEPT = OPER_TYPE_SET_EXCEPT,
    EXPR_NODE_EXCEPT_ALL = OPER_TYPE_SET_EXCEPT_ALL,
    EXPR_NODE_OPCEIL = OPER_TYPE_CEIL,

    EXPR_NODE_CONST = 65536,
    EXPR_NODE_FUNC = EXPR_NODE_CONST + 1,
    EXPR_NODE_JOIN = EXPR_NODE_CONST + 2,
    EXPR_NODE_PARAM = EXPR_NODE_CONST + 3,
    EXPR_NODE_COLUMN = EXPR_NODE_CONST + 4,
    EXPR_NODE_RS_COLUMN = EXPR_NODE_CONST + 5,
    EXPR_NODE_STAR = EXPR_NODE_CONST + 6,
    EXPR_NODE_RESERVED = EXPR_NODE_CONST + 7,
    EXPR_NODE_SELECT = EXPR_NODE_CONST + 8,
    EXPR_NODE_SEQUENCE = EXPR_NODE_CONST + 9,
    EXPR_NODE_CASE = EXPR_NODE_CONST + 10,
    EXPR_NODE_GROUP = EXPR_NODE_CONST + 11,
    EXPR_NODE_AGGR = EXPR_NODE_CONST + 12,
    EXPR_NODE_USER_FUNC = EXPR_NODE_CONST + 13, // stored procedure or user defined function
    EXPR_NODE_USER_PROC = EXPR_NODE_CONST + 14, // stored procedure
    EXPR_NODE_PROC = EXPR_NODE_CONST + 15,      // stored procedure
    EXPR_NODE_NEW_COL = EXPR_NODE_CONST + 16,   // ':NEW.F1' IN TRIGGER
    EXPR_NODE_OLD_COL = EXPR_NODE_CONST + 17,   // ':OLD.F1' IN TRIGGER
    EXPR_NODE_PL_ATTR = EXPR_NODE_CONST + 18,
    EXPR_NODE_OVER = EXPR_NODE_CONST + 19,         // Analytic Func
    EXPR_NODE_TRANS_COLUMN = EXPR_NODE_CONST + 20, // for transform column
    EXPR_NODE_NEGATIVE = EXPR_NODE_CONST + 21,
    EXPR_NODE_DIRECT_COLUMN = EXPR_NODE_CONST + 22, // for function based index column
    EXPR_NODE_ARRAY = EXPR_NODE_CONST + 23,         // array
    EXPR_NODE_V_METHOD = EXPR_NODE_CONST + 24,
    EXPR_NODE_V_ADDR = EXPR_NODE_CONST + 25,
    EXPR_NODE_V_CONSTRUCT = EXPR_NODE_CONST + 26,
    EXPR_NODE_CSR_PARAM = EXPR_NODE_CONST + 27,
    EXPR_NODE_UNKNOWN = 0xFFFFFFFF,
} expr_node_type_t;

#define IS_UDT_EXPR(type) \
    ((type) == EXPR_NODE_V_METHOD || (type) == EXPR_NODE_V_ADDR || (type) == EXPR_NODE_V_CONSTRUCT)

#define IS_OPER_NODE(node) ((node)->type > 0 && (node)->type < EXPR_NODE_OPCEIL)

typedef struct nodetype_mapped {
    expr_node_type_t id;
    text_t name;
} nodetype_mapped_t;

static const nodetype_mapped_t g_nodetype_names[] = {
    // type_id             type_name
    { EXPR_NODE_PRIOR, { (char *)"PRIOR", 5 } },
    { EXPR_NODE_ADD, { (char *)"ADD", 3 } },
    { EXPR_NODE_SUB, { (char *)"SUB", 3 } },
    { EXPR_NODE_MUL, { (char *)"MUL", 3 } },
    { EXPR_NODE_DIV, { (char *)"DIV", 3 } },
    { EXPR_NODE_BITAND, { (char *)"BITAND", 6 } },
    { EXPR_NODE_BITOR, { (char *)"BITOR", 5 } },
    { EXPR_NODE_BITXOR, { (char *)"BITXOR", 6 } },
    { EXPR_NODE_CAT, { (char *)"CAT", 3 } },
    { EXPR_NODE_MOD, { (char *)"MOD", 3 } },
    { EXPR_NODE_LSHIFT, { (char *)"LSHIFT", 6 } },
    { EXPR_NODE_RSHIFT, { (char *)"RSHIFT", 6 } },
    { EXPR_NODE_UNION, { (char *)"UNION", 5 } },
    { EXPR_NODE_UNION_ALL, { (char *)"UNION_ALL", 9 } },
    { EXPR_NODE_INTERSECT, { (char *)"INTERSECT", 9 } },
    { EXPR_NODE_INTERSECT_ALL, { (char *)"INTERSECT_ALL", 13 } },
    { EXPR_NODE_EXCEPT, { (char *)"EXCEPT", 6 } },
    { EXPR_NODE_EXCEPT_ALL, { (char *)"EXCEPT_ALL", 10 } },
    { EXPR_NODE_OPCEIL, { (char *)"OPCEIL", 6 } },
    { EXPR_NODE_CONST, { (char *)"CONST", 5 } },
    { EXPR_NODE_FUNC, { (char *)"FUNC", 4 } },
    { EXPR_NODE_JOIN, { (char *)"JOIN", 4 } },
    { EXPR_NODE_PARAM, { (char *)"PARAM", 5 } },
    { EXPR_NODE_COLUMN, { (char *)"COLUMN", 6 } },
    { EXPR_NODE_RS_COLUMN, { (char *)"RS_COLUMN", 9 } },
    { EXPR_NODE_STAR, { (char *)"STAR", 4 } },
    { EXPR_NODE_RESERVED, { (char *)"RESERVED", 8 } },
    { EXPR_NODE_SELECT, { (char *)"SELECT", 6 } },
    { EXPR_NODE_SEQUENCE, { (char *)"SEQUENCE", 8 } },
    { EXPR_NODE_CASE, { (char *)"CASE", 4 } },
    { EXPR_NODE_GROUP, { (char *)"GROUP", 5 } },
    { EXPR_NODE_AGGR, { (char *)"AGGR", 4 } },
    { EXPR_NODE_USER_FUNC, { (char *)"USER_FUNC", 9 } },
    { EXPR_NODE_USER_PROC, { (char *)"USER_PROC", 9 } },
    { EXPR_NODE_PROC, { (char *)"PROC", 4 } },
    { EXPR_NODE_NEW_COL, { (char *)"NEW_COL", 7 } },
    { EXPR_NODE_OLD_COL, { (char *)"OLD_COL", 7 } },
    { EXPR_NODE_PL_ATTR, { (char *)"PL_ATTR", 7 } },
    { EXPR_NODE_OVER, { (char *)"OVER", 4 } },
    { EXPR_NODE_TRANS_COLUMN, { (char *)"TRANS_COLUMN", 12 } },
    { EXPR_NODE_NEGATIVE, { (char *)"NEGATIVE", 8 } },
    { EXPR_NODE_DIRECT_COLUMN, { (char *)"DIRECT_COLUMN", 13 } },
    { EXPR_NODE_ARRAY, { (char *)"ARRAY", 5 } },
    { EXPR_NODE_V_METHOD, { (char *)"V_METHOD", 8 } },
    { EXPR_NODE_V_ADDR, { (char *)"V_ADDR", 6 } },
    { EXPR_NODE_V_CONSTRUCT, { (char *)"V_CONSTRUCT", 11 } },
    { EXPR_NODE_UNKNOWN, { (char *)"UNKNOWN_TYPE", 12 } },
};

typedef struct st_expr_profile {
    uint32 xflags; // exclusive flags
    bool32 is_aggr;
    bool32 is_cond;
    sql_context_t *context;
    sql_clause_t curr_clause; // current verify operation identify
} expr_profile_t;

typedef enum en_unary_oper {
    UNARY_OPER_NONE = 0,
    UNARY_OPER_POSITIVE = 1,
    UNARY_OPER_NEGATIVE = -1,
    UNARY_OPER_ROOT = 2,
    UNARY_OPER_ROOT_NEGATIVE = -2 /* combine UNARY_OPER_ROOT and UNARY_OPER_NEGATIVE */
} unary_oper_t;

#define NODE_TYPE_SIZE ELEMENT_COUNT(g_nodetype_names)
#define UNARY_INCLUDE_ROOT(node) (abs((int32)(node)->unary) == (int32)UNARY_OPER_ROOT)
#define UNARY_INCLUDE_NEGATIVE(node) ((int32)(node)->unary < UNARY_OPER_NONE)
#define UNARY_INCLUDE_NON_NEGATIVE(node) ((int32)(node)->unary >= UNARY_OPER_NONE)
#define UNARY_REDUCE_NEST(out_expr, sub_node)                          \
    do {                                                               \
        if ((out_expr)->unary != UNARY_OPER_NONE) {                    \
            if ((sub_node)->unary == UNARY_OPER_NONE) {                \
                (sub_node)->unary = (out_expr)->unary;                 \
                break;                                                 \
            }                                                          \
            (sub_node)->unary *= (out_expr)->unary;                    \
            if ((sub_node)->unary > UNARY_OPER_ROOT) {                 \
                (sub_node)->unary = UNARY_OPER_ROOT;                   \
            } else if ((sub_node)->unary < UNARY_OPER_ROOT_NEGATIVE) { \
                (sub_node)->unary = UNARY_OPER_ROOT_NEGATIVE;          \
            }                                                          \
        }                                                              \
    } while (0);

#define SQL_SET_OPTMZ_MODE(node, _mode_)            \
    do {                                            \
        (node)->optmz_info.mode = (uint16)(_mode_); \
    } while (0)

#define SQL_MAX_FEXEC_VAR_BYTES SIZE_K(64)
#define SQL_MAX_FEXEC_VARS 128
#define SQL_HASH_OPTM_THRESHOLD 10
#define SQL_MAX_HASH_OPTM_KEYS 64
#define SQL_MAX_HASH_OPTM_COUNT 256

/* * When CONCAT (||) two const variants, if length of the final length is
less than this Marco, we do the constant optimization in verification phase;
since concatenating two long string may consume too must context memory.
Then the optimization is done in first execution */
#define SQL_MAX_OPTMZ_CONCAT_LEN 512

#define JSON_FUNC_ATTR_EQUAL(att1, att2) (((att1)->ids == (att2)->ids) && ((att1)->return_size == (att2)->return_size))

/* Get the datatype of an expr node and tree */
#define NODE_DATATYPE(node) ((node)->datatype)
/* TREE_DATATYPE cannot use in executing, can use sql_get_tree_datetype */
#define TREE_DATATYPE(tree) (NODE_DATATYPE((tree)->root))

#define NODE_TYPMODE(node) ((node)->typmod)
#define TREE_TYPMODE(tree) (NODE_TYPMODE((tree)->root))

/* Get the expr type of an expr node and tree */
#define NODE_EXPR_TYPE(node) ((node)->type)
#define TREE_EXPR_TYPE(tree) (NODE_EXPR_TYPE((tree)->root))

/* Get the location info of an expr node and tree */
#define NODE_LOC(node) ((node)->loc)
#define TREE_LOC(tree) (NODE_LOC((tree)->root))

#define NODE_VALUE(T, node) VALUE(T, &(node)->value)
#define NODE_VALUE_PTR(T, node) VALUE_PTR(T, &(node)->value)

#define EXPR_VALUE(T, expr) NODE_VALUE(T, (expr)->root)
#define EXPR_VALUE_PTR(T, expr) NODE_VALUE_PTR(T, (expr)->root)

/* Get table id of an column expr node and tree */
#define NODE_TAB(node) VAR_TAB(&(node)->value)
#define EXPR_TAB(expr) VAR_TAB(&(expr)->root->value)
/* Get table id of an rowid expr node and tree */
#define ROWID_NODE_TAB(node) ((node)->value.v_rid.tab_id)
#define ROWID_EXPR_TAB(expr) ((expr)->root->value.v_rid.tab_id)
/* Get column id of an column expr node and tree */
#define NODE_COL(node) VAR_COL(&(node)->value)
#define EXPR_COL(expr) VAR_COL(&(expr)->root->value)
/* Get NODE_ANCESTOR of an column expr node and tree */
#define NODE_ANCESTOR(node) VAR_ANCESTOR(&(node)->value)
#define EXPR_ANCESTOR(expr) VAR_ANCESTOR(&(expr)->root->value)
/* Get NODE_ANCESTOR of an column expr node and tree */
#define ROWID_NODE_ANCESTOR(node) ((node)->value.v_rid.ancestor)
/* Get NODE_VM_ID of an column expr node */
#define NODE_VM_ID(node) VAR_VM_ID(&(node)->value)
/* Get NODE_VM_ANCESTOR of an column expr node */
#define NODE_VM_ANCESTOR(node) VAR_VM_ANCESTOR(&(node)->value)
/* Get group id of an vm column expr node */
#define NODE_VM_GROUP(node) VAR_VM_GROUP(&(node)->value)

#define TAB_OF_NODE(node)                                                                           \
    ((NODE_EXPR_TYPE(node) == EXPR_NODE_COLUMN || NODE_EXPR_TYPE(node) == EXPR_NODE_TRANS_COLUMN) ? \
        NODE_TAB(node) :                                                                            \
        ROWID_NODE_TAB(node))
#define COL_OF_NODE(node)                                                                                            \
    ((NODE_EXPR_TYPE(node) == EXPR_NODE_COLUMN || NODE_EXPR_TYPE(node) == EXPR_NODE_TRANS_COLUMN) ? NODE_COL(node) : \
                                                                                                    CT_INVALID_ID16)
#define ANCESTOR_OF_NODE(node) \
    (NODE_EXPR_TYPE(node) == EXPR_NODE_COLUMN ? NODE_ANCESTOR(node) : ROWID_NODE_ANCESTOR(node))

/* To check whether an expr_tree or expr_node is a reserved NULL,
 * @see sql_verify_reserved_value */
#define NODE_IS_RES_NULL(node) ((NODE_EXPR_TYPE(node) == EXPR_NODE_RESERVED) && ((node)->value.v_int == RES_WORD_NULL))
#define NODE_IS_RES_ROWNUM(node) \
    ((NODE_EXPR_TYPE(node) == EXPR_NODE_RESERVED) && ((node)->value.v_int == RES_WORD_ROWNUM))
#define NODE_IS_RES_ROWSCN(node) \
    ((NODE_EXPR_TYPE(node) == EXPR_NODE_RESERVED) && ((node)->value.v_int == RES_WORD_ROWSCN))
#define NODE_IS_RES_ROWID(node) \
    ((NODE_EXPR_TYPE(node) == EXPR_NODE_RESERVED) && ((node)->value.v_int == RES_WORD_ROWID))
#define NODE_IS_RES_ROWNODEID(node) \
    ((NODE_EXPR_TYPE(node) == EXPR_NODE_RESERVED) && ((node)->value.v_int == RES_WORD_ROWNODEID))
#define NODE_IS_RES_DUMMY(node) \
    ((NODE_EXPR_TYPE(node) == EXPR_NODE_RESERVED) && ((node)->value.v_int == RES_WORD_DUMMY))
#define NODE_IS_RES_TRUE(node) ((NODE_EXPR_TYPE(node) == EXPR_NODE_RESERVED) && ((node)->value.v_int == RES_WORD_TRUE))
#define NODE_IS_RES_FALSE(node) \
    ((NODE_EXPR_TYPE(node) == EXPR_NODE_RESERVED) && ((node)->value.v_int == RES_WORD_FALSE))

/* select rowid from view may generate a column-type rowid, see function @sql_verify_rowid */
#define NODE_IS_COLUMN_ROWID(node) \
    ((NODE_EXPR_TYPE(node) == EXPR_NODE_COLUMN) && ((node)->value.v_col.is_rowid == CT_TRUE))
/* select rownodeid from view may generate a column-type rownodeid, see function @sql_verify_rownodeid */
#define NODE_IS_COLUMN_ROWNODEID(node) \
    ((NODE_EXPR_TYPE(node) == EXPR_NODE_COLUMN) && ((node)->value.v_col.is_rownodeid == CT_TRUE))

#define TREE_IS_RES_NULL(expr) NODE_IS_RES_NULL((expr)->root)
#define TREE_IS_RES_ROWID(expr) NODE_IS_RES_ROWID((expr)->root)

#define NODE_IS_VALUE_NULL(node) (node)->value.is_null
#define TREE_IS_VALUE_NULL(tree) NODE_IS_VALUE_NULL((tree)->root)

#define NODE_IS_CONST(expr) ((expr)->type == EXPR_NODE_CONST)
#define TREE_IS_CONST(tree) (NODE_IS_CONST((tree)->root))

#define NODE_IS_PARAM(expr) ((expr)->type == EXPR_NODE_PARAM)
#define NODE_IS_CSR_PARAM(expr) ((expr)->type == EXPR_NODE_CSR_PARAM)

#define NODE_IS_NEGATIVE(expr) ((expr)->type == EXPR_NODE_NEGATIVE)
#define TREE_IS_NEGATIVE(tree) (NODE_IS_NEGATIVE((tree)->root))

#define NODE_OPTIMIZE_MODE(node) ((node)->optmz_info.mode)
#define NODE_OPTMZ_IDX(node) ((node)->optmz_info.idx)
#define NODE_OPTMZ_COUNT(node) ((node)->optmz_info.count)

#define NODE_IS_OPTMZ_CONST(node) (NODE_OPTIMIZE_MODE(node) == OPTIMIZE_AS_CONST)
#define NODE_IS_FIRST_EXECUTABLE(node) (NODE_OPTIMIZE_MODE(node) == OPTMZ_FIRST_EXEC_ROOT)
#define NODE_IS_OPTMZ_ALL(node) (NODE_OPTIMIZE_MODE(node) == OPTMZ_FIRST_EXEC_ALL)

/* To check whether an expr_tree or expr_node is a reserved DEFAULT,
 * @see sql_verify_reserved_value */
#define TREE_IS_RES_DEFAULT(expr) \
    ((TREE_EXPR_TYPE(expr) == EXPR_NODE_RESERVED) && (EXPR_VALUE(int32, expr) == RES_WORD_DEFAULT))

/* To check whether an expr_tree or expr_node is a binding parameter,
 * @see sql_verify_reserved_value */
#define TREE_IS_BINDING_PARAM(expr) (TREE_EXPR_TYPE(expr) == EXPR_NODE_PARAM)

#define IS_NORMAL_COLUMN(expr) ((expr)->root->type == EXPR_NODE_COLUMN && (expr)->root->unary == UNARY_OPER_NONE)
#define IS_FAKE_COLUMN_NODE(node) (NODE_IS_RES_ROWNUM(node) || NODE_IS_RES_ROWSCN(node) || NODE_IS_RES_ROWID(node))
#define IS_LOCAL_COLUMN(expr) (IS_NORMAL_COLUMN(expr) && EXPR_ANCESTOR(expr) == 0)
#define IS_ANCESTOR_COLUMN(expr) (IS_NORMAL_COLUMN(expr) && EXPR_ANCESTOR(expr) > 0)

/* trim type for the argument expression of TRIM() */
typedef enum en_func_trim_type {
    FUNC_RTRIM = 0, /* also stands for unnamable keyword "TRAILING" */
    FUNC_LTRIM = 1, /* also stands for unnamable keyword "LEADING" */
    FUNC_BOTH = 2,  /* also stands for unnamable keyword "BOTH" */
} func_trim_type_t;

typedef enum en_any_type {
    ANY_MIN,
    ANY_MAX
} any_type_t;

/**
 * 1. `select * from tableX where date_col < to_date('2018-09-10 12:12:12');`
 * The format of TO_DATE relies on NLS_DATE_FORMAT, which is dependent on
 * the session parameter.
 * If NLS_DATE_FORMAT = 'YYYY-MM-DD HH24:MI:SS', the parsed date is 2018/09/10.
 * However, if NLS_DATE_FORMAT = 'YYYY-DD-MM HH24:MI:SS', the parsed date is 2018/10/09.
 * Due to soft parse, TO_DATE with one constant argument can not be optimized
 * in verify phase. In practice, it can be computed in advance on the first execution.
 *
 * Similar scenes include SYSDATE, SYSTIMESTAMP, SESSIONTIMEZONE;
 */
typedef enum en_optmz_mode {
    OPTIMIZE_NONE = 0,
    OPTMZ_FIRST_EXEC_ROOT,
    OPTMZ_FIRST_EXEC_NODE,
    OPTMZ_FIRST_EXEC_ALL,
    OPTIMIZE_AS_PARAM,
    OPTIMIZE_AS_CONST,
    OPTMZ_AS_HASH_TABLE,
    OPTMZ_INVAILD = 100
} optmz_mode_t;

typedef struct st_expr_optmz_info {
    uint16 mode; // @optmz_mode_t
    uint16 idx;
} expr_optmz_info_t;

typedef struct st_distinct_t {
    bool32 need_distinct;
    uint32 idx;
    uint32 group_id;
} distinct_t;

typedef struct st_json_func_attr {
    uint64 ids;         // json_func_attr_t
    uint16 return_size; // for JSON_FUNC_ATT_RETURNING_VARCHAR2
    struct {
        bool8 ignore_returning : 1;
        bool8 unused : 7;
    };
    uint8 unused2;
} json_func_attr_t;

#pragma pack(4)
typedef struct st_expr_node {
    struct st_expr_tree *owner;
    struct st_expr_tree *argument; // for function node & array node
    expr_node_type_t type;
    var_word_t word; // for column, function
    unary_oper_t unary;
    expr_optmz_info_t optmz_info;
    variant_t value;
    source_location_t loc;

    union {
        struct {
            ct_type_t datatype; // data type, set by verifier
            union {
                struct {
                    uint16 size; // data size, set by verifier
                    uint8 precision;
                    int8 scale;
                };
                void *udt_type; // udt type meta, as plv_record_t or plv_collection_t
            };
        };
        typmode_t typmod;
    };

    union {
        struct st_cond_tree *cond_arg; // for if function
        winsort_args_t *win_args;      // for winsort-func
        uint32 ext_args;               // for trim func
        galist_t *sort_items;          // for group_concat(... order by expr) or median
    };

    bool8 nullaware : 1;      // for all/any optimized min/max aggr node
    bool8 exec_default : 1;   // execute default expr cast
    bool8 format_json : 1;    // for json expr
    bool8 has_verified : 1;   // for order by 1,2 or order by alias
    bool8 is_median_expr : 1; // expr for sharding median
    bool8 ignore_nulls : 1;   // for first_value/last_value
    bool8 parent_ref : 1;     // true means is already added to parent refs
    bool8 is_pkg : 1;         // if in user defined pkg
    uint8 lang_type;          // for proc/func lang type
    uint8 unused[2];

    json_func_attr_t json_func_attr; // for json_value/json_query/json_mergepatch
    distinct_t dis_info;

    // for expression tree
    struct st_expr_node *left;
    struct st_expr_node *right;

    // for expr-node chain
    // don't change the definition order of prev and next
    // so cond_node_t can be change to biqueue_node_t by macro QUEUE_NODE_OF
    // and be added to a bi-queue
    struct st_expr_node *prev;
    struct st_expr_node *next;
} expr_node_t;
#pragma pack()

typedef struct st_expr_chain {
    uint32 count;
    expr_node_t *first;
    expr_node_t *last;
} expr_chain_t;

typedef struct st_star_location {
    uint32 begin;
    uint32 end;
} star_location_t;

typedef struct st_expr_tree {
    sql_context_t *owner;
    expr_node_t *root;
    struct st_expr_tree *next; // for expr list
    source_location_t loc;
    uint32 expecting;
    unary_oper_t unary;
    bool32 generated;
    expr_chain_t chain;
    text_t arg_name;
    star_location_t star_loc;
    uint32 subscript;
} expr_tree_t;

typedef struct st_sql_walker {
    sql_stmt_t *stmt;
    sql_context_t *context;
    galist_t *columns;
} sql_walker_t;

typedef enum en_pivot_type {
    PIVOT_TYPE,
    UNPIVOT_TYPE,
    NOPIVOT_TYPE,
} pivot_type_t;

typedef struct st_pivot_items {
    pivot_type_t type;
    source_location_t loc;
    galist_t *alias;
    galist_t *group_sets;
    union {
        struct {
            expr_tree_t *aggr_expr;
            galist_t *aggrs;
            galist_t *pivot_rs_columns;
            expr_tree_t *for_expr;
            expr_tree_t *in_expr;
            galist_t *aggr_alias;
            uint32 aggr_count;
        };
        struct {
            galist_t *unpivot_data_rs;
            galist_t *column_name;
            galist_t *unpivot_alias_rs;
            bool32 include_nulls;
        };
    };
} pivot_items_t;

typedef status_t (*expr_calc_func_t)(sql_stmt_t *stmt, expr_node_t *node, variant_t *result);

typedef struct st_node_func_tab {
    expr_node_type_t type;
    expr_calc_func_t invoke;
} node_func_tab_t;

typedef struct st_case_pair {
    struct st_cond_tree *when_cond;
    expr_tree_t *when_expr;
    expr_tree_t *value;
} case_pair_t;

typedef struct st_case_expr {
    bool32 is_cond; /* FALSE: CASE expr WHEN expr THEN expr ... END , TRUE: CASE WHEN condition THEN expr ... END */
    expr_tree_t *expr;
    galist_t pairs;
    expr_tree_t *default_expr;
} case_expr_t;

typedef struct st_visit_assist {
    sql_stmt_t *stmt;
    sql_query_t *query;
    uint32 excl_flags;
    void *param0;
    void *param1;
    void *param2;
    void *param3;
    uint32 result0;
    uint32 result1;
    uint32 result2;
    date_t time;
} visit_assist_t;

#define RELATION_LEVELS 3

typedef struct st_cols_used {
    biqueue_t cols_que[RELATION_LEVELS]; // list for ancestor, parent and self column expression
    uint16 count[RELATION_LEVELS];       // count for ancestor, parent and self column expression
    uint8 level_flags[RELATION_LEVELS];  // flags of each level
    uint8 flags;
    uint8 subslct_flag;
    uint8 inc_flags;
    uint8 level;
    uint8 func_maxlev; // the max level of column expression in functions
    uint32 ancestor;   // the max ancestor of column
    bool8 collect_sub_select : 1;
    bool8 unused : 7;
} cols_used_t;

#define APPEND_CHAIN(chain, node)         \
    do {                                  \
        (node)->next = NULL;              \
        if ((chain)->count == 0) {        \
            (chain)->first = node;        \
            (chain)->last = node;         \
            (node)->prev = NULL;          \
        } else {                          \
            (chain)->last->next = node;   \
            (node)->prev = (chain)->last; \
            (chain)->last = node;         \
        }                                 \
        (chain)->count++;                 \
    } while (0)

#define SQL_GET_STMT_SYSTIMESTAMP(stmt, result)                   \
    do {                                                          \
        if ((stmt)->v_systimestamp == SQL_UNINITIALIZED_TSTAMP) { \
            (stmt)->v_systimestamp = cm_now();                    \
        }                                                         \
        (result)->v_tstamp = (stmt)->v_systimestamp;              \
    } while (0)

#define SQL_GET_STMT_SYSDATE(stmt, result)                 \
    do {                                                   \
        if ((stmt)->v_sysdate == SQL_UNINITIALIZED_DATE) { \
            (stmt)->v_sysdate = cm_date_now();             \
        }                                                  \
        (result)->v_date = (stmt)->v_sysdate;              \
    } while (0)


#define VA_EXCL_NONE 0x00000000
#define VA_EXCL_PRIOR 0x00000001
#define VA_EXCL_WIN_SORT 0x00000002
#define VA_EXCL_FUNC 0x00000004
#define VA_EXCL_PROC 0x00000008

#define ANCESTOR_IDX 0
#define PARENT_IDX 1
#define SELF_IDX 2

#define FLAG_HAS_ANCESTOR_COLS 0x01
#define FLAG_HAS_PARENT_COLS 0x02
#define FLAG_HAS_SELF_COLS 0x04

#define FLAG_INC_ROWNUM 0x01
#define FLAG_INC_PRIOR 0x02
#define FLAG_INC_PARAM 0x04

#define LEVEL_HAS_DIFF_COLS 0x01
#define LEVEL_HAS_DIFF_TABS 0x02
#define LEVEL_HAS_ROWID 0x04
#define LEVEL_HAS_ROWNODEID 0x08

#define STATIC_SUB_SELECT 0x01
#define DYNAMIC_SUB_SELECT 0x02

#define HAS_PARENT_COLS(flags) ((flags) & FLAG_HAS_PARENT_COLS)
#define HAS_ANCESTOR_COLS(flags) ((flags) & FLAG_HAS_ANCESTOR_COLS)
#define HAS_SELF_COLS(flags) ((flags) & FLAG_HAS_SELF_COLS)
#define HAS_NO_COLS(flags) ((flags) == 0)
#define HAS_ONLY_SELF_COLS(flags) ((flags) == FLAG_HAS_SELF_COLS)
#define HAS_ONLY_PARENT_COLS(flags) ((flags) == FLAG_HAS_PARENT_COLS)
#define HAS_PRNT_OR_ANCSTR_COLS(flags) (HAS_PARENT_COLS(flags) || HAS_ANCESTOR_COLS(flags))
#define HAS_PRNT_AND_ANCSTR_COLS(flags) (HAS_PARENT_COLS(flags) && HAS_ANCESTOR_COLS(flags))
#define HAS_NOT_ONLY_SELF_COLS(flags) (HAS_SELF_COLS(flags) && (HAS_ANCESTOR_COLS(flags) || HAS_PARENT_COLS(flags)))

#define HAS_DIFF_TABS(cols_used, idx) ((cols_used)->level_flags[idx] & LEVEL_HAS_DIFF_TABS)
#define HAS_ROWID_COLUMN(cols_used, idx) ((cols_used)->level_flags[idx] & LEVEL_HAS_ROWID)
#define HAS_ROWNODEID_COLUMN(cols_used, idx) ((cols_used)->level_flags[idx] & LEVEL_HAS_ROWNODEID)

#define HAS_SUBSLCT(cols_used) ((cols_used)->subslct_flag > 0)
#define HAS_STATIC_SUBSLCT(cols_used) ((cols_used)->subslct_flag & STATIC_SUB_SELECT)
#define HAS_DYNAMIC_SUBSLCT(cols_used) ((cols_used)->subslct_flag & DYNAMIC_SUB_SELECT)

#define HAS_ROWNUM(cols_used) ((cols_used)->inc_flags & FLAG_INC_ROWNUM)
#define HAS_PRIOR(cols_used) ((cols_used)->inc_flags & FLAG_INC_PRIOR)
#define HAS_PARAM(cols_used) ((cols_used)->inc_flags & FLAG_INC_PARAM)

#define VAR_IS_NUMBERIC_ZERO(var) \
    ((var)->is_null == CT_FALSE && CT_IS_NUMERIC_TYPE((var)->type) && (var)->v_bigint == 0)

#ifdef __cplusplus
}
#endif

#endif
