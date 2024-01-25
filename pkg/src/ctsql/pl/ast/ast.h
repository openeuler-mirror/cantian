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
 * ast.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/ast/ast.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __AST_H__
#define __AST_H__

#include "pl_defs.h"
#include "pragma.h"
#include "decl.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PL_MAX_BLOCK_DEPTH 128

typedef bool32 (*plc_keyword_hook_t)(word_t *word);
typedef bool32 (*plc_variant_hook_t)(void *anchor);

typedef struct st_pl_arg_info pl_arg_info_t;
typedef struct st_plc_block plc_block_t;
typedef struct st_plc_block_stack plc_block_stack_t;
typedef struct st_pl_lable_info pl_lable_info_t;
typedef struct st_proc_complier pl_compiler_t;
typedef struct st_pl_ctl_block_id pl_ctl_block_id_t;
typedef struct st_pl_line_ctrl pl_line_ctrl_t;
typedef struct st_pl_line_begin pl_line_begin_t;
typedef struct st_pl_line_ctl_block pl_line_ctl_block_t;
typedef struct st_pl_line_raise pl_line_raise_t;
typedef struct st_pl_label_ctrl pl_line_label_t;
typedef struct st_pl_line_except pl_line_except_t;
typedef struct st_pl_line_while pl_line_while_t;
typedef struct st_pl_line_loop pl_line_loop_t;
typedef struct st_pl_line_continue pl_line_continue_t;
typedef struct st_pl_line_exit pl_line_exit_t;
typedef struct st_pl_line_end_loop pl_line_end_loop_t;
typedef struct st_pl_line_goto pl_line_goto_t;
typedef struct st_pl_line_close pl_line_close_t;
typedef struct st_pl_line_open pl_line_open_t;
typedef struct st_pl_into pl_into_t;
typedef struct st_pl_line_sql pl_line_sql_t;
typedef struct st_pl_line_fetch pl_line_fetch_t;
typedef struct st_pl_line_case pl_line_case_t;
typedef struct st_pl_line_if pl_line_if_t;
typedef struct st_pl_line_else pl_line_else_t;
typedef struct st_pl_line_elsif pl_line_elsif_t;
typedef struct st_pl_line_when_case pl_line_when_case_t;
typedef struct st_pl_line_normal pl_line_normal_t;
typedef struct st_pl_line_savepoint pl_line_savepoint_t;
typedef struct st_pl_line_return pl_line_return_t;
typedef struct st_pl_using_expr pl_using_expr_t;
typedef struct st_pl_line_execute pl_line_execute_t;
typedef struct st_pl_line_rollback pl_line_rollback_t;
typedef struct st_pl_line_for pl_line_for_t;
typedef struct st_pl_line_when pl_line_when_t;
typedef struct st_plc_compile_lines_map plc_compile_lines_map_t;

struct st_pl_arg_info {
    expr_node_t *func;
    uint32 pos;
};

struct st_plc_block {
    pl_line_ctrl_t *entry;
    text_t name;
};

struct st_plc_block_stack {
    plc_block_t items[PL_MAX_BLOCK_DEPTH];
    uint16 depth;
};

struct st_pl_lable_info {
    pl_line_ctrl_t *lines[PL_MAX_BLOCK_DEPTH];
    uint32 count;
};

typedef enum en_pl_compile_step {
    PL_COMPILE_INIT = 0,
    PL_COMPILE_AFTER_DECL = 1
} pl_compile_step_t;

struct st_proc_complier {
    sql_stmt_t *stmt;
    plc_block_stack_t stack;         // decl-stack; call,begin and for
    plc_block_stack_t control_stack; // control-stack; support if,while,loop,case etc
    pl_line_ctrl_t *last_line;
    uint32 type;
    uint32 root_type;
    int64 proc_oid; // for PL_ANONYMOUS_BLOCK or CALL statement, no oid at all
    source_location_t line_loc;
    var_udo_t *obj;

    pl_source_pages_t pages;

    // record label jump info
    pl_lable_info_t labels;

    // for convert sql
    uint32 large_page_id;
    char *convert_buf;
    uint32 convert_buf_size;

    uint32 into_count;
    text_t *sql;

    // for params
    uint16 param_block_id;
    galist_t *params;

    // for decls
    galist_t *decls;      /* the declare variable */
    galist_t *type_decls; // for %rowtype

    plc_keyword_hook_t keyword_hook;
    plc_variant_hook_t variant_hook;
    galist_t *current_input; // for currrent line: input variants referenced by sql, list of expr_node_t

    void *entity;
    pl_line_begin_t *body;
    void *spec_dc; // for package
    uint32 proc_id;
    bool32 push_stack;
    uint32 step;
    void *proc;
};

struct st_pl_ctl_block_id {
    uint32 depth;
    uint32 id[PL_MAX_BLOCK_DEPTH];
};

// if pl_line_type_t change, need change LINE_TYPE_NUM too
enum en_pl_line_type {
    LINE_UNKNOWN = -1,
    LINE_NONE = 0,
    LINE_BEGIN = 1,
    LINE_END = 2,
    LINE_END_IF = 3,
    LINE_END_LOOP = 4,
    LINE_EXCEPTION = 5,
    LINE_SETVAL = 6, // such as a := 100;
    LINE_IF = 7,     // IF aaa THEN ... END IF
    LINE_ELIF = 8,
    LINE_ELSE = 9,
    LINE_FOR = 10,
    LINE_LOOP = 11,
    LINE_GOTO = 12,
    LINE_EXEC = 13,
    LINE_FETCH = 14,
    LINE_OPEN = 15,
    LINE_WHEN = 16,
    LINE_CLOSE = 17,
    LINE_NULL = 18,
    LINE_SQL = 19, // inline sql
    LINE_PUTLINE = 20,
    LINE_CASE = 21,
    LINE_WHEN_CASE = 22,
    LINE_END_CASE = 23,
    LINE_EXIT = 24,
    LINE_LABEL = 25,
    LINE_CONTINUE = 26,
    LINE_WHILE = 27,
    LINE_RAISE = 28,
    LINE_COMMIT = 29,
    LINE_ROLLBACK = 30,
    LINE_SAVEPOINT = 31,
    LINE_PROC = 32,   // call stored procedure
    LINE_RETURN = 33, // call stored procedure
    LINE_EXECUTE = 34,
    LINE_END_WHEN = 35,
    LINE_END_EXCEPTION = 36,
};

typedef enum en_pl_line_type pl_line_type_t;

struct st_pl_line_ctrl {
    source_location_t loc;
    pl_line_type_t type;
    struct st_pl_line_ctrl *next;
};

struct st_pl_line_begin {
    pl_line_ctrl_t ctrl;
    galist_t *decls;
    galist_t *type_decls;
    union {
        struct {
            pl_line_ctrl_t *except; /* exception line */
            pl_line_ctrl_t *end;    /* the end line of this block */
            text_t *name;
        };
        /* call spec info */
        struct {
            text_t lib_user;
            text_t lib_name;
            text_t func;
        };
    };
};

struct st_pl_line_ctl_block {
    pl_line_ctrl_t *line;
    pl_ctl_block_id_t ctl_block_id;
    struct st_pl_line_ctl_block *next;
};

struct st_pl_line_raise {
    pl_line_ctrl_t ctrl;
    text_t excpt_name;
    pl_exception_t excpt_info;
    pl_line_ctrl_t *next;
};

struct st_pl_label_ctrl {
    pl_line_ctrl_t ctrl;
    text_t name;
    pl_line_ctrl_t *stack_line;
};

struct st_pl_line_except {
    pl_line_ctrl_t ctrl;
    galist_t *excpts; /* the excepts tackle lines of this block */
    pl_line_ctrl_t *end;
};

struct st_pl_line_while {
    pl_line_ctrl_t ctrl;
    pl_line_ctrl_t *next;
    text_t *name;
    cond_tree_t *cond;
    pl_line_ctrl_t *stack_line;
};

struct st_pl_line_loop {
    pl_line_ctrl_t ctrl;
    pl_line_ctrl_t *next;
    pl_line_ctrl_t *stack_line;
};

struct st_pl_line_continue {
    pl_line_ctrl_t ctrl;
    void *cond;
    pl_line_ctrl_t *next;
};

struct st_pl_line_exit {
    pl_line_ctrl_t ctrl;
    void *cond;
    pl_line_ctrl_t *next;
};

struct st_pl_line_end_loop {
    pl_line_ctrl_t ctrl;
    pl_line_ctrl_t *loop;
};

struct st_pl_line_goto {
    pl_line_ctrl_t ctrl;
    text_t label;
    pl_line_ctrl_t *next;
};

struct st_pl_line_close {
    pl_line_ctrl_t ctrl;
    plv_id_t vid;
};

struct st_pl_line_open {
    pl_line_ctrl_t ctrl;
    galist_t *exprs;
    plv_id_t vid;
    bool32 is_dynamic_sql;
    union {
        sql_context_t *context;
        struct {
            expr_tree_t *dynamic_sql;
            galist_t *using_exprs;
        };
    };
    galist_t *input; // list of expr_node_t
};

enum en_plv_into_type {
    INTO_AS_VALUE = 0x1, /* select xx, xx into var1, var2 from xxx, scalar field assign,
                         result set field and variable one-to-one correspondence */
    INTO_AS_COLL,     /* fetch cursor bulk collect into collection or multi collection, the attr_type is scalar type */
    INTO_AS_REC,      /* select xx, xx into record from xxx, scalar field assign,
                      result set field and record field one-to-one correspondence */
    INTO_AS_COLL_REC, /* fetch cursor bulk collect into collection, the attr_type is record type */
};

typedef enum en_plv_into_type plv_into_type_t;

#define INTO_COMMON_PREFETCH_COUNT 1 // as for impcur cursor/for expcursor/fetch into, only fetch one record
#define INTO_VALUES_PREFETCH_COUNT 2 /* as select into/ exec dynamic sql into, \
need fetch twice to check if has addition record */

struct st_pl_into {
    galist_t *output; // list of expr_node_t. select ... into ..., returning ...
    uint32 prefetch_rows;
    bool8 is_bulk;
    uint8 into_type; // plv_into_type_t
    uint8 unused[2];
    expr_tree_t *limit;
};

struct st_pl_line_sql {
    pl_line_ctrl_t ctrl;
    bool32 is_dynamic_sql; // if local tmp table exist in sql, treate as dynamic sql
    union {
        sql_context_t *context;
        expr_tree_t *dynamic_sql;
    };

    galist_t *input; // list of expr_node_t
    pl_into_t into;
};

struct st_pl_line_fetch {
    pl_line_ctrl_t ctrl;
    plv_id_t vid;
    pl_into_t into;
};

struct st_pl_line_case {
    pl_line_ctrl_t ctrl;
    expr_tree_t *selector;
};

struct st_pl_line_if {
    pl_line_ctrl_t ctrl;
    cond_tree_t *cond;
    pl_line_ctrl_t *t_line; // line for true
    pl_line_ctrl_t *f_line; // line for false
    pl_line_ctrl_t *next;   // line for exit
};

struct st_pl_line_else {
    pl_line_ctrl_t ctrl;
    pl_line_if_t *if_line; // line for if-brother, may be elsif-brother, they're same.
};

struct st_pl_line_elsif {
    pl_line_ctrl_t ctrl;
    cond_tree_t *cond;
    pl_line_ctrl_t *t_line; // line for true
    pl_line_ctrl_t *f_line; // line for false
    pl_line_ctrl_t *next;   // line for exit if
    pl_line_if_t *if_line;  // line for if-brother
};

struct st_pl_line_when_case {
    pl_line_ctrl_t ctrl;
    void *cond;
    pl_line_ctrl_t *t_line; // line for true
    pl_line_ctrl_t *f_line; // line for false
    pl_line_ctrl_t *next;   // line for exit if

    pl_line_if_t *if_line; // line for if-brother
    expr_tree_t *selector;
};

struct st_pl_line_normal {
    pl_line_ctrl_t ctrl;
    union {
        expr_node_t *proc; // call proc
        struct {           // setval
            expr_node_t *left;
            expr_tree_t *expr;
            cond_tree_t *cond;
        };
    };
};

struct st_pl_line_savepoint {
    pl_line_ctrl_t ctrl;
    text_t savepoint;
};

struct st_pl_line_return {
    pl_line_ctrl_t ctrl;
    expr_tree_t *expr;
};

struct st_pl_using_expr {
    expr_tree_t *expr;
    plv_direction_t dir;
};

struct st_pl_line_execute {
    pl_line_ctrl_t ctrl;
    expr_tree_t *dynamic_sql;
    galist_t *using_exprs; // using exprs
    pl_into_t into;
};

struct st_pl_line_rollback {
    pl_line_ctrl_t ctrl;
    text_t savepoint;
};

enum en_pl_block_end {
    PBE_END,
    PBE_END_IF,
    PBE_ELIF,
    PBE_ELSE,
    PBE_END_LOOP,
    PBE_WHEN_CASE,
    PBE_END_CASE,
    PBE_END_EXCEPTION,
};

typedef enum en_pl_block_end pl_block_end_t;

struct st_pl_line_for {
    pl_line_ctrl_t ctrl;
    pl_line_ctrl_t *next;
    bool8 is_cur;
    bool8 is_push;
    uint16 reseved;
    union {
        struct {
            bool32 reverse;
            expr_tree_t *lower_expr; /* the lower_bound expr of for-loop */
            expr_tree_t *upper_expr; /* the upper_bound expr of for-loop */
        };

        struct {
            bool32 is_impcur;
            plv_id_t cursor_id;     // indicate in cursor, exp or imp
            sql_context_t *context; // impcur true
            galist_t *exprs;
            pl_into_t into;
        };
    };
    plv_decl_t *id;
    galist_t *decls; // record declare index variant's pos in for statement.
    text_t *name;
};

struct st_pl_line_when {
    pl_line_ctrl_t ctrl;
    galist_t excepts;
};

// MACRO must exists at begin of the line, or made mistake.
#define IS_PL_LABEL(leader_word)                                                                                       \
    ((leader_word)->type == WORD_TYPE_OPERATOR && (leader_word)->text.len == 2 && (leader_word)->text.str[0] == '<' && \
        (leader_word)->text.str[1] == '<')

#define IS_END_LINE_TYPE(type)                                                                                 \
    ((type) == LINE_END || (type) == LINE_END_CASE || (type) == LINE_END_EXCEPTION || (type) == LINE_END_IF || \
        (type) == LINE_END_LOOP || (type) == LINE_END_WHEN)

void plc_check_end_symbol(word_t *word);
status_t plc_check_word_eof(word_type_t type, source_location_t loc);
status_t plc_prepare_noarg_call(word_t *word);
status_t plc_compile_exception_set_except(plv_decl_t *decl, word_t *word, pl_exception_t *pl_except);
status_t plc_using_clause_get_dir(plv_direction_t *dir, lex_t *lex, text_t *decl_name);
status_t plc_make_input_name(galist_t *input, char *buf, uint32 buf_len, text_t *name);
status_t plc_ctl_block_count_change(pl_line_type_t line_type, uint32 *block_depth, uint32 *block_count,
    uint32 count_size);
status_t plc_verify_label_next(sql_stmt_t *plc_stmt, pl_line_ctl_block_t **curr_ctl_block_ln);
void plc_copy_ctl_block_id(pl_ctl_block_id_t *ctl_block_id, uint32 block_depth, uint32 *block_count, uint32 cnt_size);
status_t plc_find_ctl_block_id(pl_line_ctl_block_t *ctl_block_lines, pl_line_ctrl_t *line,
    pl_ctl_block_id_t *ctl_block_id);
bool32 plc_ctl_block_equal(pl_ctl_block_id_t *block_id1, pl_ctl_block_id_t *block_id2);
#define CURR_CTL_STACK(compiler) ((compiler)->control_stack)
#define CURR_CTL_BLOCK_BEGIN(compiler) ((CURR_CTL_STACK(compiler).depth == 0) ? NULL : CURR_CTL_STACK(compiler).items[CURR_CTL_STACK(compiler).depth - 1].entry)
#define CURR_BLOCK_BEGIN(compiler) (((compiler)->stack.depth == 0) ? NULL : (compiler)->stack.items[(compiler)->stack.depth - 1].entry)


#ifdef __cplusplus
}
#endif

#endif