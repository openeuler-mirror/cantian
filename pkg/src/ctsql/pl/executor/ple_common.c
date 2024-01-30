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
 * ple_common.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/executor/ple_common.c
 *
 * -------------------------------------------------------------------------
 */

#include "ple_common.h"
#include "ctsql_package.h"
#include "pl_scalar.h"
#include "ctsql_privilege.h"
#include "pl_hash_tb.h"
#include "dml_executor.h"

void ple_update_func_error(sql_stmt_t *stmt, expr_node_t *node)
{
    pl_executor_t *executor = (pl_executor_t *)stmt->pl_exec;
    text_t user = node->word.func.user.value;
    text_t name = node->word.func.name.value;

    if (executor == NULL) {
        return;
    }
    if (executor->error_tracked == CT_TRUE) {
        PLE_RESET_EXEC_ERR(executor);
        executor->error_tracked = CT_FALSE;
    }

    if (user.len == 0) {
        if (node->value.v_func.pack_id == DBE_STD_PACK_ID) {
            user.str = "DBE_STD";
            user.len = (uint32)strlen(user.str);
        } else if (node->value.v_func.pack_id == CT_INVALID_ID32 && node->value.v_func.is_proc == CT_FALSE) {
            user.str = "PUBLIC";
            user.len = (uint32)strlen(user.str);
        } else {
            user.str = "UNKNOWN";
            user.len = (uint32)strlen(user.str);
        }
    }
    ple_check_error(stmt);
    ple_update_error_stack(stmt, &user, &name, &node->loc);
    ple_set_error(stmt, &user, &name, &node->loc);
}

ple_var_t *ple_get_plvar(pl_executor_t *executor, plv_id_t vid)
{
    uint16 depth = (uint16)vid.block + executor->stack_base;
    ple_block_t *block = executor->block_stack.items[depth];
    ple_var_t *var = block->var_map.items[vid.id];
    return var;
}

status_t ple_init_executor(pl_executor_t *executor, sql_stmt_t *stmt)
{
    executor->sql_loc.line = 1;
    executor->sql_loc.column = 1;
    executor->combine64 = 0;
    executor->cond_exec.depth = 0;
    executor->selector_exec.depth = 0;
    executor->start_line = NULL;
    executor->curr_line = NULL;
    executor->trig_exec = NULL;
    executor->dynamic_parent = NULL;
    executor->curr_input = NULL;
    executor->coverage = NULL;
    executor->recent_rows = 0;
    executor->err_buf[0] = '\0';
    MEMS_RETURN_IFERR(memset_s(&executor->exec_except, sizeof(pl_exec_exception_t), 0, sizeof(pl_exec_exception_t)));

    executor->block_stack.depth = 0;
    executor->stack_base = 0;
    executor->entity = NULL;
    return sql_array_init(&executor->svpts, CT_MAX_SAVEPOINTS, stmt, sql_stack_alloc);
}

status_t ple_prepare_pl_cursors(sql_stmt_t *stmt, bool8 *is_curs_prepare)
{
    if (stmt->is_sub_stmt) {
        *is_curs_prepare = CT_FALSE;
        return CT_SUCCESS;
    }

    if (stmt->session->pl_cursors == NULL) {
        uint32 size = sizeof(pl_cursor_slot_t) * PLE_MAX_CURSORS;
        CT_RETURN_IFERR(sql_push(stmt, size, (void **)&stmt->session->pl_cursors));
        errno_t rc_memzero = memset_s(stmt->session->pl_cursors, size, 0, size);
        if (rc_memzero != EOK) {
            CTSQL_POP(stmt);
            CT_THROW_ERROR(ERR_RESET_MEMORY, "initializing pl cursors");
            return CT_ERROR;
        }
        *is_curs_prepare = CT_TRUE;
    } else {
        *is_curs_prepare = CT_FALSE;
    }
    return CT_SUCCESS;
}

status_t ple_begin_auton_rm(session_t *session)
{
    knl_temp_cache_t *temp_table = NULL;
    knl_session_t *knl_se = &session->knl_session;

    for (uint32 i = 0; i < knl_se->temp_table_count; i++) {
        temp_table = &knl_se->temp_table_cache[i];
        if (temp_table->hold_rmid != CT_INVALID_ID32 && temp_table->table_type == DICT_TYPE_TEMP_TABLE_SESSION) {
            CT_THROW_ERROR(ERR_PL_BEGIN_AUTOTRANS);
            return CT_ERROR;
        }
    }

    if (srv_alloc_auton_rm(session) != CT_SUCCESS) {
        return CT_ERROR;
    }
    knl_set_session_scn(&session->knl_session, CT_INVALID_ID64);
    return CT_SUCCESS;
}

status_t ple_end_auton_rm(session_t *session)
{
    return srv_release_auton_rm(session);
}

void ple_send_error(sql_stmt_t *stmt)
{
    pl_executor_t *executor = (pl_executor_t *)stmt->pl_exec;
    if (executor->err_buf_pos > 0 && (g_tls_error.code != ERR_PL_EXEC ||
        (executor->exec_except.has_exception && executor->exec_except.except.error_code == ERR_PL_EXEC))) {
        cm_reset_error();
        PL_THROW_ERROR(ERR_PL_EXEC, "%s", executor->err_buf);
        executor->err_buf_full = CT_FALSE;
        executor->err_buf_pos = 0;
        executor->err_buf[0] = '\0';
    }
}

void ple_copy_error(pl_executor_t *exec, char *buf, uint32 buf_size)
{
    int iret_snprintf;
    int32 code;
    const char *msg = NULL;
    source_location_t location;

    if (exec->err_buf_pos == 0) {
        cm_get_error(&code, (const char **)&msg, &location);
        if (code == ERR_USER_DEFINED_EXCEPTION) {
            code = ERR_UNHANDLED_USER_EXCEPTION;
            msg = cm_get_errormsg(code);
        }

        if (location.line == 0 && location.column == 0) {
            iret_snprintf = snprintf_s(buf, buf_size, buf_size - 1, "CT-%05d, %s\n", code, msg);
        } else {
            iret_snprintf = snprintf_s(buf, buf_size, buf_size - 1, "[%u:%u] CT-%05d, %s\n", (uint32)location.line,
                (uint32)location.column, code, msg);
        }
        // truncating is possible, it mean err buf is full, cannot be abort
        if (iret_snprintf == -1) {
            exec->err_buf_full = CT_TRUE;
        }
        return;
    }

    iret_snprintf = snprintf_s(buf, buf_size, buf_size - 1, "%s", exec->err_buf);
    if (iret_snprintf == -1) {
        exec->err_buf_full = CT_TRUE;
    }
    return;
}

void ple_set_error(sql_stmt_t *stmt, text_t *user, text_t *name, source_location_t *err_loc)
{
    pl_executor_t *exec = (pl_executor_t *)stmt->pl_exec;
    char message[CT_MESSAGE_BUFFER_SIZE];
    int iret_snprintf;
    if (exec->err_buf_full) {
        return;
    }

    ple_copy_error(exec, message, CT_MESSAGE_BUFFER_SIZE);
    if (exec->err_buf_full == CT_TRUE) {
        return;
    }

    iret_snprintf = snprintf_s(exec->err_buf, CT_MESSAGE_BUFFER_SIZE, CT_MESSAGE_BUFFER_SIZE - 1,
        "[%u:%u] PL/SQL(%s.%s) terminated with execute errors\n%s", err_loc->line, err_loc->column, T2S(user),
        T2S_EX(name), message);
    if (iret_snprintf == -1) {
        exec->err_buf_pos = CT_MESSAGE_BUFFER_SIZE - 1;
        exec->err_buf_full = CT_TRUE;
    } else {
        exec->err_buf_pos = iret_snprintf;
    }
}

void ple_update_error_stack(sql_stmt_t *stmt, text_t *user, text_t *name, source_location_t *err_location)
{
    pl_executor_t *exec = (pl_executor_t *)stmt->pl_exec;
    int32 code;
    source_location_t nested_loc;
    int iret_snprintf;
    char *buf_to_write = NULL;
    uint32 current_max_write;
    const char *msg = NULL;

    if (exec->err_stack_full == CT_TRUE) {
        return;
    }
    cm_get_error(&code, &msg, &nested_loc);
    if (code == ERR_USER_DEFINED_EXCEPTION) {
        code = ERR_UNHANDLED_USER_EXCEPTION;
    }
    buf_to_write = exec->err_stack + exec->err_stack_pos;
    current_max_write = CT_MESSAGE_BUFFER_SIZE - exec->err_stack_pos;
    iret_snprintf = snprintf_s(buf_to_write, current_max_write, current_max_write - 1, "[%u:%u] CT-%05d, %s.%s\n",
        (uint32)err_location->line, (uint32)err_location->column, code, T2S(user), T2S_EX(name));
    if (iret_snprintf == -1) {
        exec->err_buf_full = CT_TRUE;
        exec->err_stack_pos = CT_MESSAGE_BUFFER_SIZE - 1;
    } else {
        exec->err_stack_pos += iret_snprintf;
    }
}

status_t pl_init_sequence(sql_stmt_t *stmt)
{
    uint32 count;
    sql_seq_t *item = NULL;
    pl_entity_t *entity = (pl_entity_t *)stmt->pl_context;

    if (stmt->pl_context == NULL) {
        CT_THROW_ERROR(ERR_INVALID_CURSOR);
        return CT_ERROR;
    }

    count = entity->sequences.count;
    CT_RETURN_IFERR(sql_push(stmt, sizeof(sql_seq_t) * count, (void **)&stmt->v_sequences));

    for (uint32 i = 0; i < count; i++) {
        item = (sql_seq_t *)cm_galist_get(&entity->sequences, i);
        stmt->v_sequences[i].seq = item->seq;
        stmt->v_sequences[i].flags = item->flags;
        stmt->v_sequences[i].processed = CT_FALSE;
        stmt->v_sequences[i].value = 0;
    }

    return CT_SUCCESS;
}

void ple_check_error(sql_stmt_t *stmt)
{
    pl_executor_t *exec = (pl_executor_t *)stmt->pl_exec;
    char message[CT_MESSAGE_BUFFER_SIZE];
    int32 errcode;
    const char *errmsg = NULL;
    source_location_t err_location;

    if (exec->err_buf_full) {
        return;
    }

    cm_get_error(&errcode, &errmsg, &err_location);
    switch (errcode) {
        case ERR_ALLOC_MEMORY:
            ple_copy_error(exec, message, CT_MESSAGE_BUFFER_SIZE);
            cm_reset_error();
            PL_SRC_THROW_ERROR(err_location, ERR_STORAGE_ERROR, "%s\n%s", g_error_desc[ERR_STORAGE_ERROR], message);
            break;

        case ERR_PL_ENTRY_LOCK:
            ple_copy_error(exec, message, CT_MESSAGE_BUFFER_SIZE);
            cm_reset_error();
            PL_SRC_THROW_ERROR(err_location, ERR_RESOURCE_BUSY, "%s\n%s", g_error_desc[ERR_RESOURCE_BUSY], message);
            break;

        default:
            break;
    }
}

void ple_update_exec_error(sql_stmt_t *stmt, source_location_t *err_location)
{
    text_t user, name;
    pl_executor_t *exec = (pl_executor_t *)stmt->pl_exec;
    pl_entity_t *entity = exec->entity;
    char buf[CT_BUFLEN_256];

    if (exec->error_tracked == CT_TRUE) {
        PLE_RESET_EXEC_ERR(exec);
        exec->error_tracked = CT_FALSE;
    }
    if (entity->pl_type == PL_ANONYMOUS_BLOCK) {
        user.str = stmt->session->curr_schema;
        user.len = (uint32)strlen(user.str);
        name.str = "ANONYMOUS BLOCK";
        name.len = (uint32)strlen(name.str);
    } else if (entity->pl_type == PL_PACKAGE_BODY) {
        MEMS_RETVOID_IFERR(strcpy_s(buf, CT_BUFLEN_256, CC_T2S(&exec->obj->user, &exec->obj->pack, '.')));
        cm_str2text(buf, &user);
        name = exec->obj->name;
    } else {
        user = entity->def.user;
        name = entity->def.name;
    }

    ple_check_error(stmt);
    ple_update_error_stack(stmt, &user, &name, err_location);
    ple_set_error(stmt, &user, &name, err_location);
}

void ple_check_exec_error(sql_stmt_t *stmt, source_location_t *err_location)
{
    if (stmt->pl_context == NULL) {
        return;
    }

    pl_executor_t *exec = (pl_executor_t *)stmt->pl_exec;
    if (exec->err_stack_pos > 0 || exec->err_buf_pos > 0) {
        return;
    }
    ple_update_exec_error(stmt, err_location);
}

variant_t *ple_get_plvar_value(ple_var_t *var)
{
    return &var->value;
}

variant_t *ple_get_value(sql_stmt_t *stmt, plv_id_t vid)
{
    pl_executor_t *executor = (pl_executor_t *)stmt->pl_exec;
    ple_var_t *var = ple_get_plvar(executor, vid);
    return ple_get_plvar_value(var);
}

status_t ple_get_output_plvar(pl_executor_t *exec, pl_into_t *into, ple_var_t **left, uint32 index)
{
    expr_node_t *node = (expr_node_t *)cm_galist_get(into->output, index);
    if (node == NULL || node->type != EXPR_NODE_V_ADDR || !sql_pair_type_is_plvar(node)) {
        CT_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "unexpected pl-variant occurs");
        return CT_ERROR;
    }
    var_address_pair_t *pair = (var_address_pair_t *)cm_galist_get(node->value.v_address.pairs, 0);
    *left = ple_get_plvar(exec, pair->stack->decl->vid);
    return CT_SUCCESS;
}

status_t ple_get_dynsql_parent(sql_stmt_t *stmt, sql_stmt_t **parent)
{
    *parent = ((pl_executor_t *)stmt->pl_exec)->dynamic_parent;
    if (*parent == NULL) {
        CT_THROW_ERROR(ERR_PLSQL_ILLEGAL_LINE_FMT, "unexpected param");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

sql_stmt_t *ple_ref_cursor_get(sql_stmt_t *stmt, pl_cursor_slot_t *ref_cursor)
{
    if (ref_cursor == NULL || ref_cursor->state == CUR_RES_FREE || ref_cursor->stmt_id == CT_INVALID_ID16) {
        return NULL;
    }

    sql_stmt_t *tmp_stmt = (sql_stmt_t *)cm_list_get(&stmt->session->stmts, ref_cursor->stmt_id);
    return tmp_stmt;
}

bool32 sql_is_pl_exec(sql_stmt_t *stmt)
{
    do {
        if (stmt->pl_context != NULL) {
            return CT_TRUE;
        }
        if (stmt->parent_stmt != NULL) {
            stmt = (sql_stmt_t *)stmt->parent_stmt;
        } else {
            return CT_FALSE;
        }
    } while (CT_TRUE);
}

status_t pl_check_trig_and_udf(sql_stmt_t *stmt)
{
    sql_stmt_t *check_stmt = NULL;
    pl_executor_t *executor = NULL;
    pl_entity_t *entity = NULL;
    sql_context_t *context = NULL;

    // first stmt must be null or has record executor info
    if (stmt == NULL || stmt->pl_exec == NULL) {
        return CT_SUCCESS;
    }

    // if entity is autonomous trans, it is allowed to use DDL or DCL;
    // if not, trigger must be not allowed to use DDL or DCL, others should check parent stmt if is DML
    executor = (pl_executor_t *)stmt->pl_exec;
    entity = (pl_entity_t *)executor->entity;
    if (entity->is_auton_trans) {
        return CT_SUCCESS;
    } else if (entity->pl_type == PL_TRIGGER) {
        CT_THROW_ERROR(ERR_TRIG_DDL_DCL);
        return CT_ERROR;
    }

    check_stmt = stmt->parent_stmt;
    while (check_stmt != NULL) {
        context = check_stmt->context;
        if (context != NULL && context->type < CTSQL_TYPE_DML_CEIL) {
            CT_THROW_ERROR(ERR_UDF_DDL_DCL);
            return CT_ERROR;
        }

        if (check_stmt->pl_exec != NULL) {
            executor = (pl_executor_t *)check_stmt->pl_exec;
            entity = (pl_entity_t *)executor->entity;
            if (entity->is_auton_trans) {
                return CT_SUCCESS;
            } else if (entity->pl_type == PL_TRIGGER) {
                CT_THROW_ERROR(ERR_TRIG_DDL_DCL);
                return CT_ERROR;
            }
        }
        check_stmt = check_stmt->parent_stmt;
    }
    return CT_SUCCESS;
}

status_t ple_verify_param_as_left(sql_stmt_t *stmt, ple_var_t *left)
{
    sql_param_t *params = NULL;
    params = stmt->param_info.params;

    // If the current stmt is a DML statement and the bind variable cannot be found,
    // go to the anonymous block to find the bind variable.
    if (params == NULL) {
        if (stmt->parent_stmt != NULL) {
            params = ((sql_stmt_t *)stmt->parent_stmt)->param_info.params;
            if (params == NULL) {
                CT_THROW_ERROR(ERR_PLSQL_ILLEGAL_LINE_FMT, "can't find bind variable");
                return CT_ERROR;
            }
        } else {
            CT_THROW_ERROR(ERR_PLSQL_ILLEGAL_LINE_FMT, "can't find bind variable");
            return CT_ERROR;
        }
    }

    if (params[left->decl->param.param_id].direction == PLV_DIR_IN) {
        CT_THROW_ERROR(ERR_PLSQL_ILLEGAL_LINE_FMT, "IN bind variable bound to an OUT position");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t ple_get_param_typmod(sql_stmt_t *stmt, variant_t *value, ple_var_t *dst, typmode_t *typmode)
{
    if (stmt->is_reform_call) {
        *typmode = dst->decl->param.type;
        dst->value.type = typmode->datatype;
    } else {
        *typmode = dst->exec_type;
    }

    if (typmode->datatype == CT_TYPE_UNKNOWN) {
        CT_THROW_ERROR(ERR_INVALID_DATA_TYPE, "param datatype can't be unknown");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t ple_move_value(sql_stmt_t *stmt, variant_t *right, ple_var_t *left)
{
    typmode_t typmode = { 0 };

    switch (left->decl->type) {
        case PLV_COLLECTION:
            return udt_coll_assign(stmt, &left->value, right);
        case PLV_RECORD:
            return udt_record_assign(stmt, &left->value, right);
        case PLV_OBJECT:
            return udt_object_assign(stmt, &left->value, right);
        case PLV_PARAM:
            CT_RETURN_IFERR(ple_verify_param_as_left(stmt, left));
            if (left->value.type == CT_TYPE_RECORD) {
                return udt_record_assign(stmt, &left->value, right);
            } else if (left->value.type == CT_TYPE_OBJECT) {
                return udt_object_assign(stmt, &left->value, right);
            } else if (left->value.type == CT_TYPE_COLLECTION) {
                return udt_coll_assign(stmt, &left->value, right);
            }
            CT_RETURN_IFERR(ple_get_param_typmod(stmt, &left->value, left, &typmode));
            break;
        case PLV_CUR:
        case PLV_VAR:
        case PLV_ARRAY:
            typmode = left->exec_type;
            break;
            /* not support assign operation */
        case PLV_TYPE:
        case PLV_EXCPT:
        case PLV_IMPCUR:
        default:
            CT_THROW_ERROR(ERR_PL_WRONG_TYPE_VALUE, "left declare type", left->decl->type);
            return CT_ERROR;
    }
    return ple_copy_variant(stmt, right, &left->value, typmode);
}

static inline void ple_cursor_add_refcount(sql_stmt_t *stmt, variant_t *var)
{
    if (var->v_cursor.ref_cursor == NULL) {
        return;
    }

    pl_cursor_slot_t *ref_cursor = (pl_cursor_slot_t *)var->v_cursor.ref_cursor;
    if (ref_cursor->state == CUR_RES_FREE) {
        return;
    }

    ref_cursor->ref_count++;
}

// the same as sql_apply_typmode
// when invoke this func, please make sure that src->type, dst->type, type->datatype are same;
static status_t ple_copy_variant_core(sql_stmt_t *stmt, variant_t *src, variant_t *var, typmode_t type)
{
    uint32 blank_count;
    uint32 copy_size, value_len, max_len;

    CT_RETVALUE_IFTRUE(src->is_null, CT_SUCCESS);

    if (type.is_array == CT_TRUE) {
        *var = *src;
        return CT_SUCCESS;
    }

    switch ((ct_type_t)var->type) {
        case CT_TYPE_UINT32:
            VALUE(uint32, var) = VALUE(uint32, src);
            break;
        case CT_TYPE_INTEGER:
            VALUE(int32, var) = VALUE(int32, src);
            break;
        case CT_TYPE_BOOLEAN:
            VALUE(bool32, var) = VALUE(bool32, src);
            break;
        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_NUMBER2:
            cm_dec_copy(VALUE_PTR(dec8_t, var), (const dec8_t *)VALUE_PTR(dec8_t, src));
            CT_RETURN_IFERR(cm_adjust_dec(&var->v_dec, type.precision, type.scale));
            break;
        case CT_TYPE_BIGINT:
            VALUE(int64, var) = VALUE(int64, src);
            break;
        case CT_TYPE_REAL:
            VALUE(double, var) = VALUE(double, src);
            break;
        case CT_TYPE_DATE:
            VALUE(date_t, var) = VALUE(date_t, src);
            break;
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_LTZ:
            VALUE(timestamp_t, var) = VALUE(timestamp_t, src);
            CT_RETURN_IFERR(cm_adjust_timestamp(&var->v_tstamp, type.precision));
            break;

        case CT_TYPE_TIMESTAMP_TZ:
            VALUE(timestamp_tz_t, var) = VALUE(timestamp_tz_t, src);
            CT_RETURN_IFERR(cm_adjust_timestamp_tz(&var->v_tstamp_tz, type.precision));
            break;

        case CT_TYPE_INTERVAL_YM:
            VALUE(interval_ym_t, var) = VALUE(interval_ym_t, src);
            break;

        case CT_TYPE_INTERVAL_DS:
            VALUE(interval_ds_t, var) = VALUE(interval_ds_t, src);
            break;

        case CT_TYPE_STRING:
        case CT_TYPE_VARCHAR:
            // variant is defined char attr
            if (type.is_char) {
                CT_RETURN_IFERR(GET_DATABASE_CHARSET->length(&src->v_text, &value_len));
            } else {
                value_len = src->v_text.len;
            }
            CT_RETURN_IFERR(udt_get_varlen_databuf(type, &max_len));

            if ((value_len > type.size) || (src->v_text.len > max_len)) {
                CT_THROW_ERROR(ERR_VALUE_ERROR, "character string buffer too small");
                return CT_ERROR;
            }

            var->v_text.len = src->v_text.len;
            if (var->v_text.len != 0) {
                MEMS_RETURN_IFERR(memmove_s(var->v_text.str, max_len, src->v_text.str, var->v_text.len));
            }
            break;

        case CT_TYPE_CHAR:
            // variant is defined char attr
            if (type.is_char) {
                CT_RETURN_IFERR(GET_DATABASE_CHARSET->length(&src->v_text, &value_len));
            } else {
                value_len = src->v_text.len;
            }
            CT_RETURN_IFERR(udt_get_varlen_databuf(type, &max_len));

            if ((value_len > type.size) || (src->v_text.len > max_len)) {
                CT_THROW_ERROR(ERR_VALUE_ERROR, "character string buffer too small");
                return CT_ERROR;
            }

            copy_size = src->v_text.len;
            if (src->v_text.len != 0) {
                MEMS_RETURN_IFERR(memmove_s(var->v_text.str, max_len, src->v_text.str, copy_size));
            }
            // (type.size - value_len) is count of need_blank
            // blank_count is count of blank can be supplemented
            blank_count = MIN((src->v_text.len + (type.size - value_len)), max_len) - src->v_text.len;
            if (blank_count > 0) {
                MEMS_RETURN_IFERR(memset_s(var->v_text.str + src->v_text.len, blank_count, ' ', blank_count));
            }
            var->v_text.len = src->v_text.len + blank_count;
            break;

        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
            if (src->v_bin.size > type.size) {
                CT_THROW_ERROR(ERR_VALUE_ERROR, "binary buffer too small");
                return CT_ERROR;
            }

            var->v_bin.size = (src->v_bin.size > type.size) ? type.size : src->v_bin.size;
            if (var->v_bin.size != 0) {
                MEMS_RETURN_IFERR(memmove_s(var->v_bin.bytes, type.size, src->v_bin.bytes, var->v_bin.size));
            }
            break;

        case CT_TYPE_CURSOR:
            ple_cursor_dec_refcount(stmt, var, CT_TRUE);
            *var = *src;
            ple_cursor_add_refcount(stmt, var);
            break;

        case CT_TYPE_CLOB:
        case CT_TYPE_BLOB:
        case CT_TYPE_IMAGE:
            if (src->v_lob.type == CT_LOB_FROM_NORMAL) {
                VALUE(var_lob_t, var) = VALUE(var_lob_t, src);
                break;
            }
            CT_THROW_ERROR(ERR_VALUE_ERROR, "unsupport datatype");
            return CT_ERROR;

        case CT_TYPE_COLUMN:
        case CT_TYPE_BASE:
        default:
            CT_THROW_ERROR(ERR_VALUE_ERROR, "unsupport datatype");
            return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t ple_try_copy_variant(sql_stmt_t *stmt, variant_t *src, variant_t *dst, typmode_t type)
{
    CT_RETVALUE_IFTRUE(src->is_null, CT_SUCCESS);

    if (CT_IS_LOB_TYPE((ct_type_t)src->type)) {
        CT_RETURN_IFERR(udt_get_lob_value(stmt, src));
        CT_RETVALUE_IFTRUE(src->is_null, CT_SUCCESS);
    }

    if (type.is_array == CT_TRUE) {
        CT_RETURN_IFERR(sql_convert_to_array(stmt, src, &type, CT_FALSE));
    } else {
        if (src->type != dst->type) {
            if (dst->type == CT_TYPE_CHAR && !CT_IS_VARLEN_TYPE(src->type)) {
                CT_RETURN_IFERR(sql_convert_variant(stmt, src, dst->type));
                return udt_convert_char(src, dst, type);
            } else {
                CT_RETURN_IFERR(sql_convert_variant(stmt, src, dst->type));
            }
        }
    }

    return ple_copy_variant_core(stmt, src, dst, type);
}

status_t ple_copy_variant(sql_stmt_t *stmt, variant_t *src, variant_t *dst, typmode_t type)
{
    CT_RETURN_IFERR(ple_try_copy_variant(stmt, src, dst, type));
    dst->is_null = src->is_null; // If the copy fails, the dst'is_null should not be modified.
    return CT_SUCCESS;
}

void ple_cursor_dec_refcount(sql_stmt_t *stmt, variant_t *dst, bool32 is_free)
{
    if (dst->v_cursor.ref_cursor == NULL) {
        return;
    }

    pl_cursor_slot_t *ref_cur = (pl_cursor_slot_t *)dst->v_cursor.ref_cursor;
    if (ref_cur->state == CUR_RES_FREE) {
        return;
    }

    if (!is_free) {
        if (ref_cur->ref_count >= 1) {
            ref_cur->ref_count--;
        }
        return;
    }

    if (ref_cur->ref_count <= 1) {
        sql_stmt_t *ref_stmt = ple_ref_cursor_get(stmt, ref_cur);
        if (ref_stmt != NULL) {
            sql_free_stmt(ref_stmt);
            ref_cur->stmt_id = CT_INVALID_ID16;
        }
        ref_cur->state = CUR_RES_FREE;
        ref_cur->ref_count = 0;
        // don't call ple_free_ref_cursor, because we need free stmt.
        return;
    }

    ref_cur->ref_count--;
}

static status_t ple_calc_field_dft_expr(sql_stmt_t *stmt, expr_tree_t *default_expr, uint16 i, variant_t *value)
{
    variant_t default_value;
    if (sql_exec_expr(stmt, default_expr, &default_value) != CT_SUCCESS) {
        cm_try_set_error_loc(TREE_LOC(default_expr));
        return CT_ERROR;
    }

    return udt_record_field_address(stmt, value, i, NULL, &default_value);
}

static status_t ple_calc_record_field_dft(sql_stmt_t *stmt, int8 attr_type, expr_tree_t *default_expr, uint16 i,
    plv_decl_t *udt_field, variant_t *value)
{
    pvm_context_t vm_context = GET_VM_CTX(stmt);
    udt_mtrl_record_head_t *mtrl_head = NULL;
    variant_t temp;

    switch (attr_type) {
        case UDT_RECORD:
            if (default_expr != NULL) {
                CT_RETURN_IFERR(ple_calc_field_dft_expr(stmt, default_expr, i, value));
            } else {
                OPEN_VM_PTR(&value->v_record.value, vm_context);
                mtrl_head = (udt_mtrl_record_head_t *)d_ptr;
                MAKE_REC_VAR(&temp, udt_field, mtrl_head->field[i].rowid);
                if (ple_calc_record_dft(stmt, UDT_GET_TYPE_DEF_RECORD(udt_field), &temp) != CT_SUCCESS) {
                    CLOSE_VM_PTR_EX(&value->v_record.value, vm_context);
                    return CT_ERROR;
                }
                CLOSE_VM_PTR(&value->v_record.value, vm_context);
            }
            break;
        case UDT_SCALAR:
        case UDT_COLLECTION:
        case UDT_OBJECT:
            if (default_expr != NULL) {
                CT_RETURN_IFERR(ple_calc_field_dft_expr(stmt, default_expr, i, value));
            }
            break;
        default:
            CT_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "unexpect attr type");
            return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t ple_calc_object_dft(sql_stmt_t *stmt, plv_object_t *plv_obj, variant_t *value)
{
    plv_object_attr_t *attr = NULL;
    expr_tree_t *default_expr = NULL;

    for (uint16 i = 0; i < plv_obj->count; i++) {
        attr = udt_seek_obj_field_byid(plv_obj, i);
        default_expr = attr->default_expr;
        CT_RETURN_IFERR(ple_calc_record_field_dft(stmt, attr->type, default_expr, i, attr->udt_field, value));
    }
    return CT_SUCCESS;
}

status_t ple_calc_record_dft(sql_stmt_t *stmt, plv_record_t *plv_record, variant_t *value)
{
    plv_record_attr_t *attr = NULL;
    expr_tree_t *default_expr = NULL;

    for (uint16 i = 0; i < plv_record->count; i++) {
        attr = udt_seek_field_by_id(plv_record, i);
        default_expr = attr->default_expr;
        CT_RETURN_IFERR(ple_calc_record_field_dft(stmt, attr->type, default_expr, i, attr->udt_field, value));
    }
    return CT_SUCCESS;
}

status_t ple_calc_dft(sql_stmt_t *stmt, ple_var_t *var)
{
    variant_t default_value;

    if (sql_exec_expr(stmt, PLE_DEFAULT_EXPR(var), &default_value) != CT_SUCCESS) {
        cm_try_set_error_loc(PLE_DEFAULT_EXPR(var)->root->loc);
        return CT_ERROR;
    }

    if (ple_move_value(stmt, &default_value, var) != CT_SUCCESS) {
        cm_try_set_error_loc(PLE_DEFAULT_EXPR(var)->root->loc);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t ple_move_param_value(sql_stmt_t *stmt, variant_t *value, ple_var_t *param)
{
    typmode_t type;
    if (param->decl->type != PLV_PARAM) {
        type = param->exec_type;
    } else {
        CT_RETURN_IFERR(ple_verify_param_as_left(stmt, param));
        CT_RETURN_IFERR(ple_get_param_typmod(stmt, value, param, &type));
    }

    return ple_copy_variant(stmt, value, &param->value, type);
}

status_t ple_calc_param_dft(sql_stmt_t *stmt, ple_var_t *var)
{
    sql_param_t *param = &stmt->param_info.params[var->decl->param.param_id];
    if (param->direction == (uint8)PLV_DIR_IN) {
        var_copy(&param->value, &var->value);
        return CT_SUCCESS;
    }

    if (param->direction == (uint8)PLV_DIR_INOUT) {
        CT_RETURN_IFERR(ple_move_param_value(stmt, &param->value, var));
        param->out_value = &var->value;
        return CT_SUCCESS;
    }

    if (param->direction == (uint8)PLV_DIR_OUT) {
        param->out_value = &var->value;
    }
    return CT_SUCCESS;
}

static ct_type_t ple_data_type(ple_var_t *var)
{
    switch (var->decl->type) {
        case PLV_CUR:
            return CT_TYPE_CURSOR;
        case PLV_RECORD:
            return CT_TYPE_RECORD;
        case PLV_OBJECT:
            return CT_TYPE_OBJECT;
        case PLV_COLLECTION:
            return CT_TYPE_COLLECTION;
        default:
            return var->exec_type.datatype;
    }
}

static status_t ple_push_decl_base(sql_stmt_t *stmt, ple_varmap_t *var_map, plv_decl_t *decl, ple_var_t **res)
{
    ple_var_t *var = NULL;

    CT_RETURN_IFERR(sql_push(stmt, sizeof(ple_var_t), (void **)&var));
    var->decl = decl;
    var->exec_type = decl->variant.type;
    var->value.is_null = CT_TRUE;
    var->value.type = ple_data_type(var);
    var_map->items[var_map->count] = var;
    var_map->count++;
    *res = var;
    return CT_SUCCESS;
}

/*
 * ple_push_var
 *
 * This function is used to alloc memory for var from stack.
 */
static status_t ple_push_var(sql_stmt_t *stmt, ple_varmap_t *var_map, plv_decl_t *decl, bool32 calc_dft)
{
    ple_var_t *var = NULL;
    variant_t default_value;
    uint32 max_len;

    CT_RETURN_IFERR(ple_push_decl_base(stmt, var_map, decl, &var));

    // variable length type
    if (CT_IS_VARLEN_TYPE(var->value.type)) {
        CT_RETURN_IFERR(udt_get_varlen_databuf(var->exec_type, &max_len));
        CT_RETURN_IFERR(sql_push(stmt, max_len, (void **)&var->value.v_text.str));
    }

    // default value specified
    if (calc_dft && (var->decl->type == PLV_VAR || var->decl->type == PLV_ARRAY) && PLE_DEFAULT_EXPR(var) != NULL) {
        if (sql_exec_expr(stmt, PLE_DEFAULT_EXPR(var), &default_value) != CT_SUCCESS) {
            cm_try_set_error_loc(var->decl->loc);
            return CT_ERROR;
        }

        CT_RETURN_IFERR(ple_move_value(stmt, &default_value, var));
    }

    return CT_SUCCESS;
}

static status_t ple_push_param_record(sql_stmt_t *stmt, ple_var_t *var, ple_var_t *refer)
{
    plv_record_t *record = (plv_record_t *)refer->value.v_record.record_meta;
    var->value.v_record.count = refer->value.v_record.count;
    var->value.v_record.is_constructed = CT_FALSE;
    var->value.v_record.record_meta = refer->value.v_record.record_meta;
    CT_RETURN_IFERR(udt_record_alloc_mtrl_head(stmt, record, &var->value.v_record.value));
    var->value.is_null = CT_FALSE;
    return CT_SUCCESS;
}

static void ple_push_param_object(sql_stmt_t *stmt, ple_var_t *var, ple_var_t *refer)
{
    var->value.v_object.count = refer->value.v_object.count;
    var->value.v_object.is_constructed = CT_FALSE;
    var->value.v_object.object_meta = refer->value.v_object.object_meta;
    var->value.v_object.value = g_invalid_entry;
}

static void ple_push_param_collection(sql_stmt_t *stmt, ple_var_t *var, ple_var_t *refer)
{
    var->value.v_collection.type = refer->value.v_collection.type;
    var->value.v_collection.value = g_invalid_entry;
    var->value.v_collection.coll_meta = refer->value.v_collection.coll_meta;
    var->value.v_collection.is_constructed = CT_FALSE;
}

static status_t ple_get_param_var(sql_stmt_t *stmt, pl_executor_t *exec, uint32 pnid, bool32 flag, ple_var_t **result)
{
    if (exec->dynamic_parent == NULL) {
        return CT_SUCCESS;
    }

    sql_stmt_t *parent = exec->dynamic_parent;
    pl_using_expr_t *using_expr = NULL;
    CT_RETURN_IFERR(ple_get_dynsql_using_expr(parent, pnid, &using_expr));
    CT_RETURN_IFERR(ple_get_using_expr_var(parent, using_expr, result, flag));
    return CT_SUCCESS;
}

static status_t ple_push_param(sql_stmt_t *stmt, ple_varmap_t *var_map, plv_decl_t *decl, bool32 calc_dft)
{
    ple_var_t *var = NULL;
    uint32 max_len;

    CT_RETURN_IFERR(ple_push_decl_base(stmt, var_map, decl, &var));
    if (stmt->plsql_mode == PLSQL_STATIC || stmt->plsql_mode == PLSQL_DYNSQL) {
        return CT_SUCCESS;
    }

    sql_param_t *param = &stmt->param_info.params[decl->param.param_id];
    if (param->direction == (uint8)PLV_DIR_IN) {
        return CT_SUCCESS;
    }

    if (stmt->plsql_mode == PLSQL_DYNBLK) {
        ple_var_t *refer = NULL;
        CT_RETURN_IFERR(ple_get_param_var(stmt, stmt->pl_exec, decl->pnid, PLE_CHECK_OUT, &refer));
        var->exec_type = refer->exec_type; // USING using_expr var
        var->value.type = refer->value.type;
        if (var->value.type == CT_TYPE_RECORD) {
            CT_RETURN_IFERR(ple_push_param_record(stmt, var, refer));
        } else if (var->value.type == CT_TYPE_COLLECTION) {
            ple_push_param_collection(stmt, var, refer);
        } else if (var->value.type == CT_TYPE_OBJECT) {
            ple_push_param_object(stmt, var, refer);
        }
    }

    if (var->value.type == CT_TYPE_UNKNOWN) {
        variant_t value;
        CT_RETURN_IFERR(sql_get_param_value(stmt, decl->param.param_id, &value));
        // call proc the param type determinated in verify phase, others according as param's value
        udt_typemode_default_init(&var->exec_type, &value);
        var->value.type = value.type;
    }
    // variable length type
    if (CT_IS_VARLEN_TYPE(var->value.type)) {
        CT_RETURN_IFERR(udt_get_varlen_databuf(var->exec_type, &max_len));
        CT_RETURN_IFERR(sql_push(stmt, max_len, (void **)&var->value.v_text.str));
    }

    if (var->value.type == CT_TYPE_CURSOR) {
        var->value.v_cursor.ref_cursor = NULL;
        var->value.v_cursor.input = NULL;
    }

    return CT_SUCCESS;
}

static status_t ple_push_cursor_var(sql_stmt_t *stmt, ple_varmap_t *var_map, plv_decl_t *decl)
{
    ple_var_t *var = NULL;
    CT_RETURN_IFERR(ple_push_decl_base(stmt, var_map, decl, &var));
    var->value.is_null = CT_TRUE;
    var->value.v_cursor.ref_cursor = NULL;
    var->value.v_cursor.input = NULL;
    return CT_SUCCESS;
}

static status_t ple_push_collection_var(sql_stmt_t *stmt, ple_varmap_t *var_map, plv_decl_t *decl)
{
    ple_var_t *var = NULL;
    pl_entity_t *entity = NULL;
    CT_RETURN_IFERR(ple_push_decl_base(stmt, var_map, decl, &var));
    if (decl->collection->is_global) {
        entity = (pl_entity_t *)decl->collection->root;
        CT_RETURN_IFERR(sql_check_exec_type_priv(stmt, &entity->def.user, &entity->def.name));
    }
    var->value.v_collection.type = decl->collection->type;
    var->value.v_collection.coll_meta = (void *)decl->collection;
    var->value.v_collection.is_constructed = CT_FALSE;
    var->value.v_collection.value = g_invalid_entry;

    if (var->value.v_collection.type == UDT_HASH_TABLE) {
        CT_RETURN_IFERR(udt_hash_table_init_var(stmt, &var->value));
    }
    return CT_SUCCESS;
}

static status_t ple_push_record_var(sql_stmt_t *stmt, ple_varmap_t *var_map, plv_decl_t *decl)
{
    ple_var_t *var = NULL;
    var_record_t *v_record = NULL;
    CT_RETURN_IFERR(ple_push_decl_base(stmt, var_map, decl, &var));

    v_record = &var->value.v_record;
    v_record->record_meta = (void *)decl->record;
    v_record->count = decl->record->count;
    CT_RETURN_IFERR(udt_record_alloc_mtrl_head(stmt, decl->record, &v_record->value));
    var->value.is_null = CT_FALSE;
    var->value.v_record.is_constructed = CT_FALSE;
    return CT_SUCCESS;
}

static status_t ple_push_object_var(sql_stmt_t *stmt, ple_varmap_t *var_map, plv_decl_t *decl)
{
    ple_var_t *var = NULL;
    udt_var_object_t *v_object = NULL;
    pl_entity_t *entity = NULL;

    CT_RETURN_IFERR(ple_push_decl_base(stmt, var_map, decl, &var));

    v_object = &var->value.v_object;
    v_object->object_meta = (void *)decl->object;
    v_object->count = decl->object->count;
    v_object->value = g_invalid_entry;

    entity = (pl_entity_t *)decl->collection->root;
    CT_RETURN_IFERR(sql_check_exec_type_priv(stmt, &entity->def.user, &entity->def.name));
    var->value.v_object.is_constructed = CT_FALSE;
    return CT_SUCCESS;
}

status_t ple_push_decl_element(sql_stmt_t *stmt, galist_t *decl_list, ple_varmap_t *var_map, bool32 calc_dft)
{
    uint32 i;
    plv_decl_t *decl = NULL;

    for (i = 0; i < decl_list->count; i++) {
        decl = cm_galist_get(decl_list, i);

        switch (decl->type) {
            case PLV_VAR:   // variant
            case PLV_ARRAY: // ARRAY
            case PLV_EXCPT: // EXCEPTION
                CT_RETURN_IFERR(ple_push_var(stmt, var_map, decl, calc_dft));
                break;
            case PLV_PARAM: // PARAMETER
                CT_RETURN_IFERR(ple_push_param(stmt, var_map, decl, calc_dft));
                break;
            case PLV_CUR:    // CURSOR
            case PLV_IMPCUR: // implicit CURSOR
                CT_RETURN_IFERR(ple_push_cursor_var(stmt, var_map, decl));
                break;

            case PLV_RECORD: // RECORD
                CT_RETURN_IFERR(ple_push_record_var(stmt, var_map, decl));
                break;

            case PLV_OBJECT: // OBJECT
                CT_RETURN_IFERR(ple_push_object_var(stmt, var_map, decl));
                break;

            case PLV_COLLECTION:
                CT_RETURN_IFERR(ple_push_collection_var(stmt, var_map, decl));
                break;

            case PLV_TYPE: // TYPE DEFINITION
            default:
                var_map->items[i] = NULL;
                var_map->count++;
                break;
        }
    }

    return CT_SUCCESS;
}

status_t ple_get_dynsql_using_expr(sql_stmt_t *stmt, uint32 pnid, pl_using_expr_t **using_expr)
{
    pl_executor_t *exec = stmt->pl_exec;
    pl_line_execute_t *line = ((pl_line_execute_t *)exec->curr_line);
    if (line->ctrl.type != LINE_EXECUTE) {
        CT_SRC_THROW_ERROR(line->ctrl.loc, ERR_PLSQL_ILLEGAL_LINE_FMT, "unexpected param");
        return CT_ERROR;
    }
    if (line->using_exprs == NULL || pnid >= line->using_exprs->count) {
        CT_SRC_THROW_ERROR(line->ctrl.loc, ERR_PROGRAM_ERROR_FMT,
            "The param count of dynamic sql is not same as the param count of using clause");
        return CT_ERROR;
    }
    *using_expr = (pl_using_expr_t *)cm_galist_get(line->using_exprs, pnid);
    return CT_SUCCESS;
}

static status_t ple_check_dynsql_type(plv_decl_t *decl)
{
    if ((decl->type == PLV_COLLECTION && !decl->collection->is_global) || decl->type == PLV_RECORD) {
        CT_THROW_ERROR(ERR_PLSQL_ILLEGAL_LINE_FMT, "out parameter have to be of SQL types");
        return CT_ERROR;
    }

    if (decl->type == PLV_COLLECTION && decl->collection->type == UDT_NESTED_TABLE) {
        CT_THROW_ERROR(ERR_PLSQL_ILLEGAL_LINE_FMT, "unexpected out parameter type");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t ple_check_dynsql_pos(plv_direction_t dir, uint32 flag, text_t *name)
{
    if ((flag & PLE_CHECK_IN) && (dir == PLV_DIR_OUT)) {
        CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "OUT bind variable bound to an IN position");
        return CT_ERROR;
    }

    if ((flag & PLE_CHECK_OUT) && (dir == PLV_DIR_IN)) {
        CT_THROW_ERROR(ERR_PL_EXPR_AS_LEFT_FMT, T2S(name));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t ple_get_using_expr_var(sql_stmt_t *stmt, pl_using_expr_t *using_expr, ple_var_t **var, uint32 flag)
{
    pl_executor_t *exec = stmt->pl_exec;
    expr_tree_t *expr = using_expr->expr;

    if (expr->root->type == EXPR_NODE_V_ADDR) {
        if (!sql_pair_type_is_plvar(expr->root)) {
            CT_THROW_ERROR(ERR_PLSQL_ILLEGAL_LINE_FMT, "unexpected param");
            return CT_ERROR;
        }
        var_address_pair_t *pair = (var_address_pair_t *)cm_galist_get(expr->root->value.v_address.pairs, 0);
        ple_var_t *pl_var = ple_get_plvar(exec, pair->stack->decl->vid);
        *var = pl_var;
        if (using_expr->dir != PLV_DIR_IN) {
            CT_RETURN_IFERR(ple_check_dynsql_type(pl_var->decl));
        }
        return ple_check_dynsql_pos(using_expr->dir, flag, &pl_var->decl->name);
    } else {
        CT_THROW_ERROR(ERR_PLSQL_ILLEGAL_LINE_FMT, "unexpected param");
        return CT_ERROR;
    }
}

status_t ple_get_using_expr_value(sql_stmt_t *stmt, pl_using_expr_t *using_expr, variant_t *res, uint32 flag)
{
    pl_executor_t *exec = stmt->pl_exec;
    expr_tree_t *expr = using_expr->expr;
    variant_t *value = NULL;
    ple_var_t *pl_var = NULL;

    if (expr->root->type == EXPR_NODE_V_ADDR) {
        if (!sql_pair_type_is_plvar(expr->root)) {
            return sql_exec_expr(stmt, using_expr->expr, res);
        }
        var_address_pair_t *pair = (var_address_pair_t *)cm_galist_get(expr->root->value.v_address.pairs, 0);
        pl_var = ple_get_plvar(exec, pair->stack->decl->vid);
        value = ple_get_plvar_value(pl_var);
        if (ple_check_dynsql_pos(using_expr->dir, flag, &pl_var->decl->name) != CT_SUCCESS) {
            return CT_ERROR;
        }
        var_copy(value, res);
        return CT_SUCCESS;
    } else {
        return sql_exec_expr(stmt, using_expr->expr, res);
    }
}

status_t ple_get_dynsql_param_dir(sql_stmt_t *stmt, uint32 id, uint32 *dir)
{
    sql_stmt_t *parent = NULL;
    pl_using_expr_t *using_expr = NULL;

    if (ple_get_dynsql_parent(stmt, &parent) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (ple_get_dynsql_using_expr(parent, id, &using_expr) != CT_SUCCESS) {
        return CT_ERROR;
    }
    *dir = (uint32)using_expr->dir;

    return CT_SUCCESS;
}

static status_t ple_get_dynblk_param(sql_stmt_t *stmt, uint32 id, variant_t *value)
{
    if (stmt->param_info.params[id].direction == CT_INPUT_PARAM) {
        var_copy(&stmt->param_info.params[id].value, value);
    } else if (stmt->param_info.params[id].direction == CT_OUTPUT_PARAM) {
        CT_THROW_ERROR(ERR_PLSQL_ILLEGAL_LINE_FMT, "OUT bind variable bound to an IN position");
        return CT_ERROR;
    } else {
        var_copy(stmt->param_info.params[id].out_value, value);
    }
    return CT_SUCCESS;
}

static status_t ple_get_dynsql_param(sql_stmt_t *stmt, uint32 id, variant_t *result, uint32 flag)
{
    sql_stmt_t *parent = NULL;
    pl_using_expr_t *using_expr = NULL;

    if (ple_get_dynsql_parent(stmt, &parent) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (ple_get_dynsql_using_expr(parent, id, &using_expr) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return ple_get_using_expr_value(parent, using_expr, result, flag);
}

static status_t ple_get_cursor_rowid(sql_stmt_t *stmt, plv_id_t vid, variant_t *result)
{
    rowid_t row_id;
    variant_t *var = ple_get_value(stmt, vid);
    sql_stmt_t *cur_stmt = ple_ref_cursor_get(stmt, (pl_cursor_slot_t *)var->v_cursor.ref_cursor);

    if (cur_stmt == NULL) {
        CT_THROW_ERROR(ERR_INVALID_CURSOR);
        return CT_ERROR;
    }

    if (cur_stmt->cursor_stack.depth == 0) {
        CT_THROW_ERROR(ERR_NO_DATA_FOUND);
        return CT_ERROR;
    }

    sql_cursor_t *sql_cursor = CTSQL_CURR_CURSOR(cur_stmt);

    if (sql_cursor->table_count == 0) {
        CT_THROW_ERROR(ERR_PLSQL_VALUE_ERROR_FMT, "no table for update");
        return CT_ERROR;
    }

    if (sql_cursor->table_count > 1) {
        CT_THROW_ERROR(ERR_PLSQL_VALUE_ERROR_FMT, "mutiple tables update is not allowed");
        return CT_ERROR;
    }

    result->type = CT_TYPE_STRING;
    result->is_null = CT_FALSE;
    row_id = sql_cursor->tables[0].knl_cur->rowid;
    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROWID_BUFLEN, (void **)&result->v_text.str));
    sql_rowid2str(&row_id, result, sql_cursor->tables[0].knl_cur->dc_type);
    CTSQL_POP(stmt);

    return CT_SUCCESS;
}

static status_t ple_get_input_value(sql_stmt_t *stmt, galist_t *input, uint32 id, variant_t *res)
{
    pl_executor_t *exec = (pl_executor_t *)stmt->pl_exec;
    expr_node_t *node = (expr_node_t *)cm_galist_get(input, id);
    if (node == NULL || node->type != EXPR_NODE_V_ADDR) {
        CT_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "unexpected pl-variant occurs");
        return CT_ERROR;
    }

    if (!sql_pair_type_is_plvar(node)) {
        return sql_exec_expr_node(stmt, node, res);
    }
    var_address_pair_t *pair = (var_address_pair_t *)cm_galist_get(node->value.v_address.pairs, 0);
    plv_id_t vid = pair->stack->decl->vid;
    if (vid.is_rowid) {
        return ple_get_cursor_rowid(stmt, vid, res);
    }
    ple_var_t *var = ple_get_plvar(exec, vid);
    variant_t *value = NULL;
    if (var->decl->type == PLV_PARAM) {
        // both can get input value in params of stmt
        sql_param_t *param = &stmt->param_info.params[var->decl->param.param_id];
        value = &param->value;
        if (param->direction == PLV_DIR_OUT) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "OUT bind variable bound to an IN position");
            return CT_ERROR;
        }
    } else {
        value = ple_get_plvar_value(var);
    }
    if (CM_IS_PLV_UDT_DATATYPE(var->decl->type)) {
        *res = *value;
    } else {
        var_copy(value, res);
    }

    return CT_SUCCESS;
}

status_t ple_get_param_value(sql_stmt_t *stmt, uint32 param_id, uint32 pnid, variant_t *res)
{
    pl_executor_t *exec = stmt->pl_exec;
    galist_t *input = NULL;

    switch (stmt->plsql_mode) {
        case PLSQL_CURSOR:
            var_copy(&stmt->param_info.params[param_id].value, res);
            return CT_SUCCESS;
        case PLSQL_DYNBLK:
            return ple_get_dynblk_param(stmt, param_id, res);
        case PLSQL_DYNSQL:
            return ple_get_dynsql_param(stmt, param_id, res, PLE_CHECK_IN);
        default: // PLSQL_STATIC
            input = ((pl_line_sql_t *)exec->curr_line)->input;
            return ple_get_input_value(stmt, input, pnid, res);
    }
}

bool32 ple_get_curr_except(pl_executor_t *exec, pl_exec_exception_t **curr_except)
{
    ple_block_t *curr_block = NULL;
    pl_line_ctrl_t *curr_line = NULL;
    uint16 curr_depth = exec->block_stack.depth;
    while (curr_depth > exec->stack_base) {
        curr_block = (exec->block_stack.items[curr_depth - 1]); // not overflow
        curr_line = curr_block->entry;
        if (curr_line->type == LINE_BEGIN && curr_block->curr_except && curr_block->curr_except->has_exception) {
            *curr_except = curr_block->curr_except;
            return CT_TRUE;
        }
        curr_depth--;
    }
    return CT_FALSE;
}

void ple_save_stack_anchor(sql_stmt_t *stmt, ple_stack_anchor_t *anchor)
{
#ifdef TEST_MEM
    anchor->stack_depth = stmt->session->stack->push_depth;
#endif // TEST_MEM
    anchor->heap_offset = stmt->session->stack->heap_offset;
    anchor->push_offset = stmt->session->stack->push_offset;
}

status_t ple_push_block(sql_stmt_t *stmt, pl_line_ctrl_t *entry, ple_varmap_t *var_map, ple_stack_anchor_t anchor)
{
    pl_executor_t *exec = (pl_executor_t *)stmt->pl_exec;
    ple_block_t *ple_block = NULL;

    if (exec->block_stack.depth >= PLE_MAX_BLOCK_DEPTH) {
        CT_THROW_ERROR(ERR_EXECUTER_STACK_OVERFLOW);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_push(stmt, sizeof(ple_block_t), (void **)&ple_block));

    exec->block_stack.items[exec->block_stack.depth] = ple_block;
    ple_block->anchor = anchor;
    ple_block->entry = entry;
    ple_block->curr_except = NULL;
    exec->block_stack.depth++;

    if (var_map == NULL) {
        ple_block->var_map.count = 0;
        ple_block->var_map.items = NULL;
    } else {
        ple_block->var_map = *var_map;
    }

    return CT_SUCCESS;
}

void ple_close_cursor(sql_stmt_t *stmt, pl_cursor_slot_t *ref_cursor)
{
    sql_free_stmt(stmt);
    ref_cursor->stmt_id = CT_INVALID_ID16;
}

status_t ple_check_rollback(pl_executor_t *exec, text_t *svpt, source_location_t *loc)
{
    uint32 i;
    text_t *svpt_name = NULL;
    for (i = 0; i < exec->svpts.count; i++) {
        svpt_name = (text_t *)sql_array_get(&exec->svpts, i);
        if (cm_text_equal(svpt_name, svpt)) {
            break;
        }
    }
    if (i == exec->svpts.count) {
        CT_THROW_ERROR_TRY_SRC(loc, ERR_PL_ROLLBACK_EXCEED_SCOPE, T2S(svpt));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t ple_store_savepoint(sql_stmt_t *stmt, pl_executor_t *exec, text_t *svpt)
{
    uint32 i;
    text_t *svpt_name = NULL;
    text_t *save = NULL;
    for (i = 0; i < exec->svpts.count; i++) {
        svpt_name = (text_t *)sql_array_get(&exec->svpts, i);
        if (cm_text_equal(svpt_name, svpt)) {
            break;
        }
    }
    if (i == exec->svpts.count) {
        CT_RETURN_IFERR(vmc_alloc(&stmt->vmc, sizeof(text_t), (void **)&save));
        save->len = svpt->len;
        CT_RETURN_IFERR(vmc_alloc(&stmt->vmc, svpt->len, (void **)&save->str));
        MEMS_RETURN_IFERR(memcpy_sp(save->str, svpt->len, svpt->str, svpt->len));
        CT_RETURN_IFERR(sql_array_put(&exec->svpts, save));
    }
    return CT_SUCCESS;
}

status_t ple_fork_stmt(sql_stmt_t *stmt, sql_stmt_t **sub_stmt)
{
    // PUSH stack will release by ple_exec_dynamic_sql
    CT_RETURN_IFERR(sql_push(stmt, sizeof(sql_stmt_t), (void **)sub_stmt));
    sql_init_stmt(stmt->session, *sub_stmt, stmt->id);
    (*sub_stmt)->session->sender = &g_instance->sql.pl_sender;
    (*sub_stmt)->context = NULL;
    (*sub_stmt)->session->current_stmt = (*sub_stmt);
    (*sub_stmt)->status = stmt->status;
    (*sub_stmt)->is_verifying = stmt->is_verifying;
    (*sub_stmt)->pl_exec = stmt->pl_exec;
    (*sub_stmt)->is_srvoutput_on = stmt->is_srvoutput_on;
    (*sub_stmt)->is_sub_stmt = CT_TRUE;
    (*sub_stmt)->pl_ref_entry = stmt->pl_ref_entry;
    (*sub_stmt)->param_info.params = stmt->param_info.params;
    (*sub_stmt)->parent_stmt = stmt;
    (*sub_stmt)->cursor_info.type = PL_FORK_CURSOR;
    (*sub_stmt)->vm_ctx = stmt->vm_ctx;
    (*sub_stmt)->resource_inuse = CT_TRUE;
    (*sub_stmt)->session->switched_schema = stmt->session->switched_schema;
    (*sub_stmt)->sync_scn = stmt->sync_scn;
    (*sub_stmt)->trace_disabled = stmt->trace_disabled;
#ifdef Z_SHARDING
    if (IS_COORDINATOR) {
        (*sub_stmt)->gts_scn = stmt->gts_scn;
    }
#endif

    return CT_SUCCESS;
}

status_t ple_fork_executor_core(sql_stmt_t *stmt, sql_stmt_t *sub_stmt)
{
    pl_executor_t *sub_exec = NULL;

    CT_RETURN_IFERR(sql_push(stmt, sizeof(pl_executor_t), (void **)&sub_exec));
    if (ple_init_executor(sub_exec, stmt) != CT_SUCCESS) {
        CTSQL_POP(stmt);
        return CT_ERROR;
    }
    sub_stmt->pl_exec = sub_exec;

    return CT_SUCCESS;
}

static status_t ple_stack_alloc(void *owner, uint32 size, void **ptr)
{
    uint32 actual_size;
    cm_stack_t *stack;

    stack = (cm_stack_t *)owner;
    actual_size = size; // !!important, it can't alloc align 8-bytes

    if ((uint64)stack->heap_offset + actual_size + CT_MIN_KERNEL_RESERVE_SIZE >= stack->push_offset) {
        CT_THROW_ERROR(ERR_STACK_OVERFLOW);
        return CT_ERROR;
    }

    *ptr = STACK_ALLOC_ADDR(stack);
    stack->heap_offset += actual_size;
    return CT_SUCCESS;
}


static inline status_t ple_prepare_vbuf(vbuf_assist_t *va, uint32 size, void **buf)
{
    *(va->total_len) = *(va->total_len) + size;
    CT_RETURN_IFERR(ple_stack_alloc(va->stmt->session->stack, size, buf));
    return CT_SUCCESS;
}

static inline status_t ple_put_vtext(vbuf_assist_t *va, text_t *text)
{
    char *buf = NULL;
    uint32 size = sizeof(uint32) + CM_ALIGN4(text->len);
    *(va->total_len) = *(va->total_len) + size;
    CT_RETURN_IFERR(ple_stack_alloc(va->stmt->session->stack, size, (void **)&buf));
    *(uint32 *)buf = text->len;
    buf += sizeof(uint32);
    if (text->len > 0) {
        MEMS_RETURN_IFERR(memcpy_s(buf, text->len, text->str, text->len));
    }
    return CT_SUCCESS;
}

static status_t ple_put_input_value_core(sql_stmt_t *stmt, vbuf_assist_t *va, variant_t *value)
{
    char *buf = NULL;
    char num_buf[CT_MAX_NUMBER_LEN];
    text_t num_text;

    switch (value->type) {
        case CT_TYPE_BIGINT:
            CT_RETURN_IFERR(ple_prepare_vbuf(va, sizeof(int64), (void **)&buf));
            *(int64 *)buf = value->v_bigint;
            break;

        case CT_TYPE_INTEGER:
        case CT_TYPE_BOOLEAN:
            CT_RETURN_IFERR(ple_prepare_vbuf(va, sizeof(int32), (void **)&buf));
            *(int32 *)buf = value->v_int;
            break;

        case CT_TYPE_REAL:
            CT_RETURN_IFERR(ple_prepare_vbuf(va, sizeof(double), (void **)&buf));
            *(double *)buf = value->v_real;
            break;

        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_LTZ:
            CT_RETURN_IFERR(ple_prepare_vbuf(va, sizeof(date_t), (void **)&buf));
            *(date_t *)buf = value->v_date;
            break;

        case CT_TYPE_STRING:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_CHAR:
        case CT_TYPE_BINARY:    // binary type can put as text
        case CT_TYPE_VARBINARY: // varbinary type can put as text
        case CT_TYPE_RAW:       // raw type can put as text
            CT_RETURN_IFERR(ple_put_vtext(va, &value->v_text));
            stmt->param_info.param_strsize += value->v_text.len;
            break;

        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_NUMBER2:
            num_text.str = num_buf;
            CT_RETURN_IFERR(cm_dec_to_text(&value->v_dec, CT_MAX_DEC_OUTPUT_ALL_PREC, &num_text));
            CT_RETURN_IFERR(ple_put_vtext(va, &num_text));
            stmt->param_info.param_strsize += num_text.len;
            break;

        default:
            CT_THROW_ERROR(ERR_VALUE_ERROR, "unsupport datatype");
            return CT_ERROR;
    }
    return CT_SUCCESS;
}


static status_t ple_put_input_value(sql_stmt_t *stmt, vbuf_assist_t *va, variant_t *value)
{
    uint8 *param_flag = (uint8 *)(stmt->param_info.param_buf + sizeof(uint32));
    param_flag[va->id] = 0;
    if (value->is_null) {
        param_flag[va->id] |= CT_COLUMN_FLAG_NULLABLE;
        return CT_SUCCESS;
    }

    return ple_put_input_value_core(stmt, va, value);
}

static status_t ple_keep_input_cursor(sql_stmt_t *stmt, void *input, vbuf_assist_t *vbuf_ass,
                                      bool8 is_dyncur, uint32 count)
{
    expr_node_t *node = NULL;
    variant_t cache;
    variant_t *val = NULL;
    expr_tree_t *expr = NULL;
    sql_stmt_t *parent_stmt = NULL;

    CM_ASSERT(stmt->parent_stmt != NULL);
    parent_stmt = (sql_stmt_t *)stmt->parent_stmt;
    // Cursor's stmt and outer PL stmt is mutually independent. When passing binding params from pl to cursor clause,
    // we need pass the outer vm_ctx into cursor query because complex variants are stored on it.
    for (uint32 i = 0; i < count; i++) {
        if (is_dyncur) {
            expr = cm_galist_get((galist_t *)input, i);
            CT_RETURN_IFERR(sql_exec_expr(parent_stmt, expr, &cache));
            val = &cache;
        } else {
            node = (expr_node_t *)cm_galist_get((galist_t *)input, i);
            CT_RETURN_IFERR(sql_exec_expr_node(parent_stmt, node, &cache));
            val = &cache;
        }
        vbuf_ass->id = i;

        CT_RETURN_IFERR(ple_put_input_value(stmt, vbuf_ass, val));
        stmt->param_info.param_types[i] =
            (val->type == CT_TYPE_UNKNOWN) ? CT_TYPE_UNKNOWN : (val->type - CT_TYPE_BASE);
    }
    return CT_SUCCESS;
}


static status_t ple_keep_input_core(sql_stmt_t *stmt, pl_executor_t *exec, void *input, bool8 is_dyncur)
{
    vbuf_assist_t vbuf_ass;
    uint32 count = ((galist_t *)input)->count;

    CT_RETSUC_IFTRUE(count == 0);
    vbuf_ass.stmt = stmt;
    // reform by CS_VERSION_7 protocol reform
    // types total_len  flags  bound_value  ...bound_value
    // 1B*n    4B       1B*n      nB             nB
    uint32 type_len = CM_ALIGN4(count);

    stmt->resource_inuse = CT_TRUE;
    CT_RETURN_IFERR(vmc_alloc(&stmt->vmc, type_len, (void **)&stmt->cursor_info.param_types));
    stmt->param_info.param_types = stmt->cursor_info.param_types;

    CTSQL_SAVE_STACK(stmt);
    uint32 value_cost = sizeof(uint32) + CM_ALIGN4(count);
    if (ple_stack_alloc(stmt->session->stack, value_cost, (void **)&stmt->param_info.param_buf) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    vbuf_ass.total_len = (uint32 *)stmt->param_info.param_buf;
    *(vbuf_ass.total_len) = value_cost;
    vbuf_ass.type = stmt->session->call_version;
    stmt->param_info.param_offset = 0;
    stmt->param_info.paramset_size = 1;

    if (ple_keep_input_cursor(stmt, input, &vbuf_ass, is_dyncur, count) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    value_cost = *(uint32 *)stmt->param_info.param_buf;

    if (vmc_alloc(&stmt->vmc, value_cost, (void **)&stmt->cursor_info.param_buf) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    errno_t err_no = memcpy_sp(stmt->cursor_info.param_buf, value_cost, stmt->param_info.param_buf, value_cost);
    CTSQL_RESTORE_STACK(stmt);

    MEMS_RETURN_IFERR(err_no);
    stmt->param_info.param_buf = stmt->cursor_info.param_buf;
    return CT_SUCCESS;
}

status_t ple_keep_input(sql_stmt_t *stmt, pl_executor_t *exec, void *input, bool8 is_dyncur)
{
    CT_RETSUC_IFTRUE(input == NULL);

    return ple_keep_input_core(stmt, exec, input, is_dyncur);
}

static void ple_release_forblk(sql_stmt_t *stmt, pl_executor_t *exec, pl_line_ctrl_t *line)
{
    pl_line_for_t *for_line = (pl_line_for_t *)line;

    if (!for_line->is_cur) {
        return;
    }

    variant_t *id = ple_get_value(stmt, for_line->id->vid);
    if (id->type == CT_TYPE_RECORD) {
        udt_release_rec(stmt, id);
    }

    ple_var_t *var = ple_get_plvar(exec, for_line->cursor_id);
    pl_cursor_slot_t *ref_cur = var->value.v_cursor.ref_cursor;
    if (ref_cur == NULL) {
        return;
    }

    if (ref_cur->state == CUR_RES_FREE) {
        return;
    }

    sql_stmt_t *sub_stmt = ple_ref_cursor_get(stmt, ref_cur);
    if (sub_stmt && sub_stmt->cursor_info.is_forcur == CT_FALSE) {
        // cursor is not open by for line, can not release here
        return;
    }
    // to optimizer cursor release, avoid resource leak.
    ple_close_cursor(sub_stmt, PLE_CURSOR_SLOT_GET(var));
    // if for line open a explicit cursor, the cursor slot can't free until pop cursor's block
    if (for_line->cursor_id.block != ((int16)exec->block_stack.depth - 1)) {
        return;
    }

    ref_cur->ref_count = 0;
    ref_cur->state = CUR_RES_FREE;
}

static void ple_release_cur(sql_stmt_t *stmt, ple_var_t *var, pl_executor_t *exec)
{
    sql_stmt_t *sub_stmt = NULL;
    pl_cursor_slot_t *ref_cur = NULL;

    ref_cur = PLE_CURSOR_SLOT_GET(var);
    if (ref_cur == NULL) {
        return;
    }
    if (ref_cur->ref_count > 1) {
        ref_cur->ref_count--;
        return;
    }

    sub_stmt = ple_ref_cursor_get(stmt, ref_cur);
    if (sub_stmt != NULL) {
        sub_stmt->parent_stmt = NULL;
        sub_stmt->is_sub_stmt = CT_FALSE;
        knl_panic(!sub_stmt->cursor_info.is_returned);
        ple_close_cursor(sub_stmt, PLE_CURSOR_SLOT_GET(var));
    }

    ref_cur->ref_count = 0;
    ref_cur->state = CUR_RES_FREE;
}

static void ple_release_bgblk(sql_stmt_t *stmt, pl_executor_t *exec, ple_block_t *block)
{
    uint32 loop;
    ple_var_t *var = NULL;

    for (loop = 0; loop < block->var_map.count; loop++) {
        var = block->var_map.items[loop];
        CT_CONTINUE_IFTRUE(!var);
        // scalar not need release resoure
        CT_CONTINUE_IFTRUE((var->decl->type & (PLV_CUR | PLV_COMPLEX_VARIANT)) == 0);
        // inout or out cannot release
        CT_CONTINUE_IFTRUE(var->decl->drct == PLV_DIR_INOUT || var->decl->drct == PLV_DIR_OUT);

        if (var->decl->type == PLV_CUR) {
            ple_release_cur(stmt, var, exec);
        } else if (var->decl->type == PLV_COLLECTION) {
            udt_invoke_coll_destructor(stmt, &var->value);
        } else if (var->decl->type == PLV_RECORD) {
            udt_release_rec(stmt, &var->value);
        } else if (var->decl->type == PLV_OBJECT) {
            udt_release_obj(stmt, &var->value);
        }
    }
}

static void ple_release_currblk_res(sql_stmt_t *stmt, pl_executor_t *exec)
{
    ple_block_t *block = PLE_CURR_BLOCK(exec);
    pl_line_ctrl_t *line = block->entry;
    if (line->type == LINE_FOR) {
        ple_release_forblk(stmt, exec, line);
    }
    if (line->type == LINE_BEGIN) {
        ple_release_bgblk(stmt, exec, block);
    }
}

void ple_pop_block(sql_stmt_t *stmt, pl_executor_t *exec)
{
    ple_block_t *exec_block = NULL;
    ple_block_stack_t *block_stack = &exec->block_stack;

    // to optimize release, avoid resource leak.
    ple_release_currblk_res(stmt, exec);

    exec_block = PLE_CURR_BLOCK(exec);
#ifdef TEST_MEM
    stmt->session->stack->push_depth = exec_block->anchor.stack_depth;
#endif // TEST_MEM
    stmt->session->stack->heap_offset = exec_block->anchor.heap_offset;
    stmt->session->stack->push_offset = exec_block->anchor.push_offset;
    block_stack->depth--;
}

void ple_inherit_substmt_error(sql_stmt_t *stmt, sql_stmt_t *sub_stmt)
{
    errno_t ret;
    if (sub_stmt->pl_exec == NULL) {
        return;
    }
    if (stmt->pl_exec == NULL) {
        ple_send_error(sub_stmt);
        return;
    }

    pl_executor_t *pl_exec = (pl_executor_t *)stmt->pl_exec;
    pl_executor_t *sub_exec = (pl_executor_t *)sub_stmt->pl_exec;

    pl_exec->err_buf_full = sub_exec->err_buf_full;
    pl_exec->err_stack_full = sub_exec->err_stack_full;
    pl_exec->err_buf_pos = sub_exec->err_buf_pos;
    pl_exec->err_stack_pos = sub_exec->err_stack_pos;

    if (pl_exec->err_buf_pos > 0) {
        ret = memcpy_s(pl_exec->err_buf, sub_exec->err_buf_pos, sub_exec->err_buf, sub_exec->err_buf_pos);
        if (ret != EOK) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
            return;
        }
        pl_exec->err_buf[pl_exec->err_buf_pos] = '\0';
    }

    if (pl_exec->err_stack_pos > 0) {
        ret = memcpy_s(pl_exec->err_stack, sub_exec->err_stack_pos, sub_exec->err_stack, sub_exec->err_stack_pos);
        if (ret != EOK) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
            return;
        }
        pl_exec->err_stack[pl_exec->err_stack_pos] = '\0';
    }
}
