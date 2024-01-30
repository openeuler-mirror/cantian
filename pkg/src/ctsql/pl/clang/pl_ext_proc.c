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
 * pl_ext_proc.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/clang/pl_ext_proc.c
 *
 * -------------------------------------------------------------------------
 */
#include "pl_ext_proc.h"
#include "pl_executor.h"
#include "mes_packet.h"
#include "srv_instance.h"
#include "func_mgr.h"
#include "base_compiler.h"

/* sql type                            ct_type_t            c type
  bool/boolean                         CT_TYPE_BOOLEAN      bool*
  short/smallint                       CT_TYPE_SMALLINT     short*
  ushort/usmallint                     CT_TYPE_USMALLINT    unsigned short*
  int/Integer/binary_integer           CT_TYPE_INTEGER      int*
  binary_uint32/uint/uinteger          CT_TYPE_UINT32       unsigned int*
  bigint/binary_bigint                 CT_TYPE_BIGINT       long long*
  binary_float/float                   CT_TYPE_FLOAT        double*
  binary_double/double/real            CT_TYPE_REAL         double*
  binary                               CT_TYPE_BINARY       cbinary_t*
  varbinary                            CT_TYPE_VARBINARY    cbinary_t*
  raw                                  CT_TYPE_RAW          cbinary_t*
  nvarchar/nvarchar2/varchar2/varchar  CT_TYPE_VARCHAR      ctext_t*
  char/character/bpchar                CT_TYPE_CHAR         ctext_t*
*/
static status_t put_param_value(mes_message_ex_t *pack, variant_t *value)
{
    switch ((ct_type_t)value->type) {
        case CT_TYPE_SMALLINT:
        case CT_TYPE_USMALLINT:
        case CT_TYPE_TINYINT:
        case CT_TYPE_UTINYINT:
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
        case CT_TYPE_BOOLEAN:
            CT_RETURN_IFERR(mes_put_int32(pack, VALUE(uint32, value)));
            break;

        case CT_TYPE_BIGINT:
        case CT_TYPE_UINT64:
            CT_RETURN_IFERR(mes_put_int64(pack, VALUE(int64, value)));
            break;

        case CT_TYPE_FLOAT:
        case CT_TYPE_REAL:
            CT_RETURN_IFERR(mes_put_double(pack, VALUE(double, value)));
            break;

        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
            CT_RETURN_IFERR(mes_put_text(pack, VALUE_PTR(text_t, value)));
            break;

        default:
            CT_SET_ERROR_MISMATCH_EX(value->type);
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t check_output_arg(sql_stmt_t *stmt, expr_node_t *actual_node, plv_decl_t *formal_decl, uint32 param_id,
    expr_node_t *node)
{
    var_udo_t *obj = sql_node_get_obj(node);
    if (formal_decl->drct == PLV_DIR_IN) {
        return CT_SUCCESS;
    }

    if (actual_node->type != EXPR_NODE_V_ADDR || !sql_pair_type_is_plvar(actual_node)) {
        CT_SRC_THROW_ERROR(NODE_LOC(node), ERR_PL_ARG_FMT, param_id, T2S(&obj->name),
            "cannot be used as an assignment target");
        return CT_ERROR;
    }
    var_address_pair_t *pair = (var_address_pair_t *)cm_galist_get(actual_node->value.v_address.pairs, 0);
    if (pair->stack->decl->type == PLV_PARAM &&
        stmt->param_info.params[pair->stack->decl->param.param_id].direction == PLV_DIR_IN) {
        CT_SRC_THROW_ERROR(NODE_LOC(node), ERR_PL_ARG_FMT, param_id, T2S(&obj->name),
            "is out parameter and cannot be assigned to in parameter");
        return CT_ERROR;
    }
    if (!var_datatype_matched(formal_decl->variant.type.datatype, NODE_DATATYPE(actual_node))) {
        CT_SRC_THROW_ERROR(NODE_LOC(node), ERR_PL_ARG_FMT, param_id, T2S(&obj->name),
            "formal argument and actual argument type is inconsistent");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t encode_rpc_req(sql_stmt_t *stmt, expr_node_t *node, mes_message_ex_t *pack, ext_assist_t *assist)
{
    function_t *func = assist->func;
    uint32 i;
    uint32 arg_count;
    plv_decl_t *decl = NULL;
    variant_t value;
    ct_type_t datatype;
    uint8 *types = NULL;
    uint8 *flags = NULL;

    if (func->desc.pl_type == PL_FUNCTION) {
        i = 1;
        arg_count = func->desc.arg_count - 1;
        assist->is_func = CT_TRUE;
    } else {
        i = 0;
        arg_count = func->desc.arg_count;
        assist->is_func = CT_FALSE;
    }

    uint32 len = ((node->argument == NULL) ? 0 : sql_expr_list_len(node->argument));
    if (len != arg_count || len > FUNC_MAX_ARGS) {
        CT_THROW_ERROR(ERR_ASSERT_ERROR, "the amount of actual arguments and formal arguments are inconsistent");
        return CT_ERROR;
    }

    assist->args_num = arg_count;
    CT_RETURN_IFERR(mes_put_int32(pack, assist->is_func));
    CT_RETURN_IFERR(mes_put_str(pack, assist->library->path));
    CT_RETURN_IFERR(mes_put_text2str(pack, &((pl_line_begin_t *)func->body)->func));
    CT_RETURN_IFERR(mes_put_int64(pack, assist->oid));
    CT_RETURN_IFERR(mes_put_int32(pack, arg_count));

    if (assist->is_func) {
        decl = cm_galist_get(func->desc.params, 0);
        CT_RETURN_IFERR(mes_put_int32(pack, (uint32)decl->variant.type.datatype));
    }

    if (arg_count == 0) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(mes_reserve_space(pack, arg_count, (void **)&types));
    CT_RETURN_IFERR(mes_reserve_space(pack, arg_count, (void **)&flags));

    expr_tree_t *curr_arg = node->argument;
    for (uint32 j = 0; j < len && curr_arg; i++, j++) {
        decl = cm_galist_get(func->desc.params, i);
        CT_RETURN_IFERR(check_output_arg(stmt, curr_arg->root, decl, j, node));
        datatype = decl->variant.type.datatype;
        SET_DATA_TYPE(types[j], datatype);
        SET_DIR_FLAG(flags[j], decl->drct);
        SET_NULL_FLAG(flags[j], CT_TRUE);
        if (decl->drct == PLV_DIR_IN || decl->drct == PLV_DIR_INOUT) {
            if (sql_exec_expr(stmt, curr_arg, &value) != CT_SUCCESS) {
                pl_check_and_set_loc(curr_arg->loc);
                return CT_ERROR;
            }
            SET_NULL_FLAG(flags[j], value.is_null);
            if (value.is_null) {
                curr_arg = curr_arg->next;
                continue;
            }
            CT_RETURN_IFERR(sql_convert_variant(stmt, &value, datatype));
            sql_keep_stack_variant(stmt, &value);
            CT_RETURN_IFERR(put_param_value(pack, &value));
        }

        curr_arg = curr_arg->next;
    }

    return CT_SUCCESS;
}

static status_t get_param_value(sql_stmt_t *stmt, mes_message_ex_t *pack, ct_type_t datatype, variant_t *value)
{
    text_t text;
    value->type = datatype;
    value->is_null = CT_FALSE;
    switch (datatype) {
        case CT_TYPE_SMALLINT:
        case CT_TYPE_USMALLINT:
        case CT_TYPE_TINYINT:
        case CT_TYPE_UTINYINT:
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
        case CT_TYPE_BOOLEAN:
            CT_RETURN_IFERR(mes_get_int32(pack, VALUE_PTR(int32, value)));
            break;

        case CT_TYPE_BIGINT:
        case CT_TYPE_UINT64:
            CT_RETURN_IFERR(mes_get_int64(pack, VALUE_PTR(int64, value)));
            break;

        case CT_TYPE_FLOAT:
        case CT_TYPE_REAL:
            CT_RETURN_IFERR(mes_get_double(pack, VALUE_PTR(double, value)));
            break;

        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
            CT_RETURN_IFERR(mes_get_text(pack, &text));
            CT_RETURN_IFERR(sql_push(stmt, text.len, (void **)&value->v_text.str));
            value->v_text.len = text.len;
            if (text.len > 0) {
                errno_t ret = memcpy_sp(value->v_text.str, text.len, text.str, text.len);
                if (ret != EOK) {
                    CTSQL_POP(stmt);
                    CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
                    return CT_ERROR;
                }
            }
            break;

        default:
            CT_SET_ERROR_MISMATCH_EX(datatype);
            return CT_ERROR;
    }

    return CT_SUCCESS;
}


static status_t proc_rpc_ack(sql_stmt_t *stmt, mes_message_ex_t *pack, expr_node_t *node, ext_assist_t *assist,
    variant_t *result)
{
    function_t *func = assist->func;
    uint32 i = assist->is_func ? 1 : 0;
    uint32 k = 0;
    plv_decl_t *decl = NULL;
    ple_var_t *dst = NULL;
    expr_tree_t *curr_arg = node->argument;
    variant_t value;

    while (k < assist->args_num) {
        decl = cm_galist_get(func->desc.params, i);
        if (decl->drct != PLV_DIR_IN) {
            if (curr_arg->root->type != EXPR_NODE_V_ADDR) {
                CT_SRC_THROW_ERROR(curr_arg->root->loc, ERR_PL_SYNTAX_ERROR_FMT, "unexpected pl-variant occurs");
                return CT_ERROR;
            }
            var_address_pair_t *pair = sql_get_last_addr_pair(curr_arg->root);
            if (pair == NULL || pair->type != UDT_STACK_ADDR) {
                CT_SRC_THROW_ERROR(curr_arg->root->loc, ERR_PL_SYNTAX_ERROR_FMT, "unexpected pl-variant occurs");
                return CT_ERROR;
            }
            dst = ple_get_plvar((pl_executor_t *)stmt->pl_exec, pair->stack->decl->vid);
            CT_RETURN_IFERR(get_param_value(stmt, pack, decl->variant.type.datatype, &value));
            CT_RETURN_IFERR(ple_move_value(stmt, &value, dst));
        }

        curr_arg = curr_arg->next;
        k++;
        i++;
    }

    if (assist->is_func && result != NULL) {
        decl = (plv_decl_t *)cm_galist_get(func->desc.params, 0);
        CT_RETURN_IFERR(get_param_value(stmt, pack, decl->variant.type.datatype, result));
    }
    return CT_SUCCESS;
}

static status_t pl_clear_sym_cache_core(knl_session_t *session, knl_cursor_t *cursor, char *lib_path)
{
    mes_message_ex_t pack;
    char *buf = NULL;
    status_t status;
    int64 oid;
    buf = cm_push(session->stack, MES_MESSAGE_BUFFER_SIZE);
    if (buf == NULL) {
        return CT_ERROR;
    }
    mes_init_set(&pack, buf, MES_MESSAGE_BUFFER_SIZE);
    mes_init_send_head(GET_MSG_HEAD(&pack), MES_CMD_DROP_LIB_REQ, sizeof(mes_message_head_t), MES_MOD_EXTPROC, 0, 1,
        session->id, CT_INVALID_ID16);

    uint32 count = 0;
    uint32 *offset = NULL;

    CT_RETURN_IFERR(mes_reserve_space(&pack, sizeof(uint32), (void **)&offset));

    while (!cursor->eof) {
        oid = *(int64 *)CURSOR_COLUMN_DATA(cursor, SYS_PROC_OBJ_ID_COL);
        CT_RETURN_IFERR(mes_put_int64(&pack, oid));
        count++;
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    CT_RETURN_IFERR(mes_put_str(&pack, lib_path));
    *offset = count;

    CT_RETURN_IFERR(mes_send_data((const void *)GET_MSG_HEAD(&pack)));

    mes_message_ex_t ack_pack;
    CT_RETURN_IFERR(mes_recv(session->id, &ack_pack.msg, MES_MOD_EXTPROC, CT_FALSE, CT_INVALID_ID32, EXT_WAIT_TIMEOUT));
    mes_init_get(&ack_pack);
    switch (GET_MSG_HEAD(&ack_pack)->cmd) {
        case MES_CMD_DROP_LIB_ACK:
            status = CT_SUCCESS;
            break;

        case MES_CMD_ERROR_MSG:
            mes_handle_error_msg(GET_MSG_BUFF(&ack_pack));
            status = CT_ERROR;
            break;
        default:
            mes_release_message_buf(GET_MSG_BUFF(&ack_pack));
            CT_THROW_ERROR(ERR_MES_ILEGAL_MESSAGE, "invalid MES message type");
            return CT_ERROR;
    }
    mes_release_message_buf(GET_MSG_BUFF(&ack_pack));
    return status;
}

status_t pl_clear_sym_cache(knl_handle_t se, uint32 lib_uid, char *name, char *lib_path)
{
    knl_cursor_t *cursor = NULL;
    knl_session_t *session = (knl_session_t *)se;
    status_t status;
    if (!GET_PL_MGR->bootstrap) {
        return CT_SUCCESS;
    }
    CM_SAVE_STACK(session->stack);
    cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_PROC_ID, IX_PROC_004_ID);
    knl_init_index_scan(cursor, CT_TRUE);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&lib_uid,
        sizeof(uint32), IX_COL_PROC_004_USER_ID);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_STRING, (void *)name,
        (uint16)strlen(name), IX_COL_PROC_004_LIB_NAME);
    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        return CT_SUCCESS;
    }

    status = pl_clear_sym_cache_core(session, cursor, lib_path);
    CM_RESTORE_STACK(session->stack);
    return status;
}

status_t ple_exec_call_clang_func_core(sql_stmt_t *stmt, expr_node_t *node, variant_t *result, ext_assist_t *assist)
{
    knl_session_t *knl_session = KNL_SESSION(stmt);
    pl_line_begin_t *begin_line = (pl_line_begin_t *)assist->func->body;
    mes_message_ex_t ack_pack;
    mes_message_ex_t pack;
    char *buf = NULL;
    status_t status = CT_SUCCESS;

    CM_SAVE_STACK(knl_session->stack);
    if (sql_push(stmt, MES_MESSAGE_BUFFER_SIZE, (void **)&buf) != CT_SUCCESS) {
        return CT_ERROR;
    }
    mes_init_set(&pack, buf, MES_MESSAGE_BUFFER_SIZE);
    mes_init_send_head(GET_MSG_HEAD(&pack), MES_CMD_RPC_REQ, sizeof(mes_message_head_t), MES_MOD_EXTPROC, 0, 1,
        knl_session->id, CT_INVALID_ID16);

    if (encode_rpc_req(stmt, node, &pack, assist) != CT_SUCCESS) {
        CM_RESTORE_STACK(knl_session->stack);
        return CT_ERROR;
    }

    if (mes_send_data((const void *)GET_MSG_HEAD(&pack)) != CT_SUCCESS) {
        CM_RESTORE_STACK(knl_session->stack);
        return CT_ERROR;
    }
    CM_RESTORE_STACK(knl_session->stack);

    if (mes_recv(knl_session->id, &ack_pack.msg, MES_MOD_EXTPROC, CT_FALSE, CT_INVALID_ID32, EXT_WAIT_TIMEOUT) !=
        CT_SUCCESS) {
        cm_reset_error();
        CT_THROW_ERROR(ERR_INVOKE_EXT_FUNC_ERR, T2S(&begin_line->func), "internal exception");
        return CT_ERROR;
    }
    mes_init_get(&ack_pack);
    switch (GET_MSG_HEAD(&ack_pack)->cmd) {
        case MES_CMD_RPC_ACK:
            status = proc_rpc_ack(stmt, &ack_pack, node, assist, result);
            break;
        case MES_CMD_ERROR_MSG:
            mes_handle_error_msg(GET_MSG_BUFF(&ack_pack));
            status = CT_ERROR;
            break;
        default:
            mes_release_message_buf(GET_MSG_BUFF(&ack_pack));
            CT_THROW_ERROR(ERR_MES_ILEGAL_MESSAGE, "invalid MES message type");
            return CT_ERROR;
    }
    mes_release_message_buf(GET_MSG_BUFF(&ack_pack));
    return status;
}