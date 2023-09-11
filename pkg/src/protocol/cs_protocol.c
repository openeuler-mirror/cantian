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
 * cs_protocol.c
 *
 *
 * IDENTIFICATION
 * src/protocol/cs_protocol.c
 *
 * -------------------------------------------------------------------------
 */
#include "cs_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

const client_kind_item_t g_module_names[CLIENT_KIND_TAIL] = {
    {{ "UNKNOWN", 7 }},
    {{ "GSC APPLICATION", 15 }},
    {{ "JDBC", 4 }},
    {{ "ZSQL", 4 }},
};

status_t cs_protocol_compatible(uint32 version)
{
    if (version == CS_VERSION_0) {
        GS_THROW_ERROR(ERR_PROTOCOL_INCOMPATIBALE);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

void cs_putted_fetch_req(cs_packet_t *pack, uint32 fetch_req_offset)
{
    cs_fetch_req_t *req = (cs_fetch_req_t *)CS_RESERVE_ADDR(pack, fetch_req_offset);
    if (CS_DIFFERENT_ENDIAN(pack->options)) {
        req->stmt_id = cs_reverse_int16(req->stmt_id);
    }
}

void cs_putted_execute_req(cs_packet_t *pack, uint32 exec_req_offset)
{
    cs_execute_req_t *req = (cs_execute_req_t *)CS_RESERVE_ADDR(pack, exec_req_offset);
    if (CS_DIFFERENT_ENDIAN(pack->options)) {
        req->stmt_id = cs_reverse_int16(req->stmt_id);
        req->paramset_size = cs_reverse_int16(req->paramset_size);
        req->prefetch_rows = cs_reverse_int16(req->prefetch_rows);
    }
}

void cs_putted_prepare_req(cs_packet_t *pack, uint32 prep_req_offset)
{
    cs_prepare_req_t *req = (cs_prepare_req_t *)CS_RESERVE_ADDR(pack, prep_req_offset);
    if (CS_DIFFERENT_ENDIAN(pack->options)) {
        req->stmt_id = cs_reverse_int16(req->stmt_id);
        req->flags = cs_reverse_int16(req->flags);
    }
}

void cs_putted_lob_write_req(cs_packet_t *pack, uint32 lob_write_req_offset)
{
    lob_write_req_t *req = (lob_write_req_t *)CS_RESERVE_ADDR(pack, lob_write_req_offset);
    if (CS_DIFFERENT_ENDIAN(pack->options)) {
        req->stmt_id = cs_reverse_int16(req->stmt_id);
        req->size = cs_reverse_int32(req->size);
        req->vlob.size = cs_reverse_int32(req->vlob.size);
        req->vlob.type = cs_reverse_int32(req->vlob.type);
        req->vlob.entry_vmid = cs_reverse_int32(req->vlob.entry_vmid);
        req->vlob.last_vmid = cs_reverse_int32(req->vlob.last_vmid);
    }
}

void cs_putted_lob_read_req(cs_packet_t *pack, uint32 lob_read_req_offset)
{
    lob_read_req_t *req = (lob_read_req_t *)CS_RESERVE_ADDR(pack, lob_read_req_offset);
    if (CS_DIFFERENT_ENDIAN(pack->options)) {
        req->stmt_id = cs_reverse_int16(req->stmt_id);
        req->size = cs_reverse_int32(req->size);
        req->offset = cs_reverse_int32(req->offset);
    }
}

void cs_putted_param_head(cs_packet_t *pack, uint32 param_head_offset)
{
    cs_param_head_t *param_head = (cs_param_head_t *)CS_RESERVE_ADDR(pack, param_head_offset);
    if (CS_DIFFERENT_ENDIAN(pack->options)) {
        param_head->len = cs_reverse_int16(param_head->len);
    }
}

status_t cs_get_prepare_ack(cs_packet_t *pack, cs_prepare_ack_t **prepare_ack)
{
    GS_RETURN_IFERR(cs_get_data(pack, sizeof(cs_prepare_ack_t), (void **)prepare_ack));
    if (CS_DIFFERENT_ENDIAN(pack->options)) {
        (*prepare_ack)->stmt_id = cs_reverse_int16((*prepare_ack)->stmt_id);
        (*prepare_ack)->stmt_type = cs_reverse_int16((*prepare_ack)->stmt_type);
        (*prepare_ack)->column_count = cs_reverse_int16((*prepare_ack)->column_count);
        (*prepare_ack)->param_count = cs_reverse_int16((*prepare_ack)->param_count);
    }
    return GS_SUCCESS;
}

status_t cs_get_param_def(cs_packet_t *pack, cs_param_def_t **param_def)
{
    GS_RETURN_IFERR(cs_get_data(pack, sizeof(cs_param_def_t), (void **)param_def));
    if (CS_DIFFERENT_ENDIAN(pack->options)) {
        (*param_def)->offset = cs_reverse_int32((*param_def)->offset);
        (*param_def)->len = cs_reverse_int32((*param_def)->len);
    }
    return GS_SUCCESS;
}

status_t cs_get_param_def_new(cs_packet_t *pack, cs_param_def_new_t **param_def)
{
    GS_RETURN_IFERR(cs_get_data(pack, sizeof(cs_param_def_new_t), (void **)param_def));
    if (CS_DIFFERENT_ENDIAN(pack->options)) {
        (*param_def)->len = cs_reverse_uint32((*param_def)->len);
    }
    return GS_SUCCESS;
}

status_t cs_get_column_def(cs_packet_t *pack, cs_column_def_t **column_def)
{
    GS_RETURN_IFERR(cs_get_data(pack, sizeof(cs_column_def_t), (void **)column_def));
    if (CS_DIFFERENT_ENDIAN(pack->options)) {
        (*column_def)->size = cs_reverse_int16((*column_def)->size);
        (*column_def)->datatype = cs_reverse_int16((*column_def)->datatype);
        (*column_def)->name_len = cs_reverse_int16((*column_def)->name_len);
    }
    return GS_SUCCESS;
}

status_t cs_get_outparam_def(cs_packet_t *pack, cs_outparam_def_t **o_def)
{
    GS_RETURN_IFERR(cs_get_data(pack, sizeof(cs_outparam_def_t), (void **)o_def));
    if (CS_DIFFERENT_ENDIAN(pack->options)) {
        (*o_def)->size = cs_reverse_int16((*o_def)->size);
    }
    return GS_SUCCESS;
}

status_t cs_get_exec_ack(cs_packet_t *pack, cs_execute_ack_t **exec_ack)
{
    GS_RETURN_IFERR(cs_get_data(pack, sizeof(cs_execute_ack_t), (void **)exec_ack));
    if (CS_DIFFERENT_ENDIAN(pack->options)) {
        (*exec_ack)->batch_count = cs_reverse_int32((*exec_ack)->batch_count);
        (*exec_ack)->total_rows = cs_reverse_int32((*exec_ack)->total_rows);
        (*exec_ack)->batch_rows = cs_reverse_int16((*exec_ack)->batch_rows);
        (*exec_ack)->pending_col_count = cs_reverse_int16((*exec_ack)->pending_col_count);
        (*exec_ack)->batch_errs = cs_reverse_int16((*exec_ack)->batch_errs);
    }
    return GS_SUCCESS;
}

status_t cs_get_final_column_def(cs_packet_t *pack, cs_final_column_def_t **column_def)
{
    GS_RETURN_IFERR(cs_get_data(pack, sizeof(cs_final_column_def_t), (void **)column_def));
    if (CS_DIFFERENT_ENDIAN(pack->options)) {
        (*column_def)->col_id = cs_reverse_int16((*column_def)->col_id);
        (*column_def)->size = cs_reverse_int16((*column_def)->size);
        (*column_def)->datatype = cs_reverse_int16((*column_def)->datatype);
    }
    return GS_SUCCESS;
}

status_t cs_get_fetch_ack(cs_packet_t *pack, cs_fetch_ack_t **fetch_ack)
{
    GS_RETURN_IFERR(cs_get_data(pack, sizeof(cs_fetch_ack_t), (void **)fetch_ack));
    if (CS_DIFFERENT_ENDIAN(pack->options)) {
        (*fetch_ack)->total_rows = cs_reverse_int32((*fetch_ack)->total_rows);
        (*fetch_ack)->batch_rows = cs_reverse_int16((*fetch_ack)->batch_rows);
    }
    return GS_SUCCESS;
}

status_t cs_get_lob_read_ack(cs_packet_t *pack, lob_read_ack_t **lob_read_ack)
{
    GS_RETURN_IFERR(cs_get_data(pack, sizeof(lob_read_ack_t), (void **)lob_read_ack));
    if (CS_DIFFERENT_ENDIAN(pack->options)) {
        (*lob_read_ack)->size = cs_reverse_int32((*lob_read_ack)->size);
        (*lob_read_ack)->eof = cs_reverse_int32((*lob_read_ack)->eof);
    }
    return GS_SUCCESS;
}

#ifdef __cplusplus
}
#endif

