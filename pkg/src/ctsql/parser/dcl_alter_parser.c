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
 * dcl_alter_parser.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/parser/dcl_alter_parser.c
 *
 * -------------------------------------------------------------------------
 */

#include "dcl_alter_parser.h"
#include "srv_instance.h"
#include "cbo_base.h"
#include "ctsql_privilege.h"
#include "ddl_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t sql_parse_alsys_switch(lex_t *lex, knl_alter_sys_def_t *def, word_t *word)
{
    if (lex_fetch(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if ((key_wid_t)word->id != KEY_WORD_LOGFILE) {
        CT_SRC_THROW_ERROR_EX(word->text.loc, ERR_SQL_SYNTAX_ERROR, "LOGFILE expected but %s found", W2S(word));
        return CT_ERROR;
    }
    if (lex_expected_end(lex) != CT_SUCCESS) {
        return CT_ERROR;
    }

    def->action = ALTER_SYS_SWITCHLOG;
    return CT_SUCCESS;
}

static status_t sql_parse_match_config(knl_session_t *se, knl_alter_sys_def_t *def, lex_t *lex)
{
    config_item_t *item = NULL;
    if (IS_LOG_MODE(def->param)) {
        text_t name = {
            .str = "_LOG_LEVEL",
            .len = sizeof("_LOG_LEVEL") - 1
        };
        item = cm_get_config_item(GET_CONFIG, &name, CT_TRUE);
    } else {
        text_t name = {
            .str = def->param,
            .len = (uint32)strlen(def->param)
        };
        item = cm_get_config_item(GET_CONFIG, &name, CT_TRUE);
    }

    if (item == NULL) {
        CT_SRC_THROW_ERROR(lex->loc, ERR_INVALID_PARAMETER_NAME, def->param);
        return CT_ERROR;
    }

    def->param_id = item->id;

    if (se->kernel->db.ctrl.core.lrep_mode == LOG_REPLICATION_ON &&
        strcmp(def->param, "ARCH_TIME") == 0) {
        CT_THROW_ERROR(ERR_NOT_COMPATIBLE, "arch time while lrep_mode is LOG_REPLICATION_ON");
        return CT_ERROR;
    }

    /* VERIFY SET VALUE HERE. */
    if ((item->verify) && (item->verify((knl_handle_t)se, (void *)lex, (void *)def) != CT_SUCCESS)) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t sql_parse_alsys_modify_replica(lex_t *lex, knl_alter_sys_def_t *def)
{
    word_t word;

    if (lex_expected_fetch((lex_t *)lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.type == WORD_TYPE_STRING) {
        sql_remove_quota(&word.text.value);
    }

    cm_trim_text((text_t *)&word.text);
    cm_text2str((text_t *)&word.text, def->value, CT_PARAM_BUFFER_SIZE);

    def->action = ALTER_SYS_MODIFY_REPLICA;
    return lex_expected_end(lex);
}

static status_t sql_parse_replication_clause(knl_alter_sys_def_t *sys_def, lex_t *lex)
{
    status_t status;
    word_t word;

    status = lex_expected_fetch(lex, &word);
    CT_RETURN_IFERR(status);

    switch ((key_wid_t)word.id) {
        case KEY_WORD_ON:
            status = sql_parse_alsys_modify_replica(lex, sys_def);
            break;
        case KEY_WORD_OFF:
            sys_def->action = ALTER_SYS_STOP_REPLICA;
            status = lex_expected_end(lex);
            break;
        default:
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(&word));
            return CT_ERROR;
    }

    return status;
}

static status_t sql_parse_alsys_set(session_t *session, knl_alter_sys_def_t *sys_def, word_t *word)
{
    status_t status;

    lex_t *lex = session->lex;

    sys_def->is_coord_conn = IS_COORD_CONN(session);
    status = lex_expected_fetch_variant(lex, word);
    CT_RETURN_IFERR(status);

    if ((key_wid_t)word->id == KEY_WORD_REPLICATION) {
        return sql_parse_replication_clause(sys_def, lex);
    }

    sys_def->action = ALTER_SYS_SET_PARAM;
    CT_RETURN_IFERR(cm_text2str((text_t *)&word->text, sys_def->param, CT_NAME_BUFFER_SIZE));
    cm_str_upper(sys_def->param);

    status = lex_expected_fetch_word(lex, "=");
    CT_RETURN_IFERR(status);

    status = sql_parse_match_config(&session->knl_session, sys_def, lex);
    CT_RETURN_IFERR(status);

    CT_RETURN_IFERR(sql_parse_scope_clause(sys_def, lex));

    return lex_expected_end(lex);
}

static status_t sql_parse_alsys_load(sql_stmt_t *stmt, knl_alter_sys_def_t *sys_def, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    text_t user;
    text_t name;

    lex->flags = LEX_WITH_OWNER;

    if (lex_expected_fetch_word(lex, "DICTIONARY") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_word(lex, "FOR") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_variant(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_convert_object_name(stmt, word, &user, NULL, &name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    CT_RETURN_IFERR(cm_text2str(&user, sys_def->param, CT_NAME_BUFFER_SIZE));
    CT_RETURN_IFERR(cm_text2str(&name, sys_def->value, CT_PARAM_BUFFER_SIZE));

    sys_def->action = ALTER_SYS_LOAD_DC;

    return lex_expected_end(lex);
}

static status_t sql_parse_alsys_init(sql_stmt_t *stmt, knl_alter_sys_def_t *sys_def, word_t *word)
{
    lex_t *lex = stmt->session->lex;

    lex->flags = LEX_WITH_OWNER;

    if (lex_expected_fetch_word(lex, "DICTIONARY") != CT_SUCCESS) {
        return CT_ERROR;
    }

    sys_def->action = ALTER_SYS_INIT_ENTRY;

    return lex_expected_end(lex);
}

static status_t sql_parse_alsys_flush(lex_t *lex, knl_alter_sys_def_t *sys_def, word_t *word)
{
    uint32 matched_id;

    if (lex_expected_fetch_1of2(lex, "BUFFER", "SQLPOOL", &matched_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (matched_id == 0) {
        sys_def->action = ALTER_SYS_FLUSH_BUFFER;
    } else {
        sys_def->action = ALTER_SYS_FLUSH_SQLPOOL;
    }

    return lex_expected_end(lex);
}

static status_t sql_parse_alsys_recycle(lex_t *lex, knl_alter_sys_def_t *sys_def, word_t *word)
{
    if (lex_expected_fetch_word(lex, "sharedpool") != CT_SUCCESS) {
        return CT_ERROR;
    }

    sys_def->action = ALTER_SYS_RECYCLE_SHAREDPOOL;

    if (lex_try_fetch(lex, "force", &sys_def->force_recycle) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return lex_expected_end(lex);
}

static status_t sql_parse_dump_dest_file(sql_stmt_t *stmt, lex_t *lex, word_t *word, text_t *dest_file)
{
    bool32 result = CT_FALSE;

    if (lex_try_fetch(lex, "TO", &result) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!result) {
        return CT_SUCCESS;
    }

    if (lex_expected_fetch_string(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_copy_text(stmt->context, (text_t *)&word->text, dest_file) != CT_SUCCESS) {
        return CT_ERROR;
    }

    char real_name[CT_MAX_FILE_PATH_LENGH] = { 0x00 };
    if (sql_get_real_path(dest_file, real_name) != CT_SUCCESS) {
        CT_THROW_ERROR_EX(ERR_CAPABILITY_NOT_SUPPORT, "datafile name [%s] fmt", T2S(dest_file));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t sql_parse_dump_datafile(sql_stmt_t *stmt, lex_t *lex, knl_alter_sys_def_t *sys_def, word_t *word)
{
    int32 value;

    if (CT_SUCCESS != lex_expected_fetch_int32(lex, &value)) {
        return CT_ERROR;
    }

    if (value < 0) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "param values should positive");
        return CT_ERROR;
    }

    sys_def->page_id.file = value;

    if (CT_SUCCESS != lex_expected_fetch_word(lex, "PAGE")) {
        CT_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "page expected but %s found", W2S(word));
        return CT_ERROR;
    }

    if (CT_SUCCESS != lex_expected_fetch_int32(lex, &value)) {
        return CT_ERROR;
    }

    if (value < 0) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "param values should positive");
        return CT_ERROR;
    }

    sys_def->page_id.page = value;

    if (sql_parse_dump_dest_file(stmt, lex, word, &sys_def->out_file) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return lex_expected_end(lex);
}

static status_t sql_parse_dump_ctrlfile(sql_stmt_t *stmt, lex_t *lex, knl_alter_sys_def_t *sys_def, word_t *word)
{
    sys_def->action = ALTER_SYS_DUMP_CTRLPAGE;
    if (sql_parse_dump_dest_file(stmt, lex, word, &sys_def->out_file) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return lex_expected_end(lex);
}

static status_t sql_parse_alsys_dc_dump(sql_stmt_t *stmt, knl_alter_sys_def_t *sys_def, word_t *word)
{
    status_t status;
    lex_t *lex = stmt->session->lex;
    sys_def->action = ALTER_SYS_DUMP_DC;

    if (CT_SUCCESS != lex_expected_fetch(lex, word)) {
        return CT_ERROR;
    }

    switch (word->id) {
        case KEY_WORD_TABLE:
            sys_def->dump_info.dump_type = DC_DUMP_TABLE;
            stmt->session->lex->flags |= LEX_WITH_OWNER;
            status = lex_expected_fetch_variant(lex, word);
            CT_RETURN_IFERR(status);
            status = sql_convert_object_name(stmt, word, &sys_def->dump_info.user_name,
                                             NULL, &sys_def->dump_info.table_name);
            CT_RETURN_IFERR(status);
            status = sql_check_dump_priv(stmt, sys_def);
            CT_RETURN_IFERR(status);
            break;
        case RES_WORD_USER:
            sys_def->dump_info.dump_type = DC_DUMP_USER;

            status = lex_expected_fetch_variant(lex, word);
            CT_RETURN_IFERR(status);
            status = sql_copy_prefix_tenant(stmt, (text_t *)&word->text, &sys_def->dump_info.user_name, sql_copy_name);
            CT_RETURN_IFERR(status);
            status = sql_check_dump_priv(stmt, sys_def);
            CT_RETURN_IFERR(status);
            break;
        default:
            CT_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "table/user expected but %s found", W2S(word));
            return CT_ERROR;
    }

    if (sql_parse_dump_dest_file(stmt, lex, word, &sys_def->dump_info.dump_file) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return lex_expected_end(lex);
}

static status_t sql_parse_alsys_dump(sql_stmt_t *stmt, lex_t *lex, knl_alter_sys_def_t *def, word_t *word)
{
    status_t status;

    def->action = ALTER_SYS_DUMP_PAGE;

    if (CT_SUCCESS != lex_expected_fetch(lex, word)) {
        return CT_ERROR;
    }

    switch (word->id) {
        case KEY_WORD_DATAFILE:
            status = sql_parse_dump_datafile(stmt, lex, def, word);
            break;
        case KEY_WORD_CTRLFILE:
            status = sql_parse_dump_ctrlfile(stmt, lex, def, word);
            break;
        case KEY_WORD_CATALOG:
            status = sql_parse_alsys_dc_dump(stmt, def, word);
            break;
        default:
            CT_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "datafile expected but %s found", W2S(word));
            status = CT_ERROR;
            break;
    }

    return status;
}

static inline status_t sql_parse_int_until(int32 *value, text_t *text, const char *until)
{
    uint32 loop;
    char cval;
    char *beg = text->str;
    if (text->str[0] == '+' || text->str[0] == '-') {
        ++text->str;
        --text->len;
    }
    while (text->str[0] == ' ') {
        ++text->str;
        --text->len;
    }
    if (text->len == 0) {
        return CT_ERROR;
    }
    for (loop = 0; loop < text->len; ++loop) {
        if (until != NULL && text->str[loop] == until[0]) {
            if (loop == 0) {
                return CT_ERROR;
            }
            text->str[loop] = '\0';
            *value = atoi(beg);
            text->str[loop] = ',';
            text->str += (loop + 1);
            text->len -= (loop + 1);
            return CT_SUCCESS;
        }
        if (text->str[loop] > '9' || text->str[loop] < '0') {
            return CT_ERROR;
        }
    }
    if (loop == 0) {
        return CT_ERROR;
    }
    cval = text->str[loop]; // may exceed bound, but it does not matter
    text->str[loop] = '\0';
    *value = atoi(beg);
    text->str[loop] = cval;
    text->str += loop;
    text->len -= loop;
    return CT_SUCCESS;
}

// if the count of splitter in text is num,return 1,else return 0
static inline bool32 sql_parse_num_match_splitter(const text_t *text, int num, char split)
{
    if (text->str == NULL || text->len <= 0) {
        return 0;
    }
    int count = 0;
    for (uint32 i = 0; i < text->len; i++) {
        if (text->str[i] == split) {
            count++;
        }
    }
    return (bool32)(count == num ? 1 : 0);
}

static inline status_t sql_parse_sid_serial(word_t *word, uint32 *sid, uint32 *serial, uint32 *nodeid)
{
    text_t text, text1;
    int32 arrint0, arrint1;
    int32 arrint2 = 0;
    text.str = word->text.str;
    text.len = word->text.len;
    text1.str = word->text.str;
    text1.len = word->text.len;

    if (CT_SUCCESS != sql_parse_int_until(&arrint0, &text, ",")) {
        CT_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "invalid session id '%s'", T2S(&word->text));
        return CT_ERROR;
    }

    if (CT_SUCCESS != sql_parse_int_until(&arrint1, &text, ",")) {
        CT_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "invalid session id '%s'", T2S(&word->text));
        return CT_ERROR;
    }

    if (text.len == 0) {
        // only have sid and serial
        // 2 find two comma
        if (sql_parse_num_match_splitter(&text1, 2, ',')) {
            // The parsing str should have one splitter
            CT_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "invalid session id '%s'", T2S(&word->text));
            return CT_ERROR;
        }
    } else {
        // have sid and serial and nodeid
        if (!IS_COORDINATOR) {
            CT_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "not support to kill other session on DN node");
            return CT_ERROR;
        }
        if (text.str[0] != '@') {
            CT_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "invalid session id '%s'", T2S(&word->text));
            return CT_ERROR;
        }
        ++text.str;
        --text.len;
        if (CT_SUCCESS != sql_parse_int_until(&arrint2, &text, NULL)) {
            CT_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "invalid session id '%s'", T2S(&word->text));
            return CT_ERROR;
        }
    }

    if (arrint0 < 0 || arrint1 < 0 || arrint2 < 0) {
        CT_SRC_THROW_ERROR_EX(word->loc, ERR_SQL_SYNTAX_ERROR, "invalid session id '%s'", T2S(&word->text));
        return CT_ERROR;
    }

    *sid = (uint32)arrint0;
    *serial = (uint32)arrint1;
    *nodeid = (uint32)arrint2;

    return CT_SUCCESS;
}

static status_t sql_parse_alsys_kill(sql_stmt_t *stmt, lex_t *lex, knl_alter_sys_def_t *sys_def)
{
    word_t word;
    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "SESSION"));
    CT_RETURN_IFERR(lex_expected_fetch_string(lex, &word));
    CT_RETURN_IFERR(sql_parse_sid_serial(&word, &sys_def->session_id, &sys_def->serial_id, &sys_def->node_id));

    sys_def->action = ALTER_SYS_KILL_SESSION;

    return lex_expected_end(lex);
}

status_t sql_verify_als_gbp_trans_type(void *se, void *lex, void *def)
{
    uint32 match_id;
    char *match_word[] = { "TCP", "RDMA" };
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    if (lex_expected_fetch_1of2(lex, "TCP", "RDMA", &match_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    PRTS_RETURN_IFERR(
        snprintf_s(sys_def->value, CT_PARAM_BUFFER_SIZE, CT_PARAM_BUFFER_SIZE - 1, "%s", match_word[match_id]));

    return CT_SUCCESS;
}

static status_t sql_parse_alsys_reset(sql_stmt_t *stmt, lex_t *lex, knl_alter_sys_def_t *def)
{
    def->action = ALTER_SYS_RESET_STATISTIC;
    if (lex_expected_fetch_word(lex, "statistic") != CT_SUCCESS) {
        return CT_ERROR;
    }
    return lex_expected_end(lex);
}

static status_t sql_parse_alsys_checkpoint(lex_t *lex, knl_alter_sys_def_t *def)
{
    uint32 match_id;

    CT_RETURN_IFERR(lex_try_fetch_1of2(lex, "GLOBAL", "LOCAL", &match_id));

    switch (match_id) {
        case 0:
            def->ckpt_type = CKPT_TYPE_GLOBAL;
            break;
        case 1:
        default:
            def->ckpt_type = CKPT_TYPE_LOCAL;
            break;
    }

    CT_RETURN_IFERR(lex_expected_end(lex));

    def->action = ALTER_SYS_CHECKPOINT;
    return CT_SUCCESS;
}

static status_t sql_parse_alsys_arch_set(session_t *session, knl_alter_sys_def_t *def, word_t *word)
{
    uint32 match_id;
    status_t status;
    lex_t *lex = session->lex;

    def->is_coord_conn = IS_COORD_CONN(session);
    status = lex_expected_fetch_variant(lex, word);
    CT_RETURN_IFERR(status);

    if ((key_wid_t)word->id == KEY_WORD_REPLICATION) {
        return sql_parse_replication_clause(def, lex);
    }

    def->action = ALTER_SYS_SET_PARAM;
    CT_RETURN_IFERR(cm_text2str((text_t *)&word->text, def->param, CT_NAME_BUFFER_SIZE));
    cm_str_upper(def->param);

    status = lex_expected_fetch_word(lex, "=");
    CT_RETURN_IFERR(status);

    status = sql_parse_match_config(&session->knl_session, def, lex);
    CT_RETURN_IFERR(status);

    CT_RETURN_IFERR(sql_parse_scope_clause(def, lex));

    CT_RETURN_IFERR(lex_try_fetch_1of2(lex, "GLOBAL", "LOCAL", &match_id));

    switch (match_id) {
        case 0:
            def->arch_set_type = ARCH_SET_TYPE_GLOBAL;
            break;
        case 1:
        default:
            def->arch_set_type = ARCH_SET_TYPE_LOCAL;
            break;
    }

    CT_RETURN_IFERR(lex_expected_end(lex));

    def->action = ALTER_SYS_ARCHIVE_SET;
    return CT_SUCCESS;
}

static status_t sql_parse_reload_conf(lex_t *lex, knl_alter_sys_def_t *def)
{
    uint32 matched_id;
    if (lex_expected_fetch_1of2(lex, "HBA", "PBL", &matched_id) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (matched_id == 0) {
        def->action = ALTER_SYS_RELOAD_HBA;
    } else {
        def->action = ALTER_SYS_RELOAD_PBL;
    }
    if (lex_expected_fetch_word(lex, "CONFIG")) {
        return CT_ERROR;
    }
    return lex_expected_end(lex);
}

static status_t sql_parse_refresh_sysdba_privilege(lex_t *lex, knl_alter_sys_def_t *def)
{
    def->action = ALTER_SYS_REFRESH_SYSDBA;
    if (lex_expected_fetch_word(lex, "SYSDBA") != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (lex_expected_fetch_word(lex, "PRIVILEGE")) {
        return CT_ERROR;
    }
    return lex_expected_end(lex);
}

static status_t sql_parse_alsys_modify_lsnr_addr(lex_t *lex, knl_alter_sys_def_t *def, alsys_action_e action)
{
    word_t word;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    if (lex_expected_fetch((lex_t *)lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.type == WORD_TYPE_STRING) {
        sql_remove_quota(&word.text.value);
    }

    cm_trim_text((text_t *)&word.text);
    CT_RETURN_IFERR(cm_text2str((text_t *)&word.text, sys_def->value, CT_PARAM_BUFFER_SIZE));

    if (!cm_check_ip_valid(sys_def->value)) {
        CT_SRC_THROW_ERROR(lex->loc, ERR_TCP_INVALID_IPADDRESS, sys_def->value);
        return CT_ERROR;
    }

    def->action = action;
    return lex_expected_end(lex);
}

static status_t sql_parse_alsys_modify_hba_conf(lex_t *lex, knl_alter_sys_def_t *def, alsys_action_e action)
{
    word_t word;
    knl_alter_sys_def_t *sys_def = (knl_alter_sys_def_t *)def;

    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "ENTRY"));
    if (lex_expected_fetch((lex_t *)lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (word.type == WORD_TYPE_STRING) {
        sql_remove_quota(&word.text.value);
    }

    if (word.text.len > HBA_MAX_LINE_SIZE) {
        CT_THROW_ERROR(ERR_LINE_SIZE_TOO_LONG, 1);
        return CT_ERROR;
    }

    cm_trim_text((text_t *)&word.text);
    CT_RETURN_IFERR(cm_text2str((text_t *)&word.text, sys_def->hba_node, HBA_MAX_LINE_SIZE));

    // check whether hba config is legal
    CT_RETURN_IFERR(cm_check_hba_entry_legality(sys_def->hba_node));

    def->action = action;
    return lex_expected_end(lex);
}

static status_t sql_parse_alsys_add_param_node(lex_t *lex, knl_alter_sys_def_t *def)
{
    if (lex_expected_fetch_word(lex, "LSNR_ADDR") == CT_SUCCESS) {
        // ADD LSNR_ADDR
        return sql_parse_alsys_modify_lsnr_addr(lex, def, ALTER_SYS_ADD_LSNR_ADDR);
    } else if (lex_expected_fetch_word(lex, "HBA") == CT_SUCCESS) {
        // ADD HBA ENTRY
        cm_reset_error();
        return sql_parse_alsys_modify_hba_conf(lex, def, ALTER_SYS_ADD_HBA_ENTRY);
    } else {
        cm_reset_error();
        CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "LSNR_ADDR or HBA expected");
        return CT_ERROR;
    }
}

static status_t sql_parse_alsys_del_param_node(lex_t *lex, knl_alter_sys_def_t *def)
{
    if (lex_expected_fetch_word(lex, "LSNR_ADDR") == CT_SUCCESS) {
        // DELETE LSNR_ADDR
        return sql_parse_alsys_modify_lsnr_addr(lex, def, ALTER_SYS_DELETE_LSNR_ADDR);
    } else if (lex_expected_fetch_word(lex, "HBA") == CT_SUCCESS) {
        // DELETE HBA ENTRY
        cm_reset_error();
        return sql_parse_alsys_modify_hba_conf(lex, def, ALTER_SYS_DEL_HBA_ENTRY);
    } else {
        cm_reset_error();
        CT_SRC_THROW_ERROR_EX(LEX_LOC, ERR_SQL_SYNTAX_ERROR, "LSNR_ADDR or HBA expected");
        return CT_ERROR;
    }
}

static status_t sql_parse_alsys_debug_mode(session_t *session, knl_alter_sys_def_t *def, word_t *word)
{
    debug_config_item_t *debug_params = NULL;
    debug_config_item_t *item = NULL;
    uint32 count;
    lex_t *lex = session->lex;
    knl_session_t *se = &session->knl_session;

    def->action = ALTER_SYS_DEBUG_MODE;

    if (lex_expected_fetch_word(lex, "MODE") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_variant(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cm_text2str((text_t *)&word->text, def->param, CT_NAME_BUFFER_SIZE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    cm_str_upper(def->param);

    if (lex_expected_fetch_word(lex, "=") != CT_SUCCESS) {
        return CT_ERROR;
    }

    srv_get_debug_config_info(&debug_params, &count);

    for (uint32 i = 0; i < count; i++) {
        if (cm_str_equal_ins(debug_params[i].name, def->param)) {
            item = &debug_params[i];
            break;
        }
    }

    if (item == NULL) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER_NAME, def->param);
        return CT_ERROR;
    }

    if (item->verify((knl_handle_t)se, (void *)lex, (void *)def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return lex_expected_end(lex);
}

static status_t sql_parse_alsys_stop(lex_t *lex, knl_alter_sys_def_t *def)
{
    if (lex_expected_fetch_word(lex, "BUILD") != CT_SUCCESS) {
        return CT_ERROR;
    }

    def->action = ALTER_SYS_STOP_BUILD;
    return lex_expected_end(lex);
}

static status_t sql_parse_alsys_repair(lex_t *lex, knl_alter_sys_def_t *def)
{
    if (lex_expected_fetch_word(lex, "CATALOG") != CT_SUCCESS) {
        return CT_ERROR;
    }
    def->action = ALTER_SYS_REPAIR_CATALOG;
    return lex_expected_end(lex);
}

status_t set_log_parameter(const char *name)
{
    char log_name[CT_LOG_PARAM_CNT][CT_MAX_PARAM_LEN] = {
        { "_BLACKBOX_STACK_DEPTH" },
        { "ALARM_LOG_DIR" },
        { "AUDIT_LEVEL" },
        { "AUDIT_TRAIL_MODE" },
        { "LOG_HOME" },
        { "_LOG_BACKUP_FILE_COUNT" },
        { "_LOG_MAX_FILE_SIZE" },
        { "_LOG_LEVEL" },
        { "_LOG_FILE_PERMISSIONS" },
        { "_LOG_PATH_PERMISSIONS" },
        { "LONGSQL_TIMEOUT" },
        { "RAFT_LOG_LEVEL" },
        { "_LONGSQL_STATS_PRINT" }
    };
    for (uint32 i = 0; i < CT_LOG_PARAM_CNT; i++) {
        if (cm_str_equal(name, log_name[i])) {
            return CT_SUCCESS;
        }
    }
    return CT_ERROR;
}

static status_t sql_parse_alter_system(sql_stmt_t *stmt)
{
    word_t word;
    knl_alter_sys_def_t *sys_def = NULL;
    status_t status;

    stmt->context->type = CTSQL_TYPE_ALTER_SYSTEM;
    SQL_SET_IGNORE_PWD(stmt->session);
    SQL_SET_COPY_LOG(stmt->session, CT_TRUE);
    status = sql_alloc_mem(stmt->context, sizeof(knl_alter_sys_def_t), (void **)&sys_def);
    CT_RETURN_IFERR(status);

    status = lex_expected_fetch(stmt->session->lex, &word);
    CT_RETURN_IFERR(status);

    switch ((key_wid_t)word.id) {
        case KEY_WORD_SWITCH:
            status = sql_parse_alsys_switch(stmt->session->lex, sys_def, &word);
            break;

        case KEY_WORD_SET:
            status = sql_parse_alsys_set(stmt->session, sys_def, &word);
            if (((cm_log_param_instance()->audit_param.audit_level & SQL_AUDIT_DCL) == 0) &&
                set_log_parameter(sys_def->param) == CT_SUCCESS) {
                sql_audit_log(stmt->session, status, CT_FALSE, CT_TRUE);
            }
            break;

        case KEY_WORD_LOAD:
            status = sql_parse_alsys_load(stmt, sys_def, &word);
            break;

        case KEY_WORD_INIT:
            status = sql_parse_alsys_init(stmt, sys_def, &word);
            break;

        case KEY_WORD_FLUSH:
            status = sql_parse_alsys_flush(stmt->session->lex, sys_def, &word);
            break;

        case KEY_WORD_RECYCLE:
            status = sql_parse_alsys_recycle(stmt->session->lex, sys_def, &word);
            break;

        case KEY_WORD_DUMP:
            status = sql_parse_alsys_dump(stmt, stmt->session->lex, sys_def, &word);
            break;

        case KEY_WORD_KILL:
            status = sql_parse_alsys_kill(stmt, stmt->session->lex, sys_def);
            break;

        case KEY_WORD_RESET:
            status = sql_parse_alsys_reset(stmt, stmt->session->lex, sys_def);
            break;

        case KEY_WORD_CHECKPOINT:
            status = sql_parse_alsys_checkpoint(stmt->session->lex, sys_def);
            break;

        case KEY_WORD_ARCHIVE_SET:
            status = sql_parse_alsys_arch_set(stmt->session, sys_def, &word);
            break;

        case KEY_WORD_RELOAD:
            status = sql_parse_reload_conf(stmt->session->lex, sys_def);
            break;

        case KEY_WORD_REFRESH:
            status = sql_parse_refresh_sysdba_privilege(stmt->session->lex, sys_def);
            break;
        case KEY_WORD_ADD:
            status = sql_parse_alsys_add_param_node(stmt->session->lex, sys_def);
            break;
        case KEY_WORD_DELETE:
            status = sql_parse_alsys_del_param_node(stmt->session->lex, sys_def);
            break;
        case KEY_WORD_DEBUG:
            status = sql_parse_alsys_debug_mode(stmt->session, sys_def, &word);
            break;
        case KEY_WORD_STOP:
            status = sql_parse_alsys_stop(stmt->session->lex, sys_def);
            break;
        case KEY_WORD_REPAIR:
            status = sql_parse_alsys_repair(stmt->session->lex, sys_def);
            break;
        default:
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(&word));
            return CT_ERROR;
    }

    stmt->context->entry = sys_def;

    return status;
}

typedef struct st_altset_item altset_item_t;
typedef status_t (*sql_value_parser)(sql_stmt_t *stmt, lex_t *lex, altset_def_t *setting, const altset_item_t *item);
struct st_altset_item {
    text_t name;
    altset_type_t type;
    uint32 id;
    sql_value_parser parser;
};

static status_t sql_parse_set_commit_wait_logging(sql_stmt_t *stmt, lex_t *lex, altset_def_t *def,
    const altset_item_t *item)
{
    word_t word;
    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "="));
    do {
        CT_RETURN_IFERR(lex_expected_fetch(lex, &word));
        if (word.type == WORD_TYPE_STRING) {
            LEX_REMOVE_WRAP(&word);
        }
        cm_trim_text(&word.text.value);
        if (cm_text_str_equal_ins(&word.text.value, "WAIT")) {
            def->commit.nowait = CT_FALSE;
        } else if (cm_text_str_equal_ins(&word.text.value, "NOWAIT")) {
            def->commit.nowait = CT_TRUE;
        } else {
            break;
        }
        def->set_type = SET_COMMIT;
        def->commit.action = COMMIT_WAIT;
        return lex_expected_end(lex);
    } while (0);

    CT_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "invalid parameter value");
    return CT_ERROR;
}

static status_t sql_parse_set_commit_mode(sql_stmt_t *stmt, lex_t *lex, altset_def_t *def, const altset_item_t *item)
{
    word_t word;

    if (lex_expected_fetch_word(lex, "=") != CT_SUCCESS) {
        return CT_ERROR;
    }

    do {
        CT_RETURN_IFERR(lex_expected_fetch(lex, &word));
        if (word.type == WORD_TYPE_STRING || word.type == WORD_TYPE_DQ_STRING) {
            LEX_REMOVE_WRAP(&word);
        } else if (!IS_VARIANT(&word)) {
            break;
        }

        cm_trim_text(&word.text.value);
        if (cm_text_str_equal_ins(&word.text.value, "IMMEDIATE")) {
            def->commit.batch = CT_FALSE;
        } else if (cm_text_str_equal_ins(&word.text.value, "BATCH")) {
            def->commit.batch = CT_TRUE;
        } else {
            break;
        }

        def->set_type = SET_COMMIT;
        def->commit.action = COMMIT_LOGGING;
        return lex_expected_end(lex);
    } while (0);

    CT_SRC_THROW_ERROR_EX(word.loc, ERR_SQL_SYNTAX_ERROR, "invalid parameter value");
    return CT_ERROR;
}

static status_t sql_parse_set_lockwait_timeout(sql_stmt_t *stmt, lex_t *lex, altset_def_t *def,
    const altset_item_t *item)
{
    uint32 value;
    if (lex_expected_fetch_word(lex, "=") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_uint32(lex, &value) != CT_SUCCESS) {
        return CT_ERROR;
    }

    def->set_type = SET_LOCKWAIT_TIMEOUT;
    def->lock_wait_timeout.lock_wait_timeout = value;
    return lex_expected_end(lex);
}

static status_t sql_parse_set_curr_schema(sql_stmt_t *stmt, lex_t *lex, altset_def_t *def, const altset_item_t *item)
{
    word_t value;
    char buf[CT_NAME_BUFFER_SIZE];
    text_t schema;

    if (lex_expected_fetch_word(lex, "=") != CT_SUCCESS) {
        return CT_ERROR;
    }

    CT_RETURN_IFERR(lex_expected_fetch(lex, &value));
    def->set_type = SET_SCHEMA;
    if (value.type == WORD_TYPE_STRING) {
        sql_remove_quota(&value.text.value);
        if (value.text.len == 0) {
            CT_SRC_THROW_ERROR(value.loc, ERR_EMPTY_STRING_NOT_ALLOWED);
            return CT_ERROR;
        }
    }

    if (cm_text2str(&value.text.value, buf, CT_NAME_BUFFER_SIZE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_user_prefix_tenant(stmt->session, buf) != CT_SUCCESS) {
        return CT_ERROR;
    }

    (void)cm_str2text(buf, &schema);
    if (sql_copy_name(stmt->context, &schema, &def->curr_schema) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return lex_expected_end(lex);
}

static status_t sql_parse_set_session_timezone(sql_stmt_t *stmt, lex_t *lex, altset_def_t *def,
    const altset_item_t *item)
{
    word_t value;

    if (lex_expected_fetch_word(lex, "=") != CT_SUCCESS) {
        return CT_ERROR;
    }

    CT_RETURN_IFERR(lex_expected_fetch_string(lex, &value));

    def->set_type = SET_SESSION_TIMEZONE;
    if (sql_copy_name(stmt->context, &value.text.value, &def->timezone_offset_name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return lex_expected_end(lex);
}

static status_t sql_parse_set_nlsparam(sql_stmt_t *stmt, lex_t *lex, altset_def_t *def, const altset_item_t *item)
{
    word_t word;
    if (lex_expected_fetch_word(lex, "=") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_string(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    def->set_type = SET_NLS_PARAMS;
    def->nls_seting.id = (nlsparam_id_t)item->id;
    cm_trim_text(&word.text.value);

    if (sql_copy_text(stmt->context, &word.text.value, &def->nls_seting.value) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return lex_expected_end(lex);
}

static const altset_item_t *sql_get_altset_nlsitems(void)
{
    static altset_item_t altset_nls_items[NLS__MAX_PARAM_NUM];
    static bool32 initialized = CT_FALSE; /* for only initializing 1 time */

    if (initialized) {
        return altset_nls_items;
    }
    for (uint32 i = 0; i < NLS__MAX_PARAM_NUM; i++) {
        altset_nls_items[i].name = g_nlsparam_items[i].key;
        altset_nls_items[i].type = SET_NLS_PARAMS;
        altset_nls_items[i].id = g_nlsparam_items[i].id;
        altset_nls_items[i].parser = sql_parse_set_nlsparam;
    }
    initialized = CT_TRUE;
    return altset_nls_items;
}

static inline status_t sql_try_parse_altset_item(sql_stmt_t *stmt, lex_t *lex, word_t *word, const altset_item_t *items,
    uint32 num, altset_def_t *def, bool32 *found)
{
    uint32 i;
    for (i = 0; i < num; i++) {
        if (cm_text_equal_ins(&(word->text.value), &(items[i].name))) {
            if (sql_copy_text(stmt->context, &word->text.value, &def->pkey) != CT_SUCCESS) {
                return CT_ERROR;
            }

            *found = CT_TRUE;
            return items[i].parser(stmt, lex, def, &items[i]);
        }
    }

    *found = CT_FALSE;
    return CT_SUCCESS;
}

static status_t sql_parse_set_show_explain_predicate(sql_stmt_t *stmt, lex_t *lex, altset_def_t *def,
    const altset_item_t *item)
{
    uint32 match_id;

    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "="));
    CT_RETURN_IFERR(lex_expected_fetch_1of2((lex_t *)lex, "FALSE", "TRUE", &match_id));

    def->on_off = (match_id == 0) ? CT_FALSE : CT_TRUE;
    def->set_type = SET_SHOW_EXPLAIN_PREDICATE;

    return lex_expected_end(lex);
}

static status_t sql_parse_set_shd_socket_timeout(sql_stmt_t *stmt, lex_t *lex, altset_def_t *def,
    const altset_item_t *item)
{
    uint32 value;
    if (lex_expected_fetch_word(lex, "=") != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (lex_expected_fetch_uint32(lex, &value) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (value > CT_MAX_TIMEOUT_VALUE) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "SHD_SOCKET_TIMEOUT", (int64)0, (int64)CT_MAX_TIMEOUT_VALUE);
        return CT_ERROR;
    }
    def->set_type = SET_SHD_SOCKET_TIMEOUT;
    def->shd_socket_timeout = value;
    return lex_expected_end(lex);
}

static status_t sql_parse_set_tenant(sql_stmt_t *stmt, lex_t *lex, altset_def_t *def, const altset_item_t *item)
{
    word_t value;

    if (lex_expected_fetch_word(lex, "=") != CT_SUCCESS) {
        return CT_ERROR;
    }

    CT_RETURN_IFERR(lex_expected_fetch(lex, &value));
    def->set_type = SET_TENANT;

    if (sql_copy_name(stmt->context, &value.text.value, &def->tenant) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return lex_expected_end(lex);
}

static status_t sql_parse_set_outer_join_opt(sql_stmt_t *stmt, lex_t *lex, altset_def_t *def, const altset_item_t *item)
{
    uint32 match_id;

    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "="));
    CT_RETURN_IFERR(lex_expected_fetch_1of2((lex_t *)lex, "OFF", "ON", &match_id));

    def->on_off = (match_id == 0) ? CT_FALSE : CT_TRUE;
    def->set_type = SET_OUTER_JOIN_OPT;

    return lex_expected_end(lex);
}

static status_t sql_parse_set_cbo_index_caching(sql_stmt_t *stmt, lex_t *lex, altset_def_t *def,
    const altset_item_t *item)
{
    uint32 value;
    if (lex_expected_fetch_word(lex, "=") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_uint32(lex, &value) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (value > CBO_MAX_INDEX_CACHING) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "CBO_INDEX_CACHING", (int64)CBO_MAX_INDEX_CACHING);
        return CT_ERROR;
    }

    def->set_type = SET_CBO_INDEX_CACHING;
    def->cbo_index_caching = value;
    return lex_expected_end(lex);
}

static status_t sql_parse_set_cbo_index_cost_adj(sql_stmt_t *stmt, lex_t *lex, altset_def_t *def,
    const altset_item_t *item)
{
    uint32 value;
    if (lex_expected_fetch_word(lex, "=") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_uint32(lex, &value) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (value > CBO_MAX_INDEX_COST_ADJ) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "CBO_INDEX_COST_ADJ", (int64)CBO_MAX_INDEX_COST_ADJ);
        return CT_ERROR;
    } else if (value < CBO_MIN_INDEX_COST_ADJ) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "CBO_INDEX_COST_ADJ", (int64)CBO_MIN_INDEX_COST_ADJ);
        return CT_ERROR;
    }
    def->set_type = SET_CBO_INDEX_COST_ADJ;
    def->cbo_index_cost_adj = value;
    return lex_expected_end(lex);
}

static status_t sql_parse_set_withas_subquery(sql_stmt_t *stmt, lex_t *lex, altset_def_t *def,
    const altset_item_t *item)
{
    uint32 value;
    const char *match_words[] = { "OPTIMIZER", "MATERIALIZE", "INLINE" };

    if (lex_expected_fetch_word(lex, "=") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_1of3(lex, match_words[0], match_words[1], match_words[2], &value) != CT_SUCCESS) {
        return CT_ERROR;
    }

    def->set_type = SET_WITHAS_SUBQUERY;
    def->withas_subquery = value;
    return lex_expected_end(lex);
}

static status_t sql_parse_set_cursor_sharing(sql_stmt_t *stmt, lex_t *lex, altset_def_t *def, const altset_item_t *item)
{
    uint32 match_id;

    CT_RETURN_IFERR(lex_expected_fetch_word(lex, "="));
    CT_RETURN_IFERR(lex_expected_fetch_1of2((lex_t *)lex, "OFF", "ON", &match_id));

    def->on_off = (match_id == 0) ? CT_FALSE : CT_TRUE;
    def->set_type = SET_CURSOR_SHARING;

    return lex_expected_end(lex);
}

static status_t sql_parse_set_plan_display_format(sql_stmt_t *stmt, lex_t *lex, altset_def_t *def,
    const altset_item_t *item)
{
    uint32 value = 0;

    if (lex_expected_fetch_word(lex, "=") != CT_SUCCESS) {
        return CT_ERROR;
    }

    uint32 format_index = CT_INVALID_ID32;
    // 3 is PLAN_DISPLAY_OPTION_COUNT
    bool32 option_flag[3] = { CT_FALSE };
    uint32 flag_count = ELEMENT_COUNT(option_flag);
    char str[CT_PARAM_BUFFER_SIZE];

    CT_RETURN_IFERR(sql_get_plan_display_format_info(lex, &format_index, option_flag, flag_count));

    CT_RETURN_IFERR(
        sql_normalize_plan_display_format_value(str, CT_PARAM_BUFFER_SIZE, format_index, option_flag, flag_count));

    sql_set_plan_display_format(str, &value);

    def->set_type = SET_PLAN_DISPLAY_FORMAT;
    def->plan_display_format = value;
    return lex_expected_end(lex);
}

static inline status_t sql_parse_altses_set(sql_stmt_t *stmt, lex_t *lex, altset_def_t *def)
{
    static const altset_item_t g_altsession_items[] = {
        { { "commit_wait", 11 }, SET_COMMIT, CT_INVALID_ID32, sql_parse_set_commit_wait_logging },
        { { "commit_wait_logging", 19 }, SET_COMMIT, CT_INVALID_ID32, sql_parse_set_commit_wait_logging },
        { { "commit_logging", 14 }, SET_COMMIT, CT_INVALID_ID32, sql_parse_set_commit_mode },
        { { "commit_mode", 11 }, SET_COMMIT, CT_INVALID_ID32, sql_parse_set_commit_mode },
        { { "lock_wait_timeout", 17 }, SET_LOCKWAIT_TIMEOUT, CT_INVALID_ID32, sql_parse_set_lockwait_timeout },
        { { "current_schema", 14 }, SET_SCHEMA, CT_INVALID_ID32, sql_parse_set_curr_schema },
        { { "time_zone", 9 }, SET_SESSION_TIMEZONE, CT_INVALID_ID32, sql_parse_set_session_timezone },
        { { "_show_explain_predicate", 23 }, SET_SHOW_EXPLAIN_PREDICATE, CT_INVALID_ID32, sql_parse_set_show_explain_predicate },
        { { "shd_socket_timeout", 18 }, SET_SHD_SOCKET_TIMEOUT, CT_INVALID_ID32, sql_parse_set_shd_socket_timeout },
        { { "tenant", 6 }, SET_TENANT, CT_INVALID_ID32, sql_parse_set_tenant },
        { { "_outer_join_optimization", 24 }, SET_OUTER_JOIN_OPT, CT_INVALID_ID32, sql_parse_set_outer_join_opt },
        { { "cbo_index_caching", 17 }, SET_CBO_INDEX_CACHING, CT_INVALID_ID32, sql_parse_set_cbo_index_caching },
        { { "cbo_index_cost_adj", 18 }, SET_CBO_INDEX_COST_ADJ, CT_INVALID_ID32, sql_parse_set_cbo_index_cost_adj },
        { { "_withas_subquery", 16 }, SET_WITHAS_SUBQUERY, CT_INVALID_ID32, sql_parse_set_withas_subquery },
        { { "_cursor_sharing", 15 }, SET_CURSOR_SHARING, CT_INVALID_ID32, sql_parse_set_cursor_sharing },
        { { "plan_display_format", 19 }, SET_PLAN_DISPLAY_FORMAT, CT_INVALID_ID32, sql_parse_set_plan_display_format },
    };

    bool32 found = CT_FALSE;
    status_t status;
    word_t word;

    if (lex_expected_fetch(lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (word.type != WORD_TYPE_VARIANT && (((key_wid_t)word.id) != KEY_WORD_TIMEZONE) &&
        (((key_wid_t)word.id) != KEY_WORD_TENANT)) {
        CT_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "missing or invalid parameter");
        return CT_ERROR;
    }

    status =
        sql_try_parse_altset_item(stmt, lex, &word, g_altsession_items, ELEMENT_COUNT(g_altsession_items), def, &found);
    CT_RETURN_IFERR(status);
    if (found) {
        return CT_SUCCESS;
    }

    status = sql_try_parse_altset_item(stmt, lex, &word, sql_get_altset_nlsitems(), NLS__MAX_PARAM_NUM, def, &found);
    CT_RETURN_IFERR(status);
    if (found) {
        return CT_SUCCESS;
    }

    CT_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "missing or invalid parameter");
    return CT_ERROR;
}

static const word_record_t g_altsess_opt_set[] = {
    {.id = ABLE_TRIGGERS, .tuple = { 1, { "TRIGGERS" } } },
    {.id = ABLE_INAV_TO, .tuple = { 2, { "INTERACTIVE", "TIMEOUT" } } },
    {.id = ABLE_NOLOGGING, .tuple = { 1, { "NOLOGGING" } } },
    {.id = ABLE_OPTINFO, .tuple = { 1, { "OPTINFO_LOG" } } },
};
#define ALT_SESS_OPT_SIZE ELEMENT_COUNT(g_altsess_opt_set)

static inline status_t sql_parse_altses_able(sql_stmt_t *stmt, lex_t *lex, altable_def_t *def)
{
    uint32 matched_id;

    CT_RETURN_IFERR(lex_try_match_records(lex, g_altsess_opt_set, ALT_SESS_OPT_SIZE, (uint32 *)&matched_id));

    if (matched_id == CT_INVALID_ID32) {
        CT_SRC_THROW_ERROR_EX(lex->loc, ERR_SQL_SYNTAX_ERROR, "missing or invalid parameter");
        return CT_ERROR;
    }
    def->able_type = (altable_type_t)matched_id;
    return lex_expected_end(lex);
}

static status_t sql_parse_alter_session(sql_stmt_t *stmt)
{
    status_t status;
    word_t word;
    lex_t *lex = stmt->session->lex;
    alter_session_def_t *def = NULL;

    if (sql_alloc_mem(stmt->context, sizeof(alter_session_def_t), (void **)&def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch(stmt->session->lex, &word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    switch ((key_wid_t)word.id) {
        case KEY_WORD_SET:
            def->action = ALTSES_SET;
            status = sql_parse_altses_set(stmt, lex, &def->setting);
            break;

        case KEY_WORD_DISABLE:
            def->action = ALTSES_DISABLE;
            def->setable.enable = CT_FALSE;
            status = sql_parse_altses_able(stmt, lex, &def->setable);
            break;

        case KEY_WORD_ENABLE:
            def->action = ALTSES_ENABLE;
            def->setable.enable = CT_TRUE;
            status = sql_parse_altses_able(stmt, lex, &def->setable);
            break;

        default:
            CT_SRC_THROW_ERROR_EX(word.text.loc, ERR_SQL_SYNTAX_ERROR, "key word expected but %s found", W2S(&word));
            return CT_ERROR;
    }

    stmt->context->type = CTSQL_TYPE_ALTER_SESSION;
    stmt->context->entry = def;

    return status;
}


status_t sql_parse_dcl_alter(sql_stmt_t *stmt)
{
    word_t word;
    status_t status;

    status = lex_fetch(stmt->session->lex, &word);
    CT_RETURN_IFERR(status);

    switch ((uint32)word.id) {
        case KEY_WORD_SYSTEM:
            status = sql_parse_alter_system(stmt);
            break;

        case KEY_WORD_SESSION:
            status = sql_parse_alter_session(stmt);
            break;

        default:
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "object type expected but %s found", W2S(&word));
            status = CT_ERROR;
            break;
    }

    return status;
}

#ifdef __cplusplus
}
#endif
