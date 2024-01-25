#include "dtc_parser.h"
#include "ddl_parser.h"
#include "dtc_database.h"
#include "srv_instance.h"
#include "ddl_database_parser.h"
#include "cm_dbs_intf.h"

/* ********************* SYNTAX DEMO ************************
create database clustered db_name
controlfile('ctrl1', 'ctrl2', 'ctrl3')
system     tablespace      datafile 'system.dat' size 128M
temporary  tablespace      tempfile 'temp.dat' size 100M
temporary  undo tablespace tempfile 'temp_undo.dat' size 100M
default    tablespace      datafile 'user.dat' size 100M
doublewrite area 'sysdwa.dat'
instance
node 0
undo tablespace datafile 'undo11.dat' size 128M
swap tablespace tempfile 'swap1.dat' size 100M
logfile ('redo11.dat' size 128M, 'redo12.dat' size 128M, 'redo13.dat' size 128M)
node 1
undo tablespace datafile 'undo21.dat' size 128M
swap tablespace tempfile 'swap2.dat' size 100M
logfile ('redo21.dat' size 128M, 'redo22.dat' size 128M, 'redo23.dat' size 128M)
/
*/

static status_t dtc_parse_undo_space(sql_stmt_t *stmt, dtc_node_def_t *node, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    char *name;
    errno_t code;

    if (lex_expected_fetch_word(lex, "tablespace") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_alloc_mem(stmt->context, CT_NAME_BUFFER_SIZE, (void **)&name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    code = snprintf_s(name, CT_NAME_BUFFER_SIZE, CT_NAME_BUFFER_SIZE - 1, "UNDO_%02u", node->id);
    PRTS_RETURN_IFERR(code);

    node->undo_space.name.str = name;
    node->undo_space.name.len = (uint32)strlen(name);
    node->undo_space.type = SPACE_TYPE_UNDO | SPACE_TYPE_DEFAULT;

    if (lex_expected_fetch_word(lex, "datafile") != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_parse_dbca_datafile_spec(stmt, lex, word, &node->undo_space);
}

static status_t dtc_parse_temp_undo_space(sql_stmt_t *stmt, dtc_node_def_t *node, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    char *name;
    errno_t code;

    if (lex_expected_fetch_word(lex, "undo") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (lex_expected_fetch_word(lex, "tablespace") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_alloc_mem(stmt->context, CT_NAME_BUFFER_SIZE, (void **)&name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    code = snprintf_s(name, CT_NAME_BUFFER_SIZE, CT_NAME_BUFFER_SIZE - 1, "TEMP_UNDO_%u1", node->id);
    PRTS_RETURN_IFERR(code);

    node->temp_undo_space.name.str = name;
    node->temp_undo_space.name.len = (uint32)strlen(name);
    node->temp_undo_space.type = SPACE_TYPE_UNDO | SPACE_TYPE_DEFAULT | SPACE_TYPE_TEMP;

    if (lex_expected_fetch_word(lex, "TEMPFILE") != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_parse_dbca_datafile_spec(stmt, lex, word, &node->temp_undo_space);
}

static status_t dtc_parse_swap_space(sql_stmt_t *stmt, dtc_node_def_t *node, word_t *word)
{
    lex_t *lex = stmt->session->lex;
    char *name;
    errno_t code;

    if (lex_expected_fetch_word(lex, "tablespace") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_alloc_mem(stmt->context, CT_NAME_BUFFER_SIZE, (void **)&name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    code = snprintf_s(name, CT_NAME_BUFFER_SIZE, CT_NAME_BUFFER_SIZE - 1, "SWAP_%02u", node->id);
    PRTS_RETURN_IFERR(code);

    node->swap_space.name.str = name;
    node->swap_space.name.len = (uint32)strlen(name);
    node->swap_space.type = SPACE_TYPE_TEMP | SPACE_TYPE_SWAP | SPACE_TYPE_DEFAULT;

    if (lex_expected_fetch_word(lex, "TEMPFILE") != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_parse_dbca_datafile_spec(stmt, lex, word, &node->swap_space);
}

static status_t dtc_parse_node_def(sql_stmt_t *stmt, knl_database_def_t *def, word_t *word)
{
    dtc_node_def_t *node;
    lex_t *lex = stmt->session->lex;

    if (cm_galist_new(&def->nodes, sizeof(dtc_node_def_t), (pointer_t *)&node) != CT_SUCCESS) {
        return CT_ERROR;
    }

    node->id = def->nodes.count - 1;
    cm_galist_init(&node->logfiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&node->undo_space.datafiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&node->swap_space.datafiles, stmt->context, sql_alloc_mem);
    cm_galist_init(&node->temp_undo_space.datafiles, stmt->context, sql_alloc_mem);

    if (lex_expected_fetch(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }

    for (;;) {
        switch (word->id) {
            case KEY_WORD_UNDO:
                if (dtc_parse_undo_space(stmt, node, word) != CT_SUCCESS) {
                    return CT_ERROR;
                }
                break;

            case KEY_WORD_LOGFILE:
                if (sql_parse_dbca_logfiles(stmt, &node->logfiles, word) != CT_SUCCESS) {
                    return CT_ERROR;
                }
                break;

            case KEY_WORD_TEMPORARY:
                if (dtc_parse_swap_space(stmt, node, word) != CT_SUCCESS) {
                    return CT_ERROR;
                }
                break;
            case KEY_WORD_NO_LOGGING:
                if (dtc_parse_temp_undo_space(stmt, node, word) != CT_SUCCESS) {
                    return CT_ERROR;
                }
                break;
            default:
                return CT_SUCCESS;
        }
    }

    return CT_SUCCESS;
}

static status_t dtc_parse_nodes(sql_stmt_t *stmt, knl_database_def_t *def, word_t *word)
{
    uint32 node_id, id;
    lex_t *lex = stmt->session->lex;

    if (lex_expected_fetch_word(lex, "node")) {
        return CT_ERROR;
    }

    node_id = 0;

    for (;;) {
        if (lex_expected_fetch_uint32(lex, &id) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (id != node_id) {
            CT_SRC_THROW_ERROR_EX(lex->loc, ERR_INVALID_DATABASE_DEF, "instance number error, '%u' expected", node_id);
            return CT_ERROR;
        }

        if (dtc_parse_node_def(stmt, def, word) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (word->id != KEY_WORD_NODE) {
            break;
        }

        node_id++;
    }

    return CT_SUCCESS;
}

status_t dtc_parse_instance(sql_stmt_t *stmt, knl_database_def_t *def, word_t *word)
{
    lex_t *lex = stmt->session->lex;

    if (def->nodes.count > 0) {
        CT_SRC_THROW_ERROR(lex->loc, ERR_SQL_SYNTAX_ERROR, "INSTANCE is already defined");
        return CT_ERROR;
    }

    return dtc_parse_nodes(stmt, def, word);
}

status_t dtc_parse_maxinstance(sql_stmt_t *stmt, knl_database_def_t *def, word_t *word)
{
    lex_t *lex = stmt->session->lex;

    return lex_expected_fetch_uint32(lex, &def->max_instance);
}

static status_t dtc_verify_node(sql_stmt_t *stmt, knl_database_def_t *def, uint32 id)
{
    dtc_node_def_t *node;
    node = (dtc_node_def_t *)cm_galist_get(&def->nodes, id);
    if (node->undo_space.name.len == 0 || node->undo_space.datafiles.count == 0) {
        CT_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "UNDO tablespace of instances %d is not specific", id + 1);
        return CT_ERROR;
    }

    if (node->swap_space.name.len == 0 || node->swap_space.datafiles.count == 0) {
        CT_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "no device specified for swap tablespace");
        return CT_ERROR;
    }

    if (node->temp_undo_space.name.len == 0 || node->temp_undo_space.datafiles.count == 0) {
        CT_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "TEMP_UNDO tablespace of instances %d is not specific", id + 1);
        return CT_ERROR;
    }

    if (cm_dbs_is_enable_dbs() == CT_TRUE) {
        if (node->logfiles.count == 1) {
            return CT_SUCCESS;
        }
        CT_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "the number of redo log files is invalid, should be 1 for DBstor.");
        return CT_ERROR;
    }

    if (node->logfiles.count < CT_MIN_LOG_FILES || node->logfiles.count > CT_MAX_LOG_FILES) {
        CT_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "the number of redo log files is invalid, should be in [3, 256]");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t dtc_verify_instances(sql_stmt_t *stmt, knl_database_def_t *def)
{
    uint32 i;

    if (def->nodes.count < 1 || def->nodes.count > CT_MAX_INSTANCES) {
        CT_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "the number of instances is invalid");
        return CT_ERROR;
    }

    for (i = 0; i < def->nodes.count; i++) {
        if (dtc_verify_node(stmt, def, i) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t dtc_verify_database_def(sql_stmt_t *stmt, knl_database_def_t *def)
{
    galist_t *list = NULL;
    knl_device_def_t *dev = NULL;

    list = &def->ctrlfiles;
    if (list->count < 2 || list->count > CT_MAX_CTRL_FILES) {
        CT_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "the number of control files is invalid");
        return CT_ERROR;
    }

    if (dtc_verify_instances(stmt, def) != CT_SUCCESS) {
        return CT_ERROR;
    }

    list = &def->system_space.datafiles;
    if (list->count == 0) {
        CT_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "no device specified for system tablespace");
        return CT_ERROR;
    }

    dev = cm_galist_get(list, 0);
    if (dev->size < SYSTEM_FILE_MIN_SIZE) {
        CT_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "first system file size less than %d(MB)",
            SYSTEM_FILE_MIN_SIZE / SIZE_M(1));
        return CT_ERROR;
    }

    list = &def->temp_space.datafiles;
    if (list->count == 0) {
        CT_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "no device specified for temporary tablespace");
        return CT_ERROR;
    }

    list = &def->temp_undo_space.datafiles;
    if (list->count == 0) {
        CT_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "no device specified for temporary undo tablespace");
        return CT_ERROR;
    }

    if (strlen(def->sys_password) != 0 && cm_compare_str_ins(def->sys_password, SYS_USER_NAME) != 0) {
        CT_RETURN_IFERR(cm_verify_password_str(SYS_USER_NAME, def->sys_password, CT_PASSWD_MIN_LEN));
    }

    if (g_instance->kernel.db.status != DB_STATUS_NOMOUNT) {
        CT_THROW_ERROR(ERR_DATABASE_ALREADY_MOUNT, "database already mounted");
        return CT_ERROR;
    }

    list = &def->sysaux_space.datafiles;
    if (list->count != 1) {
        CT_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "sysaux must have only one datafile");
        return CT_ERROR;
    }
    dev = cm_galist_get(list, 0);
    uint32 min_size = CT_MIN_SYSAUX_DATAFILE_SIZE +
        (def->nodes.count - 1) * DOUBLE_WRITE_PAGES * SIZE_K(8); /* default page size is SIZE_K(8) */
    if (dev->size < min_size) {
        CT_THROW_ERROR_EX(ERR_INVALID_DATABASE_DEF, "first datafile size less than %d(MB), node count(%d)",
            min_size / SIZE_M(1), def->nodes.count);
        return CT_ERROR;
    }

    if (def->max_instance > CT_MAX_INSTANCES) {
        CT_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "MAXINSTANCES larger than 64");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t dtc_parse_create_database(sql_stmt_t *stmt)
{
    return CT_ERROR;
}
