#ifndef __DTC_PARSER_H__
#define __DTC_PARSER_H__


#include "cm_defs.h"
#include "ctsql_stmt.h"
#include "cm_lex.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t dtc_parse_create_database(sql_stmt_t *stmt);
status_t dtc_verify_database_def(sql_stmt_t *stmt, knl_database_def_t *def);
status_t dtc_parse_instance(sql_stmt_t *stmt, knl_database_def_t *def, word_t *word);
status_t dtc_parse_maxinstance(sql_stmt_t *stmt, knl_database_def_t *def, word_t *word);

#ifdef __cplusplus
}
#endif


#endif
