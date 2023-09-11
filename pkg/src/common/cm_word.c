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
 * cm_word.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_word.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_lex.h"

#ifdef __cplusplus
extern "C" {
#endif
static key_word_t g_key_words[] = {
    { (uint32)KEY_WORD_ABORT, GS_TRUE, { (char *)"abort" } },
    { (uint32)KEY_WORD_ACCOUNT, GS_TRUE, { (char *)"account" } },
    { (uint32)KEY_WORD_ACTIVATE, GS_TRUE, { (char *)"activate" } },
    { (uint32)KEY_WORD_ACTIVE, GS_TRUE, { (char *)"active" } },
    { (uint32)KEY_WORD_ADD, GS_FALSE, { (char *)"add" } },
    { (uint32)KEY_WORD_AFTER, GS_TRUE, { (char *)"after" } },
    { (uint32)KEY_WORD_ALL, GS_FALSE, { (char *)"all" } },
    { (uint32)KEY_WORD_ALTER, GS_FALSE, { (char *)"alter" } },
    { (uint32)KEY_WORD_ANALYZE, GS_TRUE, { (char *)"analyze" } },
    { (uint32)KEY_WORD_AND, GS_FALSE, { (char *)"and" } },
    { (uint32)KEY_WORD_ANY, GS_FALSE, { (char *)"any" } },
    { (uint32)KEY_WORD_APPENDONLY, GS_TRUE, { (char *)"appendonly" } },
    { (uint32)KEY_WORD_ARCHIVE, GS_TRUE, { (char *)"archive" } },
    { (uint32)KEY_WORD_ARCHIVELOG, GS_TRUE, { (char *)"archivelog" } },
    { (uint32)KEY_WORD_AS, GS_FALSE, { (char *)"as" } },
    { (uint32)KEY_WORD_ASC, GS_FALSE, { (char *)"asc" } },
    { (uint32)KEY_WORD_ASYNC, GS_TRUE, { (char *)"async" } },
    { (uint32)KEY_WORD_AUDIT, GS_FALSE, { (char *)"audit" } },
    { (uint32)KEY_WORD_AUTOALLOCATE, GS_TRUE, { (char *)"autoallocate" } },
    { (uint32)KEY_WORD_AUTOEXTEND, GS_TRUE, { (char *)"autoextend" } },
    { (uint32)KEY_WORD_AUTOMATIC, GS_TRUE, { (char *)"automatic" } },
    { (uint32)KEY_WORD_AUTON_TRANS, GS_TRUE, { (char *)"autonomous_transaction" } },
    { (uint32)KEY_WORD_AUTOOFFLINE, GS_TRUE, { (char *)"autooffline" } },
    { (uint32)KEY_WORD_AUTOPURGE, GS_TRUE, { (char *)"autopurge" } },
    { (uint32)KEY_WORD_AUTO_INCREMENT, GS_TRUE, { (char *)"auto_increment" } },
    { (uint32)KEY_WORD_AVAILABILITY, GS_TRUE, { (char *)"availability" } },
    { (uint32)KEY_WORD_BACKUP, GS_TRUE, { (char *)"backup" } },
    { (uint32)KEY_WORD_BACKUPSET, GS_TRUE, { (char *)"backupset" } },
    { (uint32)KEY_WORD_BEFORE, GS_TRUE, { (char *)"before" } },
    { (uint32)KEY_WORD_BEGIN, GS_TRUE, { (char *)"begin" } },
    { (uint32)KEY_WORD_BETWEEN, GS_FALSE, { (char *)"between" } },
    { (uint32)KEY_WORD_BODY, GS_TRUE, { (char *)"body" } },
    { (uint32)KEY_WORD_BOTH, GS_TRUE, { (char *)"both" } }, /* for TRIM expression only */
    { (uint32)KEY_WORD_BUFFER, GS_TRUE, { (char *)"buffer" } },
    { (uint32)KEY_WORD_BUILD, GS_TRUE, { (char *)"build" } },
    { (uint32)KEY_WORD_BULK, GS_TRUE, { (char *)"bulk" } },
    { (uint32)KEY_WORD_BY, GS_FALSE, { (char *)"by" } },
    { (uint32)KEY_WORD_CACHE, GS_TRUE, { (char *)"cache" } },
    { (uint32)KEY_WORD_CALL, GS_TRUE, { (char *)"call" } },
    { (uint32)KEY_WORD_CANCEL, GS_TRUE, { (char *)"cancel" } },
    { (uint32)KEY_WORD_CASCADE, GS_TRUE, { (char *)"cascade" } },
    { (uint32)KEY_WORD_CASCADED, GS_TRUE, { (char *)"cascaded" } },
    { (uint32)KEY_WORD_CASE, GS_FALSE, { (char *)"case" } },
    { (uint32)KEY_WORD_CAST, GS_TRUE, { (char *)"cast" } },
    { (uint32)KEY_WORD_CATALOG, GS_TRUE, { (char *)"catalog" } },
    { (uint32)KEY_WORD_CHARACTER, GS_TRUE, { (char *)"character" } },
    { (uint32)KEY_WORD_CHARSET, GS_TRUE, { (char *)"charset" } },
    { (uint32)KEY_WORD_CHECK, GS_FALSE, { (char *)"check" } },
    { (uint32)KEY_WORD_CHECKPOINT, GS_TRUE, { (char *)"checkpoint" } },
    { (uint32)KEY_WORD_CLOSE, GS_TRUE, { (char *)"close" } },
    { (uint32)KEY_WORD_CLUSTER, GS_TRUE, { (char *)"cluster" } },
    { (uint32)KEY_WORD_CLUSTERED, GS_TRUE, { (char *)"clustered" } },
    { (uint32)KEY_WORD_COALESCE, GS_TRUE, { (char *)"coalesce" } },
    { (uint32)KEY_WORD_COLLATE, GS_TRUE, { (char *)"collate" } },
    { (uint32)KEY_WORD_COLUMN, GS_FALSE, { (char *)"column" } },
    { (uint32)KEY_WORD_COLUMNS, GS_TRUE, { (char *)"columns" } },
    { (uint32)KEY_WORD_COLUMN_VALUE, GS_TRUE, { (char *)"column_value" } },
    { (uint32)KEY_WORD_COMMENT, GS_TRUE, { (char *)"comment" } },
    { (uint32)KEY_WORD_COMMIT, GS_TRUE, { (char *)"commit" } },
    { (uint32)KEY_WORD_COMPRESS, GS_FALSE, { (char *)"compress" } },
    { (uint32)KEY_WORD_CONFIG, GS_TRUE, { (char *)"config" } },
    { (uint32)KEY_WORD_CONNECT, GS_FALSE, { (char *)"connect" } },
    { (uint32)KEY_WORD_CONSISTENCY, GS_TRUE, { (char *)"consistency" } },
    { (uint32)KEY_WORD_CONSTRAINT, GS_FALSE, { (char *)"constraint" } },
    { (uint32)KEY_WORD_CONTENT, GS_TRUE, { (char *)"content" } },
    { (uint32)KEY_WORD_CONTINUE, GS_TRUE, { (char *)"continue" } },
    { (uint32)KEY_WORD_CONTROLFILE, GS_TRUE, { (char *)"controlfile" } },
    { (uint32)KEY_WORD_CONVERT, GS_TRUE, { (char *)"convert" } },
    { (uint32)KEY_WORD_COPY, GS_TRUE, { (char *)"copy" } },
    { (uint32)KEY_WORD_CREATE, GS_FALSE, { (char *)"create" } },
    { (uint32)KEY_WORD_CRMODE, GS_FALSE, { (char *)"crmode" } },
    { (uint32)KEY_WORD_CROSS, GS_TRUE, { (char *)"cross" } },
    { (uint32)KEY_WORD_CTRLFILE, GS_TRUE, { (char *)"ctrlfile" } },
    { (uint32)KEY_WORD_CUMULATIVE, GS_FALSE, { (char *)"cumulative" } },
    { (uint32)KEY_WORD_CURRENT, GS_FALSE, { (char *)"current" } },
    { (uint32)KEY_WORD_CURRVAL, GS_TRUE, { (char *)"currval" } },
    { (uint32)KEY_WORD_CURSOR, GS_TRUE, { (char *)"cursor" } },
    { (uint32)KEY_WORD_CYCLE, GS_TRUE, { (char *)"cycle" } },
    { (uint32)KEY_WORD_DAAC, GS_TRUE, { (char *)"daac" } },
    { (uint32)KEY_WORD_DATA, GS_TRUE, { (char *)"data" } },
    { (uint32)KEY_WORD_DATABASE, GS_TRUE, { (char *)"database" } },
    { (uint32)KEY_WORD_DATAFILE, GS_TRUE, { (char *)"datafile" } },
    { (uint32)KEY_WORD_DEBUG, GS_TRUE, { (char *)"debug" } },
    { (uint32)KEY_WORD_DECLARE, GS_TRUE, { (char *)"declare" } },
    { (uint32)KEY_WORD_DEFERRABLE, GS_TRUE, { (char *)"deferrable" } },
    { (uint32)KEY_WORD_DELETE, GS_FALSE, { (char *)"delete" } },
    { (uint32)KEY_WORD_DESC, GS_FALSE, { (char *)"desc" } },
    { (uint32)KEY_WORD_DICTIONARY, GS_TRUE, { (char *)"dictionary" } },
    { (uint32)KEY_WORD_DIRECTORY, GS_TRUE, { (char *)"directory" } },
    { (uint32)KEY_WORD_DISABLE, GS_TRUE, { (char *)"disable" } },
    { (uint32)KEY_WORD_DISCARD, GS_TRUE, { (char *)"discard" } },
    { (uint32)KEY_WORD_DISCONNECT, GS_TRUE, { (char *)"disconnect" } },
    { (uint32)KEY_WORD_DISTINCT, GS_FALSE, { (char *)"distinct" } },
    { (uint32)KEY_WORD_DISTRIBUTE, GS_TRUE, { (char *)"distribute" } },
    { (uint32)KEY_WORD_DO, GS_TRUE, { (char *)"do" } },
    { (uint32)KEY_WORD_DOUBLEWRITE, GS_TRUE, { (char *)"doublewrite" } },
    { (uint32)KEY_WORD_DROP, GS_FALSE, { (char *)"drop" } },
    { (uint32)KEY_WORD_DUMP, GS_TRUE, { (char *)"dump" } },
    { (uint32)KEY_WORD_DUPLICATE, GS_TRUE, { (char *)"duplicate" } },
    { (uint32)KEY_WORD_ELSE, GS_FALSE, { (char *)"else" } },
    { (uint32)KEY_WORD_ELSIF, GS_TRUE, { (char *)"elsif" } },
    { (uint32)KEY_WORD_ENABLE, GS_TRUE, { (char *)"enable" } },
    { (uint32)KEY_WORD_ENABLE_LOGIC_REPLICATION, GS_TRUE, { (char *)"enable_logic_replication" } },
    { (uint32)KEY_WORD_ENCRYPTION, GS_TRUE, { (char *)"encryption" } },
    { (uint32)KEY_WORD_END, GS_TRUE, { (char *)"end" } },
    { (uint32)KEY_WORD_ERROR, GS_TRUE, { (char *)"error" } },
    { (uint32)KEY_WORD_ESCAPE, GS_TRUE, { (char *)"escape" } },
    { (uint32)KEY_WORD_EXCEPT, GS_FALSE, { (char *)"except" } },
    { (uint32)KEY_WORD_EXCEPTION, GS_TRUE, { (char *)"exception" } },
    { (uint32)KEY_WORD_EXCLUDE, GS_TRUE, { (char *)"exclude" } },
    { (uint32)KEY_WORD_EXEC, GS_TRUE, { (char *)"exec" } },
    { (uint32)KEY_WORD_EXECUTE, GS_TRUE, { (char *)"execute" } },
    { (uint32)KEY_WORD_EXISTS, GS_FALSE, { (char *)"exists" } },
    { (uint32)KEY_WORD_EXIT, GS_TRUE, { (char *)"exit" } },
    { (uint32)KEY_WORD_EXPLAIN, GS_TRUE, { (char *)"explain" } },
    { (uint32)KEY_WORD_EXTENT, GS_TRUE, { (char *)"extent" } },
    { (uint32)KEY_WORD_FAILOVER, GS_TRUE, { (char *)"failover" } },
    { (uint32)KEY_WORD_FETCH, GS_TRUE, { (char *)"fetch" } },
    { (uint32)KEY_WORD_FILE, GS_TRUE, { (char *)"file" } },
    { (uint32)KEY_WORD_FILETYPE, GS_TRUE, { (char *)"filetype" } },
    { (uint32)KEY_WORD_FINAL, GS_TRUE, { (char *)"final" } },
    { (uint32)KEY_WORD_FINISH, GS_TRUE, { (char *)"finish" } },
    { (uint32)KEY_WORD_FLASHBACK, GS_TRUE, { (char *)"flashback" } },
    { (uint32)KEY_WORD_FLUSH, GS_TRUE, { (char *)"flush" } },
    { (uint32)KEY_WORD_FOLLOWING, GS_TRUE, { (char *)"following" } },
    { (uint32)KEY_WORD_FOR, GS_FALSE, { (char *)"for" } },
    { (uint32)KEY_WORD_FORALL, GS_FALSE, { (char *)"forall" } },
    { (uint32)KEY_WORD_FORCE, GS_TRUE, { (char *)"force" } },
    { (uint32)KEY_WORD_FOREIGN, GS_TRUE, { (char *)"foreign" } },
    { (uint32)KEY_WORD_FORMAT, GS_TRUE, { (char *)"format" } },
    { (uint32)KEY_WORD_FROM, GS_FALSE, { (char *)"from" } },
    { (uint32)KEY_WORD_FULL, GS_TRUE, { (char *)"full" } },
    { (uint32)KEY_WORD_FUNCTION, GS_TRUE, { (char *)"function" } },
    { (uint32)KEY_WORD_GLOBAL, GS_TRUE, { (char *)"global" } },
    { (uint32)KEY_WORD_GOTO, GS_TRUE, { (char *)"goto" } },
    { (uint32)KEY_WORD_GRANT, GS_TRUE, { (char *)"grant" } },
    { (uint32)KEY_WORD_GROUP, GS_FALSE, { (char *)"group" } },
    { (uint32)KEY_WORD_GROUPID, GS_TRUE, { (char *)"groupid" } },
    { (uint32)KEY_WORD_HASH, GS_TRUE, { (char *)"hash" } },
    { (uint32)KEY_WORD_HAVING, GS_FALSE, { (char *)"having" } },
    { (uint32)KEY_WORD_IDENTIFIED, GS_FALSE, { (char *)"identified" } },
    { (uint32)KEY_WORD_IF, GS_TRUE, { (char *)"if" } },
    { (uint32)KEY_WORD_IGNORE, GS_TRUE, { (char *)"ignore" } },
    { (uint32)KEY_WORD_IN, GS_FALSE, { (char *)"in" } },
    { (uint32)KEY_WORD_INCLUDE, GS_TRUE, { (char *)"include" } },
    { (uint32)KEY_WORD_INCLUDING, GS_TRUE, { (char *)"including" } },
    { (uint32)KEY_WORD_INCREMENT, GS_FALSE, { (char *)"increment" } },
    { (uint32)KEY_WORD_INCREMENTAL, GS_TRUE, { (char *)"incremental" } },
    { (uint32)KEY_WORD_INDEX, GS_FALSE, { (char *)"index" } },
    { (uint32)KEY_WORD_INDEXCLUSTER, GS_FALSE, { (char *)"indexcluster" } },
    { (uint32)KEY_WORD_INDEX_ASC, GS_TRUE, { (char *)"index_asc" } },
    { (uint32)KEY_WORD_INDEX_DESC, GS_TRUE, { (char *)"index_desc" } },
    { (uint32)KEY_WORD_INIT, GS_TRUE, { (char *)"init" } },
    { (uint32)KEY_WORD_INITIAL, GS_TRUE, { (char *)"initial" } },
    { (uint32)KEY_WORD_INITIALLY, GS_TRUE, { (char *)"initially" } },
    { (uint32)KEY_WORD_INITRANS, GS_TRUE, { (char *)"initrans" } },
    { (uint32)KEY_WORD_INNER, GS_TRUE, { (char *)"inner" } },
    { (uint32)KEY_WORD_INSERT, GS_FALSE, { (char *)"insert" } },
    { (uint32)KEY_WORD_INSTANCE, GS_TRUE, { (char *)"instance" } },
    { (uint32)KEY_WORD_INSTANTIABLE, GS_TRUE, { (char *)"instantiable" } },
    { (uint32)KEY_WORD_INSTEAD, GS_TRUE, { (char *)"instead" } },
    { (uint32)KEY_WORD_INTERSECT, GS_FALSE, { (char *)"intersect" } },
    { (uint32)KEY_WORD_INTO, GS_FALSE, { (char *)"into" } },
    { (uint32)KEY_WORD_INVALIDATE, GS_TRUE, { (char *)"invalidate" } },
    { (uint32)KEY_WORD_IS, GS_FALSE, { (char *)"is" } },
    { (uint32)KEY_WORD_IS_NOT, GS_TRUE, { (char *)"isnot" } },
    { (uint32)KEY_WORD_JOIN, GS_TRUE, { (char *)"join" } },
    { (uint32)KEY_WORD_JSON, GS_TRUE, { (char *)"json" } },
    { (uint32)KEY_WORD_JSONB_TABLE, GS_TRUE, { (char *)"jsonb_table" } },
    { (uint32)KEY_WORD_JSON_TABLE, GS_TRUE, { (char *)"json_table" } },
    { (uint32)KEY_WORD_KEEP, GS_TRUE, { (char *)"keep" } },
    { (uint32)KEY_WORD_KEY, GS_TRUE, { (char *)"key" } },
    { (uint32)KEY_WORD_KILL, GS_TRUE, { (char *)"kill" } },
    { (uint32)KEY_WORD_LANGUAGE, GS_TRUE, { (char *)"language" } },
    { (uint32)KEY_WORD_LEADING, GS_TRUE, { (char *)"leading" } }, /* for TRIM expression only */
    { (uint32)KEY_WORD_LEFT, GS_TRUE, { (char *)"left" } },
    { (uint32)KEY_WORD_LESS, GS_TRUE, { (char *)"less" } },
    { (uint32)KEY_WORD_LEVEL, GS_FALSE, { (char *)"level" } },
    { (uint32)KEY_WORD_LIBRARY, GS_FALSE, { (char *)"library" } },
    { (uint32)KEY_WORD_LIKE, GS_FALSE, { (char *)"like" } },
    { (uint32)KEY_WORD_LIMIT, GS_TRUE, { (char *)"limit" } },
    { (uint32)KEY_WORD_LIST, GS_TRUE, { (char *)"list" } },
    { (uint32)KEY_WORD_LNNVL, GS_TRUE, { (char *)"lnnvl" } },
    { (uint32)KEY_WORD_LOAD, GS_TRUE, { (char *)"load" } },
    { (uint32)KEY_WORD_LOB, GS_TRUE, { (char *)"lob" } },
    { (uint32)KEY_WORD_LOCAL, GS_TRUE, { (char *)"local" } },
    { (uint32)KEY_WORD_LOCK, GS_FALSE, { (char *)"lock" } },
    { (uint32)KEY_WORD_LOCK_WAIT, GS_TRUE, { (char *)"lock_wait" } },
    { (uint32)KEY_WORD_LOG, GS_TRUE, { (char *)"log" } },
    { (uint32)KEY_WORD_LOGFILE, GS_TRUE, { (char *)"logfile" } },
    { (uint32)KEY_WORD_LOGGING, GS_TRUE, { (char *)"logging" } },
    { (uint32)KEY_WORD_LOGICAL, GS_TRUE, { (char *)"logical" } },
    { (uint32)KEY_WORD_LOOP, GS_TRUE, { (char *)"loop" } },
    { (uint32)KEY_WORD_MANAGED, GS_TRUE, { (char *)"managed" } },
    { (uint32)KEY_WORD_MAXIMIZE, GS_TRUE, { (char *)"maximize" } },
    { (uint32)KEY_WORD_MAXINSTANCES, GS_TRUE, { (char *)"maxinstances" } },
    { (uint32)KEY_WORD_MAXSIZE, GS_TRUE, { (char *)"maxsize" } },
    { (uint32)KEY_WORD_MAXTRANS, GS_TRUE, { (char *)"maxtrans" } },
    { (uint32)KEY_WORD_MAXVALUE, GS_TRUE, { (char *)"maxvalue" } },
    { (uint32)KEY_WORD_MEMBER, GS_TRUE, { (char *)"member" } },
    { (uint32)KEY_WORD_MEMORY, GS_TRUE, { (char *)"memory" } },
    { (uint32)KEY_WORD_MERGE, GS_TRUE, { (char *)"merge" } },
    { (uint32)KEY_WORD_MINUS, GS_FALSE, { (char *)"minus" } },
    { (uint32)KEY_WORD_MINVALUE, GS_TRUE, { (char *)"minvalue" } },
    { (uint32)KEY_WORD_MODE, GS_TRUE, { (char *)"mode" } },
    { (uint32)KEY_WORD_MODIFY, GS_FALSE, { (char *)"modify" } },
    { (uint32)KEY_WORD_MONITOR, GS_TRUE, { (char *)"monitor" } },
    { (uint32)KEY_WORD_MOUNT, GS_TRUE, { (char *)"mount" } },
    { (uint32)KEY_WORD_MOVE, GS_TRUE, { (char *)"move" } },
    { (uint32)KEY_WORD_NEXT, GS_TRUE, { (char *)"next" } },
    { (uint32)KEY_WORD_NEXTVAL, GS_TRUE, { (char *)"nextval" } },
    { (uint32)KEY_WORD_NOARCHIVELOG, GS_TRUE, { (char *)"noarchivelog" } },
    { (uint32)KEY_WORD_NO_CACHE, GS_TRUE, { (char *)"nocache" } },
    { (uint32)KEY_WORD_NO_COMPRESS, GS_FALSE, { (char *)"nocompress" } },
    { (uint32)KEY_WORD_NO_CYCLE, GS_TRUE, { (char *)"nocycle" } },
    { (uint32)KEY_WORD_NODE, GS_TRUE, { (char *)"node" } },
    { (uint32)KEY_WORD_NO_LOGGING, GS_TRUE, { (char *)"nologging" } },
    { (uint32)KEY_WORD_NO_MAXVALUE, GS_TRUE, { (char *)"nomaxvalue" } },
    { (uint32)KEY_WORD_NO_MINVALUE, GS_TRUE, { (char *)"nominvalue" } },
    { (uint32)KEY_WORD_NO_ORDER, GS_TRUE, { (char *)"noorder" } },
    { (uint32)KEY_WORD_NO_RELY, GS_TRUE, { (char *)"norely" } },
    { (uint32)KEY_WORD_NOT, GS_FALSE, { (char *)"not" } },
    { (uint32)KEY_WORD_NO_VALIDATE, GS_TRUE, { (char *)"novalidate" } },
    { (uint32)KEY_WORD_NOWAIT, GS_FALSE, { (char *)"nowait" } },
    { (uint32)KEY_WORD_NULL, GS_FALSE, { (char *)"null" } },
    { (uint32)KEY_WORD_NULLS, GS_TRUE, { (char *)"nulls" } },
    { (uint32)KEY_WORD_OF, GS_FALSE, { (char *)"of" } },
    { (uint32)KEY_WORD_OFF, GS_TRUE, { (char *)"off" } },
    { (uint32)KEY_WORD_OFFLINE, GS_FALSE, { (char *)"offline" } },
    { (uint32)KEY_WORD_OFFSET, GS_TRUE, { (char *)"offset" } },
    { (uint32)KEY_WORD_ON, GS_FALSE, { (char *)"on" } },
    { (uint32)KEY_WORD_ONLINE, GS_FALSE, { (char *)"online" } },
    { (uint32)KEY_WORD_ONLY, GS_TRUE, { (char *)"only" } },
    { (uint32)KEY_WORD_OPEN, GS_TRUE, { (char *)"open" } },
    { (uint32)KEY_WORD_OR, GS_FALSE, { (char *)"or" } },
    { (uint32)KEY_WORD_ORDER, GS_FALSE, { (char *)"order" } },
    { (uint32)KEY_WORD_ORGANIZATION, GS_TRUE, { (char *)"organization" } },
    { (uint32)KEY_WORD_OUTER, GS_TRUE, { (char *)"outer" } },
    { (uint32)KEY_WORD_PACKAGE, GS_TRUE, { (char *)"package" } },
    { (uint32)KEY_WORD_PARALLEL, GS_TRUE, { (char *)"parallel" } },
    { (uint32)KEY_WORD_PARALLELISM, GS_TRUE, { (char *)"parallelism" } },
    { (uint32)KEY_WORD_PARAM, GS_TRUE, { (char *)"parameter" } },
    { (uint32)KEY_WORD_PARTITION, GS_TRUE, { (char *)"partition" } },
    { (uint32)KEY_WORD_PASSWORD, GS_TRUE, { (char *)"password" } },
    { (uint32)KEY_WORD_PATH, GS_TRUE, { (char *)"path" } },
    { (uint32)KEY_WORD_PCTFREE, GS_TRUE, { (char *)"pctfree" } },
    { (uint32)KEY_WORD_PERFORMANCE, GS_TRUE, { (char *)"performance" } },
    { (uint32)KEY_WORD_PHYSICAL, GS_TRUE, { (char *)"physical" } },
    { (uint32)KEY_WORD_PIVOT, GS_TRUE, { (char *)"pivot" } },
    { (uint32)KEY_WORD_PLAN, GS_TRUE, { (char *)"plan" } },
    { (uint32)KEY_WORD_PRAGMA, GS_TRUE, { (char *)"pragma" } },
    { (uint32)KEY_WORD_PRECEDING, GS_TRUE, { (char *)"preceding" } },
    { (uint32)KEY_WORD_PREPARE, GS_TRUE, { (char *)"prepare" } },
    { (uint32)KEY_WORD_PREPARED, GS_TRUE, { (char *)"prepared" } },
    { (uint32)KEY_WORD_PRESERVE, GS_TRUE, { (char *)"preserve" } },
    { (uint32)KEY_WORD_PRIMARY, GS_TRUE, { (char *)"primary" } },
    { (uint32)KEY_WORD_PRIOR, GS_TRUE, { (char *)"prior" } },
    { (uint32)KEY_WORD_PRIVILEGES, GS_FALSE, { (char *)"privileges" } },
    { (uint32)KEY_WORD_PROCEDURE, GS_TRUE, { (char *)"procedure" } },
    { (uint32)KEY_WORD_PROFILE, GS_TRUE, { (char *)"profile" } },
    { (uint32)KEY_WORD_PROTECTION, GS_TRUE, { (char *)"protection" } },
    { (uint32)KEY_WORD_PUBLIC, GS_FALSE, { (char *)"public" } },
    { (uint32)KEY_WORD_PUNCH, GS_TRUE, { (char *)"punch" } },
    { (uint32)KEY_WORD_PURGE, GS_TRUE, { (char *)"purge" } },
    { (uint32)KEY_WORD_QUERY, GS_TRUE, { (char *)"query" } },
    { (uint32)KEY_WORD_RAISE, GS_TRUE, { (char *)"raise" } },
    { (uint32)KEY_WORD_RANGE, GS_TRUE, { (char *)"range" } },
    { (uint32)KEY_WORD_READ, GS_TRUE, { (char *)"read" } },
    { (uint32)KEY_WORD_READ_ONLY, GS_TRUE, { (char *)"readonly" } },
    { (uint32)KEY_WORD_READ_WRITE, GS_TRUE, { (char *)"readwrite" } },
    { (uint32)KEY_WORD_REBUILD, GS_TRUE, { (char *)"rebuild" } },
    { (uint32)KEY_WORD_RECOVER, GS_TRUE, { (char *)"recover" } },
    { (uint32)KEY_WORD_RECYCLE, GS_TRUE, { (char *)"recycle" } },
    { (uint32)KEY_WORD_RECYCLEBIN, GS_TRUE, { (char *)"recyclebin" } },
    { (uint32)KEY_WORD_REDO, GS_TRUE, { (char *)"redo" } },
    { (uint32)KEY_WORD_REFERENCES, GS_TRUE, { (char *)"references" } },
    { (uint32)KEY_WORD_REFRESH, GS_TRUE, { (char *)"refresh" } },
    { (uint32)KEY_WORD_REGEXP, GS_TRUE, { (char *)"regexp" } },
    { (uint32)KEY_WORD_REGEXP_LIKE, GS_TRUE, { (char *)"regexp_like" } },
    { (uint32)KEY_WORD_REGISTER, GS_TRUE, { (char *)"register" } },
    { (uint32)KEY_WORD_RELEASE, GS_TRUE, { (char *)"release" } },
    { (uint32)KEY_WORD_RELOAD, GS_TRUE, { (char *)"reload" } },
    { (uint32)KEY_WORD_RELY, GS_TRUE, { (char *)"rely" } },
    { (uint32)KEY_WORD_RENAME, GS_FALSE, { (char *)"rename" } },
    { (uint32)KEY_WORD_REPAIR, GS_FALSE, { (char *)"repair" } },
    { (uint32)KEY_WORD_REPLACE, GS_TRUE, { (char *)"replace" } },
#ifdef Z_SHARDING
    { (uint32)KEY_WORD_REPLICATION, GS_TRUE, { (char *)"replication" } },
#endif
    { (uint32)KEY_WORD_RESET, GS_TRUE, { (char *)"reset" } },
    { (uint32)KEY_WORD_RESIZE, GS_TRUE, { (char *)"resize" } },
    { (uint32)KEY_WORD_RESTORE, GS_TRUE, { (char *)"restore" } },
    { (uint32)KEY_WORD_RESTRICT, GS_TRUE, { (char *)"restrict" } },
    { (uint32)KEY_WORD_RETURN, GS_TRUE, { (char *)"return" } },
    { (uint32)KEY_WORD_RETURNING, GS_TRUE, { (char *)"returning" } },
    { (uint32)KEY_WORD_REUSE, GS_TRUE, { (char *)"reuse" } },
    { (uint32)KEY_WORD_REVERSE, GS_TRUE, { (char *)"reverse" } },
    { (uint32)KEY_WORD_REVOKE, GS_TRUE, { (char *)"revoke" } },
    { (uint32)KEY_WORD_RIGHT, GS_TRUE, { (char *)"right" } },
    { (uint32)KEY_WORD_ROLE, GS_TRUE, { (char *)"role" } },
    { (uint32)KEY_WORD_ROLLBACK, GS_TRUE, { (char *)"rollback" } },
    { (uint32)KEY_WORD_ROUTE, GS_TRUE, { (char *)"route" } },
    { (uint32)KEY_WORD_ROWS, GS_FALSE, { (char *)"rows" } },
    { (uint32)KEY_WORD_SAVEPOINT, GS_TRUE, { (char *)"savepoint" } },
    { (uint32)KEY_WORD_SCN, GS_TRUE, { (char *)"scn" } },
    { (uint32)KEY_WORD_SECONDARY, GS_TRUE, { (char *)"secondary" } },
    { (uint32)KEY_WORD_SECTION, GS_TRUE, { (char *)"section" } },
    { (uint32)KEY_WORD_SELECT, GS_FALSE, { (char *)"select" } },
    { (uint32)KEY_WORD_SEPARATOR, GS_TRUE, { (char *)"separator" } },
    { (uint32)KEY_WORD_SEQUENCE, GS_TRUE, { (char *)"sequence" } },
    { (uint32)KEY_WORD_SERIALIZABLE, GS_TRUE, { (char *)"serializable" } },
    { (uint32)KEY_WORD_SERVER, GS_TRUE, { (char *)"server" } },
    { (uint32)KEY_WORD_SESSION, GS_FALSE, { (char *)"session" } },
    { (uint32)KEY_WORD_SET, GS_FALSE, { (char *)"set" } },
    { (uint32)KEY_WORD_SHARE, GS_TRUE, { (char *)"share" } },
    { (uint32)KEY_WORD_SHOW, GS_TRUE, { (char *)"show" } },
    { (uint32)KEY_WORD_SHRINK, GS_TRUE, { (char *)"shrink" } },
    { (uint32)KEY_WORD_SHUTDOWN, GS_TRUE, { (char *)"shutdown" } },
#ifdef DB_DEBUG_VERSION
    { (uint32)KEY_WORD_SIGNAL, GS_TRUE, { (char *)"signal" } },
#endif
    { (uint32)KEY_WORD_SIZE, GS_TRUE, { (char *)"size" } },
    { (uint32)KEY_WORD_SKIP, GS_TRUE, { (char *)"skip" } },
    { (uint32)KEY_WORD_SKIP_ADD_DROP_TABLE, GS_TRUE, { (char *)"skip_add_drop_table" } },
    { (uint32)KEY_WORD_SKIP_COMMENTS, GS_TRUE, { (char *)"skip_comment" } },
    { (uint32)KEY_WORD_SKIP_TRIGGERS, GS_TRUE, { (char *)"skip_triggers" } },
    { (uint32)KEY_WORD_SKIP_QUOTE_NAMES, GS_TRUE, { (char *)"skip_quote_names" } },
    { (uint32)KEY_WORD_SPACE, GS_TRUE, { (char *)"space" } },
    { (uint32)KEY_WORD_SPLIT, GS_TRUE, { (char *)"split" } },
    { (uint32)KEY_WORD_SPLIT_FACTOR, GS_TRUE, { (char *)"split_factor" } },
    { (uint32)KEY_WORD_SQL_MAP, GS_FALSE, { (char *)"sql_map" } },
    { (uint32)KEY_WORD_STANDARD, GS_TRUE, { (char *)"standard" } },
    { (uint32)KEY_WORD_STANDBY, GS_TRUE, { (char *)"standby" } },
    { (uint32)KEY_WORD_START, GS_FALSE, { (char *)"start" } },
    { (uint32)KEY_WORD_STARTUP, GS_TRUE, { (char *)"startup" } },
    { (uint32)KEY_WORD_STOP, GS_TRUE, { (char *)"stop" } },
    { (uint32)KEY_WORD_STORAGE, GS_TRUE, { (char *)"storage" } },
    { (uint32)KEY_WORD_SUBPARTITION, GS_TRUE, { (char *)"subpartition" } },
    { (uint32)KEY_WORD_SWAP, GS_TRUE, { (char *)"swap" } },
    { (uint32)KEY_WORD_SWITCH, GS_TRUE, { (char *)"switch" } },
    { (uint32)KEY_WORD_SWITCHOVER, GS_TRUE, { (char *)"switchover" } },
#ifdef DB_DEBUG_VERSION
    { (uint32)KEY_WORD_SYNCPOINT, GS_TRUE, { (char *)"syncpoint" } },
#endif
    { (uint32)KEY_WORD_SYNONYM, GS_FALSE, { (char *)"synonym" } },
    { (uint32)KEY_WORD_SYSAUX, GS_TRUE, { (char *)"sysaux" } },
    { (uint32)KEY_WORD_SYSTEM, GS_TRUE, { (char *)"system" } },
    { (uint32)KEY_WORD_TABLE, GS_FALSE, { (char *)"table" } },
    { (uint32)KEY_WORD_TABLES, GS_TRUE, { (char *)"tables" } },
    { (uint32)KEY_WORD_TABLESPACE, GS_TRUE, { (char *)"tablespace" } },
    { (uint32)KEY_WORD_TAG, GS_TRUE, { (char *)"tag" } },
    { (uint32)KEY_WORD_TEMP, GS_TRUE, { (char *)"temp" } },
    { (uint32)KEY_WORD_TEMPFILE, GS_TRUE, { (char *)"tempfile" } },
    { (uint32)KEY_WORD_TEMPORARY, GS_TRUE, { (char *)"temporary" } },
    { (uint32)KEY_WORD_TENANT, GS_TRUE, { (char *)"tenant" } },
    { (uint32)KEY_WORD_THAN, GS_TRUE, { (char *)"than" } },
    { (uint32)KEY_WORD_THEN, GS_FALSE, { (char *)"then" } },
    { (uint32)KEY_WORD_THREAD, GS_TRUE, { (char *)"thread" } },
    { (uint32)KEY_WORD_TIMEOUT, GS_TRUE, { (char *)"timeout" } },
    { (uint32)KEY_WORD_TIMEZONE, GS_TRUE, { (char *)"time_zone" } },
    { (uint32)KEY_WORD_TO, GS_FALSE, { (char *)"to" } },
    { (uint32)KEY_WORD_TRAILING, GS_TRUE, { (char *)"trailing" } }, /* for TRIM expression only */
    { (uint32)KEY_WORD_TRANSACTION, GS_TRUE, { (char *)"transaction" } },
    { (uint32)KEY_WORD_TRIGGER, GS_FALSE, { (char *)"trigger" } },
    { (uint32)KEY_WORD_TRUNCATE, GS_TRUE, { (char *)"truncate" } },
    { (uint32)KEY_WORD_TYPE, GS_TRUE, { (char *)"type" } },
    { (uint32)KEY_WORD_UNDO, GS_TRUE, { (char *)"undo" } },
    { (uint32)KEY_WORD_UNIFORM, GS_TRUE, { (char *)"uniform" } },
    { (uint32)KEY_WORD_UNION, GS_FALSE, { (char *)"union" } },
    { (uint32)KEY_WORD_UNIQUE, GS_TRUE, { (char *)"unique" } },
    { (uint32)KEY_WORD_UNLIMITED, GS_TRUE, { (char *)"unlimited" } },
    { (uint32)KEY_WORD_UNLOCK, GS_TRUE, { (char *)"unlock" } },
    { (uint32)KEY_WORD_UNPIVOT, GS_TRUE, { (char *)"unpivot" } },
    { (uint32)KEY_WORD_UNTIL, GS_TRUE, { (char *)"until" } },
    { (uint32)KEY_WORD_UNUSABLE, GS_TRUE, { (char *)"unusable" } },
    { (uint32)KEY_WORD_UPDATE, GS_FALSE, { (char *)"update" } },
    { (uint32)KEY_WORD_USER, GS_FALSE, { (char *)"user" } },
    { (uint32)KEY_WORD_USERS, GS_TRUE, { (char *)"users" } },
    { (uint32)KEY_WORD_USING, GS_TRUE, { (char *)"using" } },
    { (uint32)KEY_WORD_VALIDATE, GS_TRUE, { (char *)"validate" } },
    { (uint32)KEY_WORD_VALUES, GS_FALSE, { (char *)"values" } },
    { (uint32)KEY_WORD_VIEW, GS_FALSE, { (char *)"view" } },
    { (uint32)KEY_WORD_WAIT, GS_TRUE, { (char *)"wait" } },
    { (uint32)KEY_WORD_WHEN, GS_TRUE, { (char *)"when" } },
    { (uint32)KEY_WORD_WHERE, GS_FALSE, { (char *)"where" } },
    { (uint32)KEY_WORD_WHILE, GS_FALSE, { (char *)"while" } },
    { (uint32)KEY_WORD_WITH, GS_FALSE, { (char *)"with" } },
};

#ifdef WIN32
static_assert(sizeof(g_key_words) / sizeof(key_word_t) == KEY_WORD_DUMB_END - KEY_WORD_0_UNKNOWN - 1,
              "Array g_key_words defined error");
#endif

/* datatype key words */
static datatype_word_t g_datatype_words[] = {
    { { (char *)"bigint" }, DTYP_BIGINT, GS_TRUE, GS_TRUE },
    { { (char *)"binary" }, DTYP_BINARY, GS_TRUE, GS_FALSE },
    { { (char *)"binary_bigint" }, DTYP_BINARY_BIGINT, GS_TRUE, GS_TRUE },
    { { (char *)"binary_double" }, DTYP_BINARY_DOUBLE, GS_TRUE, GS_FALSE },
    { { (char *)"binary_float" }, DTYP_BINARY_FLOAT, GS_TRUE, GS_FALSE },
    { { (char *)"binary_integer" }, DTYP_BINARY_INTEGER, GS_TRUE, GS_TRUE },
    { { (char *)"binary_uint32" }, DTYP_UINTEGER, GS_TRUE, GS_FALSE },
    { { (char *)"blob" }, DTYP_BLOB, GS_TRUE, GS_FALSE },
    { { (char *)"bool" }, DTYP_BOOLEAN, GS_TRUE, GS_FALSE },
    { { (char *)"boolean" }, DTYP_BOOLEAN, GS_TRUE, GS_FALSE },
    { { (char *)"bpchar" }, DTYP_CHAR, GS_TRUE, GS_FALSE },
    { { (char *)"bytea" }, DTYP_BLOB, GS_TRUE, GS_FALSE },
    { { (char *)"char" }, DTYP_CHAR, GS_FALSE, GS_FALSE },
    { { (char *)"character" }, DTYP_CHAR, GS_TRUE, GS_FALSE },
    { { (char *)"clob" }, DTYP_CLOB, GS_TRUE, GS_FALSE },
    { { (char *)"date" }, DTYP_DATE, GS_FALSE, GS_FALSE },
    { { (char *)"datetime" }, DTYP_DATE, GS_TRUE, GS_FALSE },
    { { (char *)"decimal" }, DTYP_DECIMAL, GS_FALSE, GS_FALSE },
    { { (char *)"double" }, DTYP_DOUBLE, GS_TRUE, GS_FALSE },
    { { (char *)"float" }, DTYP_FLOAT, GS_TRUE, GS_FALSE },
    { { (char *)"image" }, DTYP_IMAGE, GS_TRUE, GS_FALSE },
    { { (char *)"int" }, DTYP_INTEGER, GS_TRUE, GS_TRUE },
    { { (char *)"integer" }, DTYP_INTEGER, GS_FALSE, GS_TRUE },
    { { (char *)"interval" }, DTYP_INTERVAL, GS_TRUE, GS_FALSE },
    { { (char *)"jsonb" }, DTYP_JSONB, GS_TRUE, GS_FALSE },
    { { (char *)"long" }, DTYP_CLOB, GS_TRUE, GS_FALSE },
    { { (char *)"longblob" }, DTYP_IMAGE, GS_TRUE, GS_FALSE },
    { { (char *)"longtext" }, DTYP_CLOB, GS_TRUE, GS_FALSE },
    { { (char *)"mediumblob" }, DTYP_IMAGE, GS_TRUE, GS_FALSE },
    { { (char *)"nchar" }, DTYP_NCHAR, GS_TRUE, GS_FALSE },
    { { (char *)"number" }, DTYP_NUMBER, GS_FALSE, GS_FALSE },
    { { (char *)"number2" }, DTYP_NUMBER2, GS_TRUE, GS_FALSE },
    { { (char *)"numeric" }, DTYP_DECIMAL, GS_TRUE, GS_FALSE },
    { { (char *)"nvarchar" }, DTYP_NVARCHAR, GS_TRUE, GS_FALSE },
    { { (char *)"nvarchar2" }, DTYP_NVARCHAR, GS_TRUE, GS_FALSE },
    { { (char *)"raw" }, DTYP_RAW, GS_FALSE, GS_FALSE },
    { { (char *)"real" }, DTYP_DOUBLE, GS_TRUE, GS_FALSE },
    { { (char *)"serial" }, DTYP_SERIAL, GS_TRUE, GS_FALSE },
    { { (char *)"short" }, DTYP_SMALLINT, GS_TRUE, GS_TRUE },
    { { (char *)"smallint" }, DTYP_SMALLINT, GS_TRUE, GS_TRUE },
    { { (char *)"text" }, DTYP_CLOB, GS_TRUE, GS_FALSE },
    { { (char *)"timestamp" }, DTYP_TIMESTAMP, GS_TRUE, GS_FALSE },
    { { (char *)"tinyint" }, DTYP_TINYINT, GS_TRUE, GS_TRUE },
    { { (char *)"ubigint" }, DTYP_UBIGINT, GS_TRUE, GS_FALSE },
    { { (char *)"uint" }, DTYP_UINTEGER, GS_TRUE, GS_FALSE },
    { { (char *)"uinteger" }, DTYP_UINTEGER, GS_TRUE, GS_FALSE },
    { { (char *)"ushort" }, DTYP_USMALLINT, GS_TRUE, GS_FALSE },
    { { (char *)"usmallint" }, DTYP_USMALLINT, GS_TRUE, GS_FALSE },
    { { (char *)"utinyint" }, DTYP_UTINYINT, GS_TRUE, GS_FALSE },
    { { (char *)"varbinary" }, DTYP_VARBINARY, GS_TRUE, GS_FALSE },
    { { (char *)"varchar" }, DTYP_VARCHAR, GS_FALSE, GS_FALSE },
    { { (char *)"varchar2" }, DTYP_VARCHAR, GS_FALSE, GS_FALSE },
};

/* reserved keywords
 * **Note:** the reserved keywords must be arrange in alphabetically
 * ascending order for speeding the search process. */
static key_word_t g_reserved_words[] = {
    { (uint32)RES_WORD_COLUMN_VALUE,       GS_TRUE,  { (char *)"column_value" } },
    { (uint32)RES_WORD_CONNECT_BY_ISCYCLE, GS_TRUE,  { (char *)"connect_by_iscycle" } },
    { (uint32)RES_WORD_CONNECT_BY_ISLEAF,  GS_TRUE,  { (char *)"connect_by_isleaf" } },
    { (uint32)RES_WORD_CURDATE,            GS_TRUE,  { (char *)"curdate" } },
    { (uint32)RES_WORD_CURDATE,            GS_TRUE,  { (char *)"current_date" } },
    { (uint32)RES_WORD_CURTIMESTAMP,       GS_TRUE,  { (char *)"current_timestamp" } },
    { (uint32)RES_WORD_DATABASETZ,         GS_TRUE,  { (char *)"dbtimezone" } },
    { (uint32)RES_WORD_DEFAULT,            GS_FALSE, { (char *)"default" } },
    { (uint32)RES_WORD_DELETING,           GS_TRUE,  { (char *)"deleting" } },
    { (uint32)RES_WORD_FALSE,              GS_FALSE, { (char *)"false" } },
    { (uint32)RES_WORD_INSERTING,          GS_TRUE,  { (char *)"inserting" } },
    { (uint32)RES_WORD_LEVEL,              GS_FALSE, { (char *)"level" } },
    { (uint32)RES_WORD_LOCALTIMESTAMP,     GS_TRUE,  { (char *)"localtimestamp" } },
    { (uint32)RES_WORD_SYSTIMESTAMP,       GS_TRUE,  { (char *)"now" } },
    { (uint32)RES_WORD_NULL,               GS_FALSE, { (char *)"null" } },
    { (uint32)RES_WORD_ROWID,              GS_FALSE, { (char *)"rowid" } },
    { (uint32)RES_WORD_ROWNODEID,          GS_FALSE, { (char *)"rownodeid" } },
    { (uint32)RES_WORD_ROWNUM,             GS_FALSE, { (char *)"rownum" } },
    { (uint32)RES_WORD_ROWSCN,             GS_FALSE, { (char *)"rowscn" } },
    { (uint32)RES_WORD_SESSIONTZ,          GS_TRUE,  { (char *)"sessiontimezone" } },
    { (uint32)RES_WORD_SYSDATE,            GS_FALSE, { (char *)"sysdate" } },
    { (uint32)RES_WORD_SYSTIMESTAMP,       GS_TRUE,  { (char *)"systimestamp" } },
    { (uint32)RES_WORD_TRUE,               GS_FALSE, { (char *)"true" } },
    { (uint32)RES_WORD_UPDATING,           GS_TRUE,  { (char *)"updating" } },
    { (uint32)RES_WORD_USER,               GS_FALSE, { (char *)"user" } },
    { (uint32)RES_WORD_UTCTIMESTAMP,       GS_TRUE,  { (char *)"utc_timestamp" } },
};

static key_word_t g_datetime_unit_words[] = {
    { (uint32)IU_DAY,         GS_TRUE, { "DAY", 3 } },
    { (uint32)IU_HOUR,        GS_TRUE, { "HOUR", 4 } },
    { (uint32)IU_MICROSECOND, GS_TRUE, { "MICROSECOND", 11 } },
    { (uint32)IU_MINUTE,      GS_TRUE, { "MINUTE", 6 } },
    { (uint32)IU_MONTH,       GS_TRUE, { "MONTH", 5 } },
    { (uint32)IU_QUARTER,     GS_TRUE, { "QUARTER", 7 } },
    { (uint32)IU_SECOND,      GS_TRUE, { "SECOND", 6 } },
    { (uint32)IU_DAY,         GS_TRUE, { "SQL_TSI_DAY", 11 } },
    { (uint32)IU_MICROSECOND, GS_TRUE, { "SQL_TSI_FRAC_SECOND", 19 } },
    { (uint32)IU_HOUR,        GS_TRUE, { "SQL_TSI_HOUR", 12 } },
    { (uint32)IU_MINUTE,      GS_TRUE, { "SQL_TSI_MINUTE", 14 } },
    { (uint32)IU_MONTH,       GS_TRUE, { "SQL_TSI_MONTH", 13 } },
    { (uint32)IU_QUARTER,     GS_TRUE, { "SQL_TSI_QUARTER", 15 } },
    { (uint32)IU_SECOND,      GS_TRUE, { "SQL_TSI_SECOND", 14 } },
    { (uint32)IU_WEEK,        GS_TRUE, { "SQL_TSI_WEEK", 12 } },
    { (uint32)IU_YEAR,        GS_TRUE, { "SQL_TSI_YEAR", 12 } },
    { (uint32)IU_WEEK,        GS_TRUE, { "WEEK", 4 } },
    { (uint32)IU_YEAR,        GS_TRUE, { "YEAR", 4 } },
};

static key_word_t g_hint_key_words[] = {
    { (uint32)ID_HINT_CB_MTRL,          GS_FALSE, { (char *)"cb_mtrl", 7 } },
    { (uint32)ID_HINT_DB_VERSION,       GS_FALSE, { (char *)"db_version", 10 } },
    { (uint32)ID_HINT_FULL,             GS_FALSE, { (char *)"full", 4 } },
    { (uint32)ID_HINT_HASH_AJ,          GS_FALSE, { (char *)"hash_aj", 7 } },
    { (uint32)ID_HINT_HASH_BUCKET_SIZE, GS_FALSE, { (char *)"hash_bucket_size", 16 } },
    { (uint32)ID_HINT_HASH_SJ,          GS_FALSE, { (char *)"hash_sj", 7 } },
    { (uint32)ID_HINT_HASH_TABLE,       GS_FALSE, { (char *)"hash_table", 10 } },
    { (uint32)ID_HINT_INDEX,            GS_FALSE, { (char *)"index", 5 } },
    { (uint32)ID_HINT_INDEX_ASC,        GS_FALSE, { (char *)"index_asc", 9 } },
    { (uint32)ID_HINT_INDEX_DESC,       GS_FALSE, { (char *)"index_desc", 10 } },
    { (uint32)ID_HINT_INDEX_FFS,        GS_FALSE, { (char *)"index_ffs", 9 } },
    { (uint32)ID_HINT_INDEX_SS,         GS_FALSE, { (char *)"index_ss", 8 } },
    { (uint32)ID_HINT_INLINE,           GS_FALSE, { (char *)"inline", 6 } },
    { (uint32)ID_HINT_LEADING,          GS_FALSE, { (char *)"leading", 7 } },
    { (uint32)ID_HINT_MATERIALIZE,      GS_FALSE, { (char *)"materialize", 11 } },
    { (uint32)ID_HINT_NL_BATCH,         GS_FALSE, { (char *)"nl_batch", 8 } },
    { (uint32)ID_HINT_NL_FULL_MTRL,     GS_FALSE, { (char *)"nl_full_mtrl", 12 } },
    { (uint32)ID_HINT_NL_FULL_OPT,      GS_FALSE, { (char *)"nl_full_opt", 11 } },
    { (uint32)ID_HINT_NO_CB_MTRL,       GS_FALSE, { (char *)"no_cb_mtrl", 10 } },
    { (uint32)ID_HINT_NO_HASH_TABLE,    GS_FALSE, { (char *)"no_hash_table", 13 } },
    { (uint32)ID_HINT_NO_INDEX,         GS_FALSE, { (char *)"no_index", 8 } },
    { (uint32)ID_HINT_NO_INDEX_FFS,     GS_FALSE, { (char *)"no_index_ffs", 12 } },
    { (uint32)ID_HINT_NO_INDEX_SS,      GS_FALSE, { (char *)"no_index_ss", 11 } },
    { (uint32)ID_HINT_NO_OR_EXPAND,     GS_FALSE, { (char *)"no_or_expand", 12 } },
    { (uint32)ID_HINT_NO_PUSH_PRED,     GS_FALSE, { (char *)"no_push_pred", 12 } },
    { (uint32)ID_HINT_NO_UNNEST,        GS_FALSE, { (char *)"no_unnest", 9 } },
    { (uint32)ID_HINT_OPTIM_MODE,       GS_FALSE, { (char *)"optimizer_mode", 14 } },
    { (uint32)ID_HINT_OPT_ESTIMATE,     GS_FALSE, { (char *)"opt_estimate", 12 } },
    { (uint32)ID_HINT_OPT_PARAM,        GS_FALSE, { (char *)"opt_param", 9 } },
    { (uint32)ID_HINT_ORDERED,          GS_FALSE, { (char *)"ordered", 7 } },
    { (uint32)ID_HINT_OR_EXPAND,        GS_FALSE, { (char *)"or_expand", 9 } },
    { (uint32)ID_HINT_FEATURES_ENABLE,  GS_FALSE, { (char *)"outline_features_enable", 23 } },
    { (uint32)ID_HINT_PARALLEL,         GS_FALSE, { (char *)"parallel", 8 } },
    { (uint32)ID_HINT_RULE,             GS_FALSE, { (char *)"rule", 4 } },
    { (uint32)ID_HINT_SEMI_TO_INNER,    GS_FALSE, { (char *)"semi_to_inner", 13 } },
#ifdef Z_SHARDING
    { (uint32)ID_HINT_SHD_READ_MASTER,  GS_FALSE, { (char *)"shd_read_master", 15 } },
    { (uint32)ID_HINT_SQL_WHITELIST,    GS_FALSE, { (char *)"sql_whitelist", 13 } },
#endif
    { (uint32)ID_HINT_THROW_DUPLICATE,  GS_FALSE, { (char *)"throw_duplicate", 15 } },
    { (uint32)ID_HINT_UNNEST,           GS_FALSE, { (char *)"unnest", 6 } },
    { (uint32)ID_HINT_USE_CONCAT,       GS_FALSE, { (char *)"use_concat", 10 } },
    { (uint32)ID_HINT_USE_HASH,         GS_FALSE, { (char *)"use_hash", 8 } },
    { (uint32)ID_HINT_USE_MERGE,        GS_FALSE, { (char *)"use_merge", 9 } },
    { (uint32)ID_HINT_USE_NL,           GS_FALSE, { (char *)"use_nl", 6 } },
};

const key_word_t g_method_key_words[] = {
    {(uint32)METHOD_COUNT,  GS_TRUE, { (char *)"COUNT",  5 } },
    {(uint32)METHOD_DELETE, GS_TRUE, { (char *)"DELETE", 6 } },
    {(uint32)METHOD_EXISTS, GS_TRUE, { (char *)"EXISTS", 6 } },
    {(uint32)METHOD_EXTEND, GS_TRUE, { (char *)"EXTEND", 6 } },
    {(uint32)METHOD_FIRST,  GS_TRUE, { (char *)"FIRST",  5 } },
    {(uint32)METHOD_LAST,   GS_TRUE, { (char *)"LAST",   4 } },
    {(uint32)METHOD_LIMIT,  GS_TRUE, { (char *)"LIMIT",  5 } },
    {(uint32)METHOD_NEXT,   GS_TRUE, { (char *)"NEXT",   4 } },
    {(uint32)METHOD_PRIOR,  GS_TRUE, { (char *)"PRIOR",  5 } },
    {(uint32)METHOD_TRIM,   GS_TRUE, { (char *)"TRIM",   4 } }
};

const key_word_t g_pl_attr_words[] = {
    { (uint32)PL_ATTR_WORD_FOUND,     GS_TRUE, { (char *)"FOUND",    5 } },
    { (uint32)PL_ATTR_WORD_ISOPEN,    GS_TRUE, { (char *)"ISOPEN",   6 } },
    { (uint32)PL_ATTR_WORD_NOTFOUND,  GS_TRUE, { (char *)"NOTFOUND", 8 } },
    { (uint32)PL_ATTR_WORD_ROWCOUNT,  GS_TRUE, { (char *)"ROWCOUNT", 8 } },
    { (uint32)PL_ATTR_WORD_ROWTYPE,   GS_TRUE, { (char *)"ROWTYPE",  7 } },
    { (uint32)PL_ATTR_WORD_TYPE,      GS_TRUE, { (char *)"TYPE",     4 } },
};

#define RESERVED_WORDS_COUNT (sizeof(g_reserved_words) / sizeof(key_word_t))
#define KEY_WORDS_COUNT      (sizeof(g_key_words) / sizeof(key_word_t))
#define DATATYPE_WORDS_COUNT (ELEMENT_COUNT(g_datatype_words))
#define HINT_KEY_WORDS_COUNT (sizeof(g_hint_key_words) / sizeof(key_word_t))

bool32 lex_match_subset(key_word_t *word_set, int32 count, word_t *word)
{
    int32 begin_pos, end_pos, mid_pos, cmp_result;
    key_word_t *cmp_word = NULL;

    begin_pos = 0;
    end_pos = count - 1;

    while (end_pos >= begin_pos) {
        mid_pos = (begin_pos + end_pos) / 2;
        cmp_word = &word_set[mid_pos];

        cmp_result = cm_compare_text_ins((text_t *)&word->text, &cmp_word->text);
        if (cmp_result == 0) {
            word->namable = (uint32)cmp_word->namable;
            word->id = (uint32)cmp_word->id;
            return GS_TRUE;
        } else if (cmp_result < 0) {
            end_pos = mid_pos - 1;
        } else {
            begin_pos = mid_pos + 1;
        }
    }

    return GS_FALSE;
}

bool32 lex_match_datetime_unit(word_t *word)
{
    return lex_match_subset(g_datetime_unit_words, ELEMENT_COUNT(g_datetime_unit_words), word);
}

const datatype_word_t *lex_match_datatype_words(const datatype_word_t *word_set, int32 count, word_t *word)
{
    int32 begin_pos, end_pos, mid_pos, cmp_result;
    const datatype_word_t *cmp_word = NULL;

    begin_pos = 0;
    end_pos = count - 1;

    while (end_pos >= begin_pos) {
        mid_pos = (begin_pos + end_pos) / 2;
        cmp_word = &word_set[mid_pos];

        cmp_result = cm_compare_text_ins((text_t *)&word->text, &cmp_word->text);
        if (cmp_result == 0) {
            return cmp_word;
        } else if (cmp_result < 0) {
            end_pos = mid_pos - 1;
        } else {
            begin_pos = mid_pos + 1;
        }
    }

    return NULL;
}

bool32 lex_check_datatype(struct st_lex *lex, word_t *typword)
{
    return lex_match_datatype_words(g_datatype_words, DATATYPE_WORDS_COUNT, typword) != NULL;
}

static inline status_t lex_match_if_unsigned_type(struct st_lex *lex, word_t *word, uint32 unsigned_type)
{
    uint32 signed_flag;
    if (lex_try_fetch_1of2(lex, "SIGNED", "UNSIGNED", &signed_flag) != GS_SUCCESS) {
        return GS_ERROR;
    }
    if (signed_flag == 1) {
        word->id = unsigned_type;
    }
    return GS_SUCCESS;
}

static inline status_t lex_match_datatype(struct st_lex *lex, word_t *word)
{
    bool32 result = GS_FALSE;
    /* special handling PG's datatype:
     * + character varying
     * + double precision */
    switch (word->id) {
        case DTYP_CHAR:
            if (lex_try_fetch(lex, "varying", &result) != GS_SUCCESS) {
                return GS_ERROR;
            }
            if (result) {  // if `varying` is found, then the datatype is `VARCHAR`
                word->id = DTYP_VARCHAR;
            }
            break;
        case DTYP_DOUBLE:
            return lex_try_fetch(lex, "precision", &result);

        case DTYP_TINYINT:
            return lex_match_if_unsigned_type(lex, word, DTYP_UTINYINT);

        case DTYP_SMALLINT:
            return lex_match_if_unsigned_type(lex, word, DTYP_USMALLINT);

        case DTYP_BIGINT:
            return lex_match_if_unsigned_type(lex, word, DTYP_UBIGINT);

        case DTYP_INTEGER:
            return lex_match_if_unsigned_type(lex, word, DTYP_UINTEGER);

        case DTYP_BINARY_INTEGER:
            return lex_match_if_unsigned_type(lex, word, DTYP_BINARY_UINTEGER);

        case DTYP_BINARY_BIGINT:
            return lex_match_if_unsigned_type(lex, word, DTYP_BINARY_UBIGINT);

        default:
            // DO NOTHING
            break;
    }
    return GS_SUCCESS;
}

status_t lex_try_match_datatype(struct st_lex *lex, word_t *word, bool32 *matched)
{
    const datatype_word_t *dt_word = lex_match_datatype_words(g_datatype_words, DATATYPE_WORDS_COUNT, word);

    if (dt_word == NULL) {
        if (SECUREC_UNLIKELY(lex->key_word_count != 0)) {  // match external key words only
            if (!lex_match_subset((key_word_t *)lex->key_words, (int32)lex->key_word_count, word)) {
                *matched = GS_FALSE;
                return GS_SUCCESS;
            }
        } else {
            *matched = GS_FALSE;
            return GS_SUCCESS;
        }
    } else {
        word->id = (uint32)dt_word->id;
    }

    word->type = WORD_TYPE_DATATYPE;
    if (lex_match_datatype(lex, word) != GS_SUCCESS) {
        return GS_ERROR;
    }
    *matched = GS_TRUE;
    return GS_SUCCESS;
}

status_t lex_match_keyword(struct st_lex *lex, word_t *word)
{
    lex->ext_flags = 0;
    if (SECUREC_UNLIKELY(lex->key_word_count != 0)) {  // match external key words only
        if (lex_match_subset((key_word_t *)lex->key_words, (int32)lex->key_word_count, word)) {
            word->type = WORD_TYPE_KEYWORD;
            lex->ext_flags = LEX_SINGLE_WORD | LEX_WITH_OWNER;
            return GS_SUCCESS;
        }
    }

    if (lex_match_subset((key_word_t *)g_reserved_words, RESERVED_WORDS_COUNT, word)) {
        word->type = WORD_TYPE_RESERVED;
        return GS_SUCCESS;
    }

    if (lex_match_subset((key_word_t *)g_key_words, KEY_WORDS_COUNT, word)) {
        word->type = WORD_TYPE_KEYWORD;
        if (word->id == KEY_WORD_PRIOR) {
            word->type = WORD_TYPE_OPERATOR;
            word->id = OPER_TYPE_PRIOR;
        }
        return GS_SUCCESS;
    }

    const datatype_word_t *dt_word = lex_match_datatype_words(g_datatype_words, DATATYPE_WORDS_COUNT, word);
    if (dt_word != NULL) {
        word->type = WORD_TYPE_DATATYPE;
        word->id = (uint32)dt_word->id;
        word->namable = dt_word->namable;
        return GS_SUCCESS;
    }

    return GS_SUCCESS;
}

status_t lex_match_hint_keyword(struct st_lex *lex, word_t *word)
{
    if (lex_match_subset((key_word_t *)g_hint_key_words, HINT_KEY_WORDS_COUNT, word)) {
        word->type = WORD_TYPE_HINT_KEYWORD;
    }

    return GS_SUCCESS;
}

void lex_init_keywords(void)
{
    uint32 i;

    for (i = 0; i < KEY_WORDS_COUNT; i++) {
        g_key_words[i].text.len = (uint32)strlen(g_key_words[i].text.str);
    }

    for (i = 0; i < RESERVED_WORDS_COUNT; i++) {
        g_reserved_words[i].text.len = (uint32)strlen(g_reserved_words[i].text.str);
    }

    for (i = 0; i < DATATYPE_WORDS_COUNT; i++) {
        g_datatype_words[i].text.len = (uint32)strlen(g_datatype_words[i].text.str);
    }

    for (i = 0; i < HINT_KEY_WORDS_COUNT; i++) {
        g_hint_key_words[i].text.len = (uint32)strlen(g_hint_key_words[i].text.str);
    }
}

status_t lex_get_word_typmode(word_t *word, typmode_t *typmod)
{
    const datatype_word_t *dt_word = lex_match_datatype_words(g_datatype_words, DATATYPE_WORDS_COUNT, word);
    if (dt_word == NULL) {
        return GS_ERROR;
    }

    switch (dt_word->id) {
        case DTYP_UINTEGER:
        case DTYP_BINARY_UINTEGER:
            typmod->datatype = GS_TYPE_UINT32;
            typmod->size = sizeof(uint32);
            break;
        case DTYP_SMALLINT:
        case DTYP_USMALLINT:
        case DTYP_TINYINT:
        case DTYP_UTINYINT:
        case DTYP_INTEGER:
        case DTYP_BINARY_INTEGER:
            typmod->datatype = GS_TYPE_INTEGER;
            typmod->size = sizeof(int32);
            break;

        case DTYP_BIGINT:
        case DTYP_SERIAL:
        case DTYP_BINARY_BIGINT:
            typmod->datatype = GS_TYPE_BIGINT;
            typmod->size = sizeof(int64);
            break;

        case DTYP_DOUBLE:
        case DTYP_BINARY_DOUBLE:
        case DTYP_FLOAT:
        case DTYP_BINARY_FLOAT:
            typmod->datatype = GS_TYPE_REAL;
            typmod->size = sizeof(double);
            typmod->precision = GS_UNSPECIFIED_REAL_PREC;
            typmod->scale = GS_UNSPECIFIED_REAL_SCALE;
            break;

        default:
            return GS_ERROR;
    }

    return GS_SUCCESS;
}

bool32 lex_match_coll_method_name(sql_text_t *method_name, uint8 *method_id)
{
    if (method_name == NULL) {
        *method_id = METHOD_END;
        return GS_FALSE;
    }

    word_t word;
    word.text = *method_name;
    if (lex_match_subset((key_word_t *)g_method_key_words, METHOD_KEY_WORDS_COUNT, &word)) {
        *method_id = (uint8)word.id;
        return GS_TRUE;
    } else {
        *method_id = METHOD_END;
        return GS_FALSE;
    }
}


#ifdef __cplusplus
}
#endif
