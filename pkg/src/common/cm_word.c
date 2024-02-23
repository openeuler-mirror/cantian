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
    { (uint32)KEY_WORD_ABNORMAL, CT_FALSE, { (char *)"abnormal" } },
    { (uint32)KEY_WORD_ABORT, CT_TRUE, { (char *)"abort" } },
    { (uint32)KEY_WORD_ACCOUNT, CT_TRUE, { (char *)"account" } },
    { (uint32)KEY_WORD_ACTIVATE, CT_TRUE, { (char *)"activate" } },
    { (uint32)KEY_WORD_ACTIVE, CT_TRUE, { (char *)"active" } },
    { (uint32)KEY_WORD_ADD, CT_FALSE, { (char *)"add" } },
    { (uint32)KEY_WORD_AFTER, CT_TRUE, { (char *)"after" } },
    { (uint32)KEY_WORD_ALL, CT_FALSE, { (char *)"all" } },
    { (uint32)KEY_WORD_ALTER, CT_FALSE, { (char *)"alter" } },
    { (uint32)KEY_WORD_ANALYZE, CT_TRUE, { (char *)"analyze" } },
    { (uint32)KEY_WORD_AND, CT_FALSE, { (char *)"and" } },
    { (uint32)KEY_WORD_ANY, CT_FALSE, { (char *)"any" } },
    { (uint32)KEY_WORD_APPENDONLY, CT_TRUE, { (char *)"appendonly" } },
    { (uint32)KEY_WORD_ARCHIVE, CT_TRUE, { (char *)"archive" } },
    { (uint32)KEY_WORD_ARCHIVELOG, CT_TRUE, { (char *)"archivelog" } },
    { (uint32)KEY_WORD_ARCHIVE_SET, CT_FALSE, { (char *)"archive_set" } },
    { (uint32)KEY_WORD_AS, CT_FALSE, { (char *)"as" } },
    { (uint32)KEY_WORD_ASC, CT_FALSE, { (char *)"asc" } },
    { (uint32)KEY_WORD_ASYNC, CT_TRUE, { (char *)"async" } },
    { (uint32)KEY_WORD_AUDIT, CT_FALSE, { (char *)"audit" } },
    { (uint32)KEY_WORD_AUTOALLOCATE, CT_TRUE, { (char *)"autoallocate" } },
    { (uint32)KEY_WORD_AUTOEXTEND, CT_TRUE, { (char *)"autoextend" } },
    { (uint32)KEY_WORD_AUTOMATIC, CT_TRUE, { (char *)"automatic" } },
    { (uint32)KEY_WORD_AUTON_TRANS, CT_TRUE, { (char *)"autonomous_transaction" } },
    { (uint32)KEY_WORD_AUTOOFFLINE, CT_TRUE, { (char *)"autooffline" } },
    { (uint32)KEY_WORD_AUTOPURGE, CT_TRUE, { (char *)"autopurge" } },
    { (uint32)KEY_WORD_AUTO_INCREMENT, CT_TRUE, { (char *)"auto_increment" } },
    { (uint32)KEY_WORD_AVAILABILITY, CT_TRUE, { (char *)"availability" } },
    { (uint32)KEY_WORD_BACKUP, CT_TRUE, { (char *)"backup" } },
    { (uint32)KEY_WORD_BACKUPSET, CT_TRUE, { (char *)"backupset" } },
    { (uint32)KEY_WORD_BEFORE, CT_TRUE, { (char *)"before" } },
    { (uint32)KEY_WORD_BEGIN, CT_TRUE, { (char *)"begin" } },
    { (uint32)KEY_WORD_BETWEEN, CT_FALSE, { (char *)"between" } },
    { (uint32)KEY_WORD_BODY, CT_TRUE, { (char *)"body" } },
    { (uint32)KEY_WORD_BOTH, CT_TRUE, { (char *)"both" } }, /* for TRIM expression only */
    { (uint32)KEY_WORD_BUFFER, CT_TRUE, { (char *)"buffer" } },
    { (uint32)KEY_WORD_BUILD, CT_TRUE, { (char *)"build" } },
    { (uint32)KEY_WORD_BULK, CT_TRUE, { (char *)"bulk" } },
    { (uint32)KEY_WORD_BY, CT_FALSE, { (char *)"by" } },
    { (uint32)KEY_WORD_CACHE, CT_TRUE, { (char *)"cache" } },
    { (uint32)KEY_WORD_CALL, CT_TRUE, { (char *)"call" } },
    { (uint32)KEY_WORD_CANCEL, CT_TRUE, { (char *)"cancel" } },
    { (uint32)KEY_WORD_CASCADE, CT_TRUE, { (char *)"cascade" } },
    { (uint32)KEY_WORD_CASCADED, CT_TRUE, { (char *)"cascaded" } },
    { (uint32)KEY_WORD_CASE, CT_FALSE, { (char *)"case" } },
    { (uint32)KEY_WORD_CAST, CT_TRUE, { (char *)"cast" } },
    { (uint32)KEY_WORD_CATALOG, CT_TRUE, { (char *)"catalog" } },
    { (uint32)KEY_WORD_CHARACTER, CT_TRUE, { (char *)"character" } },
    { (uint32)KEY_WORD_CHARSET, CT_TRUE, { (char *)"charset" } },
    { (uint32)KEY_WORD_CHECK, CT_FALSE, { (char *)"check" } },
    { (uint32)KEY_WORD_CHECKPOINT, CT_TRUE, { (char *)"checkpoint" } },
    { (uint32)KEY_WORD_CLOSE, CT_TRUE, { (char *)"close" } },
    { (uint32)KEY_WORD_CLUSTER, CT_TRUE, { (char *)"cluster" } },
    { (uint32)KEY_WORD_CLUSTERED, CT_TRUE, { (char *)"clustered" } },
    { (uint32)KEY_WORD_COALESCE, CT_TRUE, { (char *)"coalesce" } },
    { (uint32)KEY_WORD_COLLATE, CT_TRUE, { (char *)"collate" } },
    { (uint32)KEY_WORD_COLUMN, CT_FALSE, { (char *)"column" } },
    { (uint32)KEY_WORD_COLUMNS, CT_TRUE, { (char *)"columns" } },
    { (uint32)KEY_WORD_COLUMN_VALUE, CT_TRUE, { (char *)"column_value" } },
    { (uint32)KEY_WORD_COMMENT, CT_TRUE, { (char *)"comment" } },
    { (uint32)KEY_WORD_COMMIT, CT_TRUE, { (char *)"commit" } },
    { (uint32)KEY_WORD_COMPRESS, CT_FALSE, { (char *)"compress" } },
    { (uint32)KEY_WORD_CONFIG, CT_TRUE, { (char *)"config" } },
    { (uint32)KEY_WORD_CONNECT, CT_FALSE, { (char *)"connect" } },
    { (uint32)KEY_WORD_CONSISTENCY, CT_TRUE, { (char *)"consistency" } },
    { (uint32)KEY_WORD_CONSTRAINT, CT_FALSE, { (char *)"constraint" } },
    { (uint32)KEY_WORD_CONTENT, CT_TRUE, { (char *)"content" } },
    { (uint32)KEY_WORD_CONTINUE, CT_TRUE, { (char *)"continue" } },
    { (uint32)KEY_WORD_CONTROLFILE, CT_TRUE, { (char *)"controlfile" } },
    { (uint32)KEY_WORD_CONVERT, CT_TRUE, { (char *)"convert" } },
    { (uint32)KEY_WORD_COPY, CT_TRUE, { (char *)"copy" } },
    { (uint32)KEY_WORD_CREATE, CT_FALSE, { (char *)"create" } },
    { (uint32)KEY_WORD_CRMODE, CT_FALSE, { (char *)"crmode" } },
    { (uint32)KEY_WORD_CROSS, CT_TRUE, { (char *)"cross" } },
    { (uint32)KEY_WORD_CTRLFILE, CT_TRUE, { (char *)"ctrlfile" } },
    { (uint32)KEY_WORD_CUMULATIVE, CT_FALSE, { (char *)"cumulative" } },
    { (uint32)KEY_WORD_CURRENT, CT_FALSE, { (char *)"current" } },
    { (uint32)KEY_WORD_CURRVAL, CT_TRUE, { (char *)"currval" } },
    { (uint32)KEY_WORD_CURSOR, CT_TRUE, { (char *)"cursor" } },
    { (uint32)KEY_WORD_CYCLE, CT_TRUE, { (char *)"cycle" } },
    { (uint32)KEY_WORD_DAAC, CT_TRUE, { (char *)"daac" } },
    { (uint32)KEY_WORD_DATA, CT_TRUE, { (char *)"data" } },
    { (uint32)KEY_WORD_DATABASE, CT_TRUE, { (char *)"database" } },
    { (uint32)KEY_WORD_DATAFILE, CT_TRUE, { (char *)"datafile" } },
    { (uint32)KEY_WORD_DB, CT_FALSE, { (char *)"db" } },
    { (uint32)KEY_WORD_DEBUG, CT_TRUE, { (char *)"debug" } },
    { (uint32)KEY_WORD_DECLARE, CT_TRUE, { (char *)"declare" } },
    { (uint32)KEY_WORD_DEFERRABLE, CT_TRUE, { (char *)"deferrable" } },
    { (uint32)KEY_WORD_DELETE, CT_FALSE, { (char *)"delete" } },
    { (uint32)KEY_WORD_DESC, CT_FALSE, { (char *)"desc" } },
    { (uint32)KEY_WORD_DICTIONARY, CT_TRUE, { (char *)"dictionary" } },
    { (uint32)KEY_WORD_DIRECTORY, CT_TRUE, { (char *)"directory" } },
    { (uint32)KEY_WORD_DISABLE, CT_TRUE, { (char *)"disable" } },
    { (uint32)KEY_WORD_DISCARD, CT_TRUE, { (char *)"discard" } },
    { (uint32)KEY_WORD_DISCONNECT, CT_TRUE, { (char *)"disconnect" } },
    { (uint32)KEY_WORD_DISTINCT, CT_FALSE, { (char *)"distinct" } },
    { (uint32)KEY_WORD_DISTRIBUTE, CT_TRUE, { (char *)"distribute" } },
    { (uint32)KEY_WORD_DO, CT_TRUE, { (char *)"do" } },
    { (uint32)KEY_WORD_DOUBLEWRITE, CT_TRUE, { (char *)"doublewrite" } },
    { (uint32)KEY_WORD_DROP, CT_FALSE, { (char *)"drop" } },
    { (uint32)KEY_WORD_DUMP, CT_TRUE, { (char *)"dump" } },
    { (uint32)KEY_WORD_DUPLICATE, CT_TRUE, { (char *)"duplicate" } },
    { (uint32)KEY_WORD_ELSE, CT_FALSE, { (char *)"else" } },
    { (uint32)KEY_WORD_ELSIF, CT_TRUE, { (char *)"elsif" } },
    { (uint32)KEY_WORD_ENABLE, CT_TRUE, { (char *)"enable" } },
    { (uint32)KEY_WORD_ENABLE_LOGIC_REPLICATION, CT_TRUE, { (char *)"enable_logic_replication" } },
    { (uint32)KEY_WORD_ENCRYPTION, CT_TRUE, { (char *)"encryption" } },
    { (uint32)KEY_WORD_END, CT_TRUE, { (char *)"end" } },
    { (uint32)KEY_WORD_ERROR, CT_TRUE, { (char *)"error" } },
    { (uint32)KEY_WORD_ESCAPE, CT_TRUE, { (char *)"escape" } },
    { (uint32)KEY_WORD_EXCEPT, CT_FALSE, { (char *)"except" } },
    { (uint32)KEY_WORD_EXCEPTION, CT_TRUE, { (char *)"exception" } },
    { (uint32)KEY_WORD_EXCLUDE, CT_TRUE, { (char *)"exclude" } },
    { (uint32)KEY_WORD_EXEC, CT_TRUE, { (char *)"exec" } },
    { (uint32)KEY_WORD_EXECUTE, CT_TRUE, { (char *)"execute" } },
    { (uint32)KEY_WORD_EXISTS, CT_FALSE, { (char *)"exists" } },
    { (uint32)KEY_WORD_EXIT, CT_TRUE, { (char *)"exit" } },
    { (uint32)KEY_WORD_EXPLAIN, CT_TRUE, { (char *)"explain" } },
    { (uint32)KEY_WORD_EXTENT, CT_TRUE, { (char *)"extent" } },
    { (uint32)KEY_WORD_FAILOVER, CT_TRUE, { (char *)"failover" } },
    { (uint32)KEY_WORD_FETCH, CT_TRUE, { (char *)"fetch" } },
    { (uint32)KEY_WORD_FILE, CT_TRUE, { (char *)"file" } },
    { (uint32)KEY_WORD_FILETYPE, CT_TRUE, { (char *)"filetype" } },
    { (uint32)KEY_WORD_FINAL, CT_TRUE, { (char *)"final" } },
    { (uint32)KEY_WORD_FINISH, CT_TRUE, { (char *)"finish" } },
    { (uint32)KEY_WORD_FLASHBACK, CT_TRUE, { (char *)"flashback" } },
    { (uint32)KEY_WORD_FLUSH, CT_TRUE, { (char *)"flush" } },
    { (uint32)KEY_WORD_FOLLOWING, CT_TRUE, { (char *)"following" } },
    { (uint32)KEY_WORD_FOR, CT_FALSE, { (char *)"for" } },
    { (uint32)KEY_WORD_FORALL, CT_FALSE, { (char *)"forall" } },
    { (uint32)KEY_WORD_FORCE, CT_TRUE, { (char *)"force" } },
    { (uint32)KEY_WORD_FOREIGN, CT_TRUE, { (char *)"foreign" } },
    { (uint32)KEY_WORD_FORMAT, CT_TRUE, { (char *)"format" } },
    { (uint32)KEY_WORD_FROM, CT_FALSE, { (char *)"from" } },
    { (uint32)KEY_WORD_FULL, CT_TRUE, { (char *)"full" } },
    { (uint32)KEY_WORD_FUNCTION, CT_TRUE, { (char *)"function" } },
    { (uint32)KEY_WORD_GLOBAL, CT_TRUE, { (char *)"global" } },
    { (uint32)KEY_WORD_GOTO, CT_TRUE, { (char *)"goto" } },
    { (uint32)KEY_WORD_GRANT, CT_TRUE, { (char *)"grant" } },
    { (uint32)KEY_WORD_GROUP, CT_FALSE, { (char *)"group" } },
    { (uint32)KEY_WORD_GROUPID, CT_TRUE, { (char *)"groupid" } },
    { (uint32)KEY_WORD_HASH, CT_TRUE, { (char *)"hash" } },
    { (uint32)KEY_WORD_HAVING, CT_FALSE, { (char *)"having" } },
    { (uint32)KEY_WORD_IDENTIFIED, CT_FALSE, { (char *)"identified" } },
    { (uint32)KEY_WORD_IF, CT_TRUE, { (char *)"if" } },
    { (uint32)KEY_WORD_IGNORE, CT_TRUE, { (char *)"ignore" } },
    { (uint32)KEY_WORD_IN, CT_FALSE, { (char *)"in" } },
    { (uint32)KEY_WORD_INCLUDE, CT_TRUE, { (char *)"include" } },
    { (uint32)KEY_WORD_INCLUDING, CT_TRUE, { (char *)"including" } },
    { (uint32)KEY_WORD_INCREMENT, CT_FALSE, { (char *)"increment" } },
    { (uint32)KEY_WORD_INCREMENTAL, CT_TRUE, { (char *)"incremental" } },
    { (uint32)KEY_WORD_INDEX, CT_FALSE, { (char *)"index" } },
    { (uint32)KEY_WORD_INDEXCLUSTER, CT_FALSE, { (char *)"indexcluster" } },
    { (uint32)KEY_WORD_INDEX_ASC, CT_TRUE, { (char *)"index_asc" } },
    { (uint32)KEY_WORD_INDEX_DESC, CT_TRUE, { (char *)"index_desc" } },
    { (uint32)KEY_WORD_INIT, CT_TRUE, { (char *)"init" } },
    { (uint32)KEY_WORD_INITIAL, CT_TRUE, { (char *)"initial" } },
    { (uint32)KEY_WORD_INITIALLY, CT_TRUE, { (char *)"initially" } },
    { (uint32)KEY_WORD_INITRANS, CT_TRUE, { (char *)"initrans" } },
    { (uint32)KEY_WORD_INNER, CT_TRUE, { (char *)"inner" } },
    { (uint32)KEY_WORD_INSERT, CT_FALSE, { (char *)"insert" } },
    { (uint32)KEY_WORD_INSTANCE, CT_TRUE, { (char *)"instance" } },
    { (uint32)KEY_WORD_INSTANTIABLE, CT_TRUE, { (char *)"instantiable" } },
    { (uint32)KEY_WORD_INSTEAD, CT_TRUE, { (char *)"instead" } },
    { (uint32)KEY_WORD_INTERSECT, CT_FALSE, { (char *)"intersect" } },
    { (uint32)KEY_WORD_INTO, CT_FALSE, { (char *)"into" } },
    { (uint32)KEY_WORD_INVALIDATE, CT_TRUE, { (char *)"invalidate" } },
    { (uint32)KEY_WORD_IS, CT_FALSE, { (char *)"is" } },
    { (uint32)KEY_WORD_IS_NOT, CT_TRUE, { (char *)"isnot" } },
    { (uint32)KEY_WORD_JOIN, CT_TRUE, { (char *)"join" } },
    { (uint32)KEY_WORD_JSON, CT_TRUE, { (char *)"json" } },
    { (uint32)KEY_WORD_JSONB_TABLE, CT_TRUE, { (char *)"jsonb_table" } },
    { (uint32)KEY_WORD_JSON_TABLE, CT_TRUE, { (char *)"json_table" } },
    { (uint32)KEY_WORD_KEEP, CT_TRUE, { (char *)"keep" } },
    { (uint32)KEY_WORD_KEY, CT_TRUE, { (char *)"key" } },
    { (uint32)KEY_WORD_KILL, CT_TRUE, { (char *)"kill" } },
    { (uint32)KEY_WORD_LANGUAGE, CT_TRUE, { (char *)"language" } },
    { (uint32)KEY_WORD_LEADING, CT_TRUE, { (char *)"leading" } }, /* for TRIM expression only */
    { (uint32)KEY_WORD_LEFT, CT_TRUE, { (char *)"left" } },
    { (uint32)KEY_WORD_LESS, CT_TRUE, { (char *)"less" } },
    { (uint32)KEY_WORD_LEVEL, CT_FALSE, { (char *)"level" } },
    { (uint32)KEY_WORD_LIBRARY, CT_FALSE, { (char *)"library" } },
    { (uint32)KEY_WORD_LIKE, CT_FALSE, { (char *)"like" } },
    { (uint32)KEY_WORD_LIMIT, CT_TRUE, { (char *)"limit" } },
    { (uint32)KEY_WORD_LIST, CT_TRUE, { (char *)"list" } },
    { (uint32)KEY_WORD_LNNVL, CT_TRUE, { (char *)"lnnvl" } },
    { (uint32)KEY_WORD_LOAD, CT_TRUE, { (char *)"load" } },
    { (uint32)KEY_WORD_LOB, CT_TRUE, { (char *)"lob" } },
    { (uint32)KEY_WORD_LOCAL, CT_TRUE, { (char *)"local" } },
    { (uint32)KEY_WORD_LOCK, CT_FALSE, { (char *)"lock" } },
    { (uint32)KEY_WORD_LOCK_WAIT, CT_TRUE, { (char *)"lock_wait" } },
    { (uint32)KEY_WORD_LOG, CT_TRUE, { (char *)"log" } },
    { (uint32)KEY_WORD_LOGFILE, CT_TRUE, { (char *)"logfile" } },
    { (uint32)KEY_WORD_LOGGING, CT_TRUE, { (char *)"logging" } },
    { (uint32)KEY_WORD_LOGICAL, CT_TRUE, { (char *)"logical" } },
    { (uint32)KEY_WORD_LOOP, CT_TRUE, { (char *)"loop" } },
    { (uint32)KEY_WORD_MANAGED, CT_TRUE, { (char *)"managed" } },
    { (uint32)KEY_WORD_MAXIMIZE, CT_TRUE, { (char *)"maximize" } },
    { (uint32)KEY_WORD_MAXINSTANCES, CT_TRUE, { (char *)"maxinstances" } },
    { (uint32)KEY_WORD_MAXSIZE, CT_TRUE, { (char *)"maxsize" } },
    { (uint32)KEY_WORD_MAXTRANS, CT_TRUE, { (char *)"maxtrans" } },
    { (uint32)KEY_WORD_MAXVALUE, CT_TRUE, { (char *)"maxvalue" } },
    { (uint32)KEY_WORD_MEMBER, CT_TRUE, { (char *)"member" } },
    { (uint32)KEY_WORD_MEMORY, CT_TRUE, { (char *)"memory" } },
    { (uint32)KEY_WORD_MERGE, CT_TRUE, { (char *)"merge" } },
    { (uint32)KEY_WORD_MINUS, CT_FALSE, { (char *)"minus" } },
    { (uint32)KEY_WORD_MINVALUE, CT_TRUE, { (char *)"minvalue" } },
    { (uint32)KEY_WORD_MODE, CT_TRUE, { (char *)"mode" } },
    { (uint32)KEY_WORD_MODIFY, CT_FALSE, { (char *)"modify" } },
    { (uint32)KEY_WORD_MONITOR, CT_TRUE, { (char *)"monitor" } },
    { (uint32)KEY_WORD_MOUNT, CT_TRUE, { (char *)"mount" } },
    { (uint32)KEY_WORD_MOVE, CT_TRUE, { (char *)"move" } },
    { (uint32)KEY_WORD_NEXT, CT_TRUE, { (char *)"next" } },
    { (uint32)KEY_WORD_NEXTVAL, CT_TRUE, { (char *)"nextval" } },
    { (uint32)KEY_WORD_NOARCHIVELOG, CT_TRUE, { (char *)"noarchivelog" } },
    { (uint32)KEY_WORD_NO_CACHE, CT_TRUE, { (char *)"nocache" } },
    { (uint32)KEY_WORD_NO_COMPRESS, CT_FALSE, { (char *)"nocompress" } },
    { (uint32)KEY_WORD_NO_CYCLE, CT_TRUE, { (char *)"nocycle" } },
    { (uint32)KEY_WORD_NODE, CT_TRUE, { (char *)"node" } },
    { (uint32)KEY_WORD_NO_LOGGING, CT_TRUE, { (char *)"nologging" } },
    { (uint32)KEY_WORD_NO_MAXVALUE, CT_TRUE, { (char *)"nomaxvalue" } },
    { (uint32)KEY_WORD_NO_MINVALUE, CT_TRUE, { (char *)"nominvalue" } },
    { (uint32)KEY_WORD_NO_ORDER, CT_TRUE, { (char *)"noorder" } },
    { (uint32)KEY_WORD_NO_RELY, CT_TRUE, { (char *)"norely" } },
    { (uint32)KEY_WORD_NOT, CT_FALSE, { (char *)"not" } },
    { (uint32)KEY_WORD_NO_VALIDATE, CT_TRUE, { (char *)"novalidate" } },
    { (uint32)KEY_WORD_NOWAIT, CT_FALSE, { (char *)"nowait" } },
    { (uint32)KEY_WORD_NULL, CT_FALSE, { (char *)"null" } },
    { (uint32)KEY_WORD_NULLS, CT_TRUE, { (char *)"nulls" } },
    { (uint32)KEY_WORD_OF, CT_FALSE, { (char *)"of" } },
    { (uint32)KEY_WORD_OFF, CT_TRUE, { (char *)"off" } },
    { (uint32)KEY_WORD_OFFLINE, CT_FALSE, { (char *)"offline" } },
    { (uint32)KEY_WORD_OFFSET, CT_TRUE, { (char *)"offset" } },
    { (uint32)KEY_WORD_ON, CT_FALSE, { (char *)"on" } },
    { (uint32)KEY_WORD_ONLINE, CT_FALSE, { (char *)"online" } },
    { (uint32)KEY_WORD_ONLY, CT_TRUE, { (char *)"only" } },
    { (uint32)KEY_WORD_OPEN, CT_TRUE, { (char *)"open" } },
    { (uint32)KEY_WORD_OR, CT_FALSE, { (char *)"or" } },
    { (uint32)KEY_WORD_ORDER, CT_FALSE, { (char *)"order" } },
    { (uint32)KEY_WORD_ORGANIZATION, CT_TRUE, { (char *)"organization" } },
    { (uint32)KEY_WORD_OUTER, CT_TRUE, { (char *)"outer" } },
    { (uint32)KEY_WORD_PACKAGE, CT_TRUE, { (char *)"package" } },
    { (uint32)KEY_WORD_PARALLEL, CT_TRUE, { (char *)"parallel" } },
    { (uint32)KEY_WORD_PARALLELISM, CT_TRUE, { (char *)"parallelism" } },
    { (uint32)KEY_WORD_PARAM, CT_TRUE, { (char *)"parameter" } },
    { (uint32)KEY_WORD_PARTITION, CT_TRUE, { (char *)"partition" } },
    { (uint32)KEY_WORD_PASSWORD, CT_TRUE, { (char *)"password" } },
    { (uint32)KEY_WORD_PATH, CT_TRUE, { (char *)"path" } },
    { (uint32)KEY_WORD_PCTFREE, CT_TRUE, { (char *)"pctfree" } },
    { (uint32)KEY_WORD_PERFORMANCE, CT_TRUE, { (char *)"performance" } },
    { (uint32)KEY_WORD_PHYSICAL, CT_TRUE, { (char *)"physical" } },
    { (uint32)KEY_WORD_PIVOT, CT_TRUE, { (char *)"pivot" } },
    { (uint32)KEY_WORD_PLAN, CT_TRUE, { (char *)"plan" } },
    { (uint32)KEY_WORD_PRAGMA, CT_TRUE, { (char *)"pragma" } },
    { (uint32)KEY_WORD_PRECEDING, CT_TRUE, { (char *)"preceding" } },
    { (uint32)KEY_WORD_PREPARE, CT_TRUE, { (char *)"prepare" } },
    { (uint32)KEY_WORD_PREPARED, CT_TRUE, { (char *)"prepared" } },
    { (uint32)KEY_WORD_PRESERVE, CT_TRUE, { (char *)"preserve" } },
    { (uint32)KEY_WORD_PRIMARY, CT_TRUE, { (char *)"primary" } },
    { (uint32)KEY_WORD_PRIOR, CT_TRUE, { (char *)"prior" } },
    { (uint32)KEY_WORD_PRIVILEGES, CT_FALSE, { (char *)"privileges" } },
    { (uint32)KEY_WORD_PROCEDURE, CT_TRUE, { (char *)"procedure" } },
    { (uint32)KEY_WORD_PROFILE, CT_TRUE, { (char *)"profile" } },
    { (uint32)KEY_WORD_PROTECTION, CT_TRUE, { (char *)"protection" } },
    { (uint32)KEY_WORD_PUBLIC, CT_FALSE, { (char *)"public" } },
    { (uint32)KEY_WORD_PUNCH, CT_TRUE, { (char *)"punch" } },
    { (uint32)KEY_WORD_PURGE, CT_TRUE, { (char *)"purge" } },
    { (uint32)KEY_WORD_QUERY, CT_TRUE, { (char *)"query" } },
    { (uint32)KEY_WORD_RAISE, CT_TRUE, { (char *)"raise" } },
    { (uint32)KEY_WORD_RANGE, CT_TRUE, { (char *)"range" } },
    { (uint32)KEY_WORD_READ, CT_TRUE, { (char *)"read" } },
    { (uint32)KEY_WORD_READ_ONLY, CT_TRUE, { (char *)"readonly" } },
    { (uint32)KEY_WORD_READ_WRITE, CT_TRUE, { (char *)"readwrite" } },
    { (uint32)KEY_WORD_REBUILD, CT_TRUE, { (char *)"rebuild" } },
    { (uint32)KEY_WORD_RECOVER, CT_TRUE, { (char *)"recover" } },
    { (uint32)KEY_WORD_RECYCLE, CT_TRUE, { (char *)"recycle" } },
    { (uint32)KEY_WORD_RECYCLEBIN, CT_TRUE, { (char *)"recyclebin" } },
    { (uint32)KEY_WORD_REDO, CT_TRUE, { (char *)"redo" } },
    { (uint32)KEY_WORD_REFERENCES, CT_TRUE, { (char *)"references" } },
    { (uint32)KEY_WORD_REFRESH, CT_TRUE, { (char *)"refresh" } },
    { (uint32)KEY_WORD_REGEXP, CT_TRUE, { (char *)"regexp" } },
    { (uint32)KEY_WORD_REGEXP_LIKE, CT_TRUE, { (char *)"regexp_like" } },
    { (uint32)KEY_WORD_REGISTER, CT_TRUE, { (char *)"register" } },
    { (uint32)KEY_WORD_RELEASE, CT_TRUE, { (char *)"release" } },
    { (uint32)KEY_WORD_RELOAD, CT_TRUE, { (char *)"reload" } },
    { (uint32)KEY_WORD_RELY, CT_TRUE, { (char *)"rely" } },
    { (uint32)KEY_WORD_RENAME, CT_FALSE, { (char *)"rename" } },
    { (uint32)KEY_WORD_REPAIR, CT_FALSE, { (char *)"repair" } },
    { (uint32)KEY_WORD_REPLACE, CT_TRUE, { (char *)"replace" } },
    { (uint32)KEY_WORD_REPLICATION, CT_TRUE, { (char *)"replication" } },
    { (uint32)KEY_WORD_RESET, CT_TRUE, { (char *)"reset" } },
    { (uint32)KEY_WORD_RESIZE, CT_TRUE, { (char *)"resize" } },
    { (uint32)KEY_WORD_RESTORE, CT_TRUE, { (char *)"restore" } },
    { (uint32)KEY_WORD_RESTRICT, CT_TRUE, { (char *)"restrict" } },
    { (uint32)KEY_WORD_RETURN, CT_TRUE, { (char *)"return" } },
    { (uint32)KEY_WORD_RETURNING, CT_TRUE, { (char *)"returning" } },
    { (uint32)KEY_WORD_REUSE, CT_TRUE, { (char *)"reuse" } },
    { (uint32)KEY_WORD_REVERSE, CT_TRUE, { (char *)"reverse" } },
    { (uint32)KEY_WORD_REVOKE, CT_TRUE, { (char *)"revoke" } },
    { (uint32)KEY_WORD_RIGHT, CT_TRUE, { (char *)"right" } },
    { (uint32)KEY_WORD_ROLE, CT_TRUE, { (char *)"role" } },
    { (uint32)KEY_WORD_ROLLBACK, CT_TRUE, { (char *)"rollback" } },
    { (uint32)KEY_WORD_ROUTE, CT_TRUE, { (char *)"route" } },
    { (uint32)KEY_WORD_ROWS, CT_FALSE, { (char *)"rows" } },
    { (uint32)KEY_WORD_SAVEPOINT, CT_TRUE, { (char *)"savepoint" } },
    { (uint32)KEY_WORD_SCN, CT_TRUE, { (char *)"scn" } },
    { (uint32)KEY_WORD_SECONDARY, CT_TRUE, { (char *)"secondary" } },
    { (uint32)KEY_WORD_SECTION, CT_TRUE, { (char *)"section" } },
    { (uint32)KEY_WORD_SELECT, CT_FALSE, { (char *)"select" } },
    { (uint32)KEY_WORD_SEPARATOR, CT_TRUE, { (char *)"separator" } },
    { (uint32)KEY_WORD_SEQUENCE, CT_TRUE, { (char *)"sequence" } },
    { (uint32)KEY_WORD_SERIALIZABLE, CT_TRUE, { (char *)"serializable" } },
    { (uint32)KEY_WORD_SERVER, CT_TRUE, { (char *)"server" } },
    { (uint32)KEY_WORD_SESSION, CT_FALSE, { (char *)"session" } },
    { (uint32)KEY_WORD_SET, CT_FALSE, { (char *)"set" } },
    { (uint32)KEY_WORD_SHARE, CT_TRUE, { (char *)"share" } },
    { (uint32)KEY_WORD_SHOW, CT_TRUE, { (char *)"show" } },
    { (uint32)KEY_WORD_SHRINK, CT_TRUE, { (char *)"shrink" } },
    { (uint32)KEY_WORD_SHUTDOWN, CT_TRUE, { (char *)"shutdown" } },
#ifdef DB_DEBUG_VERSION
    { (uint32)KEY_WORD_SIGNAL, CT_TRUE, { (char *)"signal" } },
#endif
    { (uint32)KEY_WORD_SIZE, CT_TRUE, { (char *)"size" } },
    { (uint32)KEY_WORD_SKIP, CT_TRUE, { (char *)"skip" } },
    { (uint32)KEY_WORD_SKIP_ADD_DROP_TABLE, CT_TRUE, { (char *)"skip_add_drop_table" } },
    { (uint32)KEY_WORD_SKIP_COMMENTS, CT_TRUE, { (char *)"skip_comment" } },
    { (uint32)KEY_WORD_SKIP_TRIGGERS, CT_TRUE, { (char *)"skip_triggers" } },
    { (uint32)KEY_WORD_SKIP_QUOTE_NAMES, CT_TRUE, { (char *)"skip_quote_names" } },
    { (uint32)KEY_WORD_SPACE, CT_TRUE, { (char *)"space" } },
    { (uint32)KEY_WORD_SPLIT, CT_TRUE, { (char *)"split" } },
    { (uint32)KEY_WORD_SPLIT_FACTOR, CT_TRUE, { (char *)"split_factor" } },
    { (uint32)KEY_WORD_SQL_MAP, CT_FALSE, { (char *)"sql_map" } },
    { (uint32)KEY_WORD_STANDARD, CT_TRUE, { (char *)"standard" } },
    { (uint32)KEY_WORD_STANDBY, CT_TRUE, { (char *)"standby" } },
    { (uint32)KEY_WORD_START, CT_FALSE, { (char *)"start" } },
    { (uint32)KEY_WORD_STARTUP, CT_TRUE, { (char *)"startup" } },
    { (uint32)KEY_WORD_STOP, CT_TRUE, { (char *)"stop" } },
    { (uint32)KEY_WORD_STORAGE, CT_TRUE, { (char *)"storage" } },
    { (uint32)KEY_WORD_SUBPARTITION, CT_TRUE, { (char *)"subpartition" } },
    { (uint32)KEY_WORD_SWAP, CT_TRUE, { (char *)"swap" } },
    { (uint32)KEY_WORD_SWITCH, CT_TRUE, { (char *)"switch" } },
    { (uint32)KEY_WORD_SWITCHOVER, CT_TRUE, { (char *)"switchover" } },
#ifdef DB_DEBUG_VERSION
    { (uint32)KEY_WORD_SYNCPOINT, CT_TRUE, { (char *)"syncpoint" } },
#endif
    { (uint32)KEY_WORD_SYNONYM, CT_FALSE, { (char *)"synonym" } },
    { (uint32)KEY_WORD_SYSAUX, CT_TRUE, { (char *)"sysaux" } },
    { (uint32)KEY_WORD_SYSTEM, CT_TRUE, { (char *)"system" } },
    { (uint32)KEY_WORD_TABLE, CT_FALSE, { (char *)"table" } },
    { (uint32)KEY_WORD_TABLES, CT_TRUE, { (char *)"tables" } },
    { (uint32)KEY_WORD_TABLESPACE, CT_TRUE, { (char *)"tablespace" } },
    { (uint32)KEY_WORD_TAG, CT_TRUE, { (char *)"tag" } },
    { (uint32)KEY_WORD_TEMP, CT_TRUE, { (char *)"temp" } },
    { (uint32)KEY_WORD_TEMPFILE, CT_TRUE, { (char *)"tempfile" } },
    { (uint32)KEY_WORD_TEMPORARY, CT_TRUE, { (char *)"temporary" } },
    { (uint32)KEY_WORD_TENANT, CT_TRUE, { (char *)"tenant" } },
    { (uint32)KEY_WORD_THAN, CT_TRUE, { (char *)"than" } },
    { (uint32)KEY_WORD_THEN, CT_FALSE, { (char *)"then" } },
    { (uint32)KEY_WORD_THREAD, CT_TRUE, { (char *)"thread" } },
    { (uint32)KEY_WORD_TIMEOUT, CT_TRUE, { (char *)"timeout" } },
    { (uint32)KEY_WORD_TIMEZONE, CT_TRUE, { (char *)"time_zone" } },
    { (uint32)KEY_WORD_TO, CT_FALSE, { (char *)"to" } },
    { (uint32)KEY_WORD_TRAILING, CT_TRUE, { (char *)"trailing" } }, /* for TRIM expression only */
    { (uint32)KEY_WORD_TRANSACTION, CT_TRUE, { (char *)"transaction" } },
    { (uint32)KEY_WORD_TRIGGER, CT_FALSE, { (char *)"trigger" } },
    { (uint32)KEY_WORD_TRUNCATE, CT_TRUE, { (char *)"truncate" } },
    { (uint32)KEY_WORD_TYPE, CT_TRUE, { (char *)"type" } },
    { (uint32)KEY_WORD_UNDO, CT_TRUE, { (char *)"undo" } },
    { (uint32)KEY_WORD_UNIFORM, CT_TRUE, { (char *)"uniform" } },
    { (uint32)KEY_WORD_UNION, CT_FALSE, { (char *)"union" } },
    { (uint32)KEY_WORD_UNIQUE, CT_TRUE, { (char *)"unique" } },
    { (uint32)KEY_WORD_UNLIMITED, CT_TRUE, { (char *)"unlimited" } },
    { (uint32)KEY_WORD_UNLOCK, CT_TRUE, { (char *)"unlock" } },
    { (uint32)KEY_WORD_UNPIVOT, CT_TRUE, { (char *)"unpivot" } },
    { (uint32)KEY_WORD_UNTIL, CT_TRUE, { (char *)"until" } },
    { (uint32)KEY_WORD_UNUSABLE, CT_TRUE, { (char *)"unusable" } },
    { (uint32)KEY_WORD_UPDATE, CT_FALSE, { (char *)"update" } },
    { (uint32)KEY_WORD_USER, CT_FALSE, { (char *)"user" } },
    { (uint32)KEY_WORD_USERS, CT_TRUE, { (char *)"users" } },
    { (uint32)KEY_WORD_USING, CT_TRUE, { (char *)"using" } },
    { (uint32)KEY_WORD_VALIDATE, CT_TRUE, { (char *)"validate" } },
    { (uint32)KEY_WORD_VALUES, CT_FALSE, { (char *)"values" } },
    { (uint32)KEY_WORD_VIEW, CT_FALSE, { (char *)"view" } },
    { (uint32)KEY_WORD_WAIT, CT_TRUE, { (char *)"wait" } },
    { (uint32)KEY_WORD_WHEN, CT_TRUE, { (char *)"when" } },
    { (uint32)KEY_WORD_WHERE, CT_FALSE, { (char *)"where" } },
    { (uint32)KEY_WORD_WHILE, CT_FALSE, { (char *)"while" } },
    { (uint32)KEY_WORD_WITH, CT_FALSE, { (char *)"with" } },
};

#ifdef WIN32
static_assert(sizeof(g_key_words) / sizeof(key_word_t) == KEY_WORD_DUMB_END - KEY_WORD_0_UNKNOWN - 1,
              "Array g_key_words defined error");
#endif

/* datatype key words */
static datatype_word_t g_datatype_words[] = {
    { { (char *)"bigint" }, DTYP_BIGINT, CT_TRUE, CT_TRUE },
    { { (char *)"binary" }, DTYP_BINARY, CT_TRUE, CT_FALSE },
    { { (char *)"binary_bigint" }, DTYP_BINARY_BIGINT, CT_TRUE, CT_TRUE },
    { { (char *)"binary_double" }, DTYP_BINARY_DOUBLE, CT_TRUE, CT_FALSE },
    { { (char *)"binary_float" }, DTYP_BINARY_FLOAT, CT_TRUE, CT_FALSE },
    { { (char *)"binary_integer" }, DTYP_BINARY_INTEGER, CT_TRUE, CT_TRUE },
    { { (char *)"binary_uint32" }, DTYP_UINTEGER, CT_TRUE, CT_FALSE },
    { { (char *)"blob" }, DTYP_BLOB, CT_TRUE, CT_FALSE },
    { { (char *)"bool" }, DTYP_BOOLEAN, CT_TRUE, CT_FALSE },
    { { (char *)"boolean" }, DTYP_BOOLEAN, CT_TRUE, CT_FALSE },
    { { (char *)"bpchar" }, DTYP_CHAR, CT_TRUE, CT_FALSE },
    { { (char *)"bytea" }, DTYP_BLOB, CT_TRUE, CT_FALSE },
    { { (char *)"char" }, DTYP_CHAR, CT_FALSE, CT_FALSE },
    { { (char *)"character" }, DTYP_CHAR, CT_TRUE, CT_FALSE },
    { { (char *)"clob" }, DTYP_CLOB, CT_TRUE, CT_FALSE },
    { { (char *)"date" }, DTYP_DATE, CT_FALSE, CT_FALSE },
    { { (char *)"datetime" }, DTYP_DATE, CT_TRUE, CT_FALSE },
    { { (char *)"decimal" }, DTYP_DECIMAL, CT_FALSE, CT_FALSE },
    { { (char *)"double" }, DTYP_DOUBLE, CT_TRUE, CT_FALSE },
    { { (char *)"float" }, DTYP_FLOAT, CT_TRUE, CT_FALSE },
    { { (char *)"image" }, DTYP_IMAGE, CT_TRUE, CT_FALSE },
    { { (char *)"int" }, DTYP_INTEGER, CT_TRUE, CT_TRUE },
    { { (char *)"integer" }, DTYP_INTEGER, CT_FALSE, CT_TRUE },
    { { (char *)"interval" }, DTYP_INTERVAL, CT_TRUE, CT_FALSE },
    { { (char *)"jsonb" }, DTYP_JSONB, CT_TRUE, CT_FALSE },
    { { (char *)"long" }, DTYP_CLOB, CT_TRUE, CT_FALSE },
    { { (char *)"longblob" }, DTYP_IMAGE, CT_TRUE, CT_FALSE },
    { { (char *)"longtext" }, DTYP_CLOB, CT_TRUE, CT_FALSE },
    { { (char *)"mediumblob" }, DTYP_IMAGE, CT_TRUE, CT_FALSE },
    { { (char *)"nchar" }, DTYP_NCHAR, CT_TRUE, CT_FALSE },
    { { (char *)"number" }, DTYP_NUMBER, CT_FALSE, CT_FALSE },
    { { (char *)"number2" }, DTYP_NUMBER2, CT_TRUE, CT_FALSE },
    { { (char *)"numeric" }, DTYP_DECIMAL, CT_TRUE, CT_FALSE },
    { { (char *)"nvarchar" }, DTYP_NVARCHAR, CT_TRUE, CT_FALSE },
    { { (char *)"nvarchar2" }, DTYP_NVARCHAR, CT_TRUE, CT_FALSE },
    { { (char *)"raw" }, DTYP_RAW, CT_FALSE, CT_FALSE },
    { { (char *)"real" }, DTYP_DOUBLE, CT_TRUE, CT_FALSE },
    { { (char *)"serial" }, DTYP_SERIAL, CT_TRUE, CT_FALSE },
    { { (char *)"short" }, DTYP_SMALLINT, CT_TRUE, CT_TRUE },
    { { (char *)"smallint" }, DTYP_SMALLINT, CT_TRUE, CT_TRUE },
    { { (char *)"text" }, DTYP_CLOB, CT_TRUE, CT_FALSE },
    { { (char *)"timestamp" }, DTYP_TIMESTAMP, CT_TRUE, CT_FALSE },
    { { (char *)"tinyint" }, DTYP_TINYINT, CT_TRUE, CT_TRUE },
    { { (char *)"ubigint" }, DTYP_UBIGINT, CT_TRUE, CT_FALSE },
    { { (char *)"uint" }, DTYP_UINTEGER, CT_TRUE, CT_FALSE },
    { { (char *)"uinteger" }, DTYP_UINTEGER, CT_TRUE, CT_FALSE },
    { { (char *)"ushort" }, DTYP_USMALLINT, CT_TRUE, CT_FALSE },
    { { (char *)"usmallint" }, DTYP_USMALLINT, CT_TRUE, CT_FALSE },
    { { (char *)"utinyint" }, DTYP_UTINYINT, CT_TRUE, CT_FALSE },
    { { (char *)"varbinary" }, DTYP_VARBINARY, CT_TRUE, CT_FALSE },
    { { (char *)"varchar" }, DTYP_VARCHAR, CT_FALSE, CT_FALSE },
    { { (char *)"varchar2" }, DTYP_VARCHAR, CT_FALSE, CT_FALSE },
};

/* reserved keywords
 * **Note:** the reserved keywords must be arrange in alphabetically
 * ascending order for speeding the search process. */
static key_word_t g_reserved_words[] = {
    { (uint32)RES_WORD_COLUMN_VALUE,       CT_TRUE,  { (char *)"column_value" } },
    { (uint32)RES_WORD_CONNECT_BY_ISCYCLE, CT_TRUE,  { (char *)"connect_by_iscycle" } },
    { (uint32)RES_WORD_CONNECT_BY_ISLEAF,  CT_TRUE,  { (char *)"connect_by_isleaf" } },
    { (uint32)RES_WORD_CURDATE,            CT_TRUE,  { (char *)"curdate" } },
    { (uint32)RES_WORD_CURDATE,            CT_TRUE,  { (char *)"current_date" } },
    { (uint32)RES_WORD_CURTIMESTAMP,       CT_TRUE,  { (char *)"current_timestamp" } },
    { (uint32)RES_WORD_DATABASETZ,         CT_TRUE,  { (char *)"dbtimezone" } },
    { (uint32)RES_WORD_DEFAULT,            CT_FALSE, { (char *)"default" } },
    { (uint32)RES_WORD_DELETING,           CT_TRUE,  { (char *)"deleting" } },
    { (uint32)RES_WORD_FALSE,              CT_FALSE, { (char *)"false" } },
    { (uint32)RES_WORD_INSERTING,          CT_TRUE,  { (char *)"inserting" } },
    { (uint32)RES_WORD_LEVEL,              CT_FALSE, { (char *)"level" } },
    { (uint32)RES_WORD_LOCALTIMESTAMP,     CT_TRUE,  { (char *)"localtimestamp" } },
    { (uint32)RES_WORD_SYSTIMESTAMP,       CT_TRUE,  { (char *)"now" } },
    { (uint32)RES_WORD_NULL,               CT_FALSE, { (char *)"null" } },
    { (uint32)RES_WORD_ROWID,              CT_FALSE, { (char *)"rowid" } },
    { (uint32)RES_WORD_ROWNODEID,          CT_FALSE, { (char *)"rownodeid" } },
    { (uint32)RES_WORD_ROWNUM,             CT_FALSE, { (char *)"rownum" } },
    { (uint32)RES_WORD_ROWSCN,             CT_FALSE, { (char *)"rowscn" } },
    { (uint32)RES_WORD_SESSIONTZ,          CT_TRUE,  { (char *)"sessiontimezone" } },
    { (uint32)RES_WORD_SYSDATE,            CT_FALSE, { (char *)"sysdate" } },
    { (uint32)RES_WORD_SYSTIMESTAMP,       CT_TRUE,  { (char *)"systimestamp" } },
    { (uint32)RES_WORD_TRUE,               CT_FALSE, { (char *)"true" } },
    { (uint32)RES_WORD_UPDATING,           CT_TRUE,  { (char *)"updating" } },
    { (uint32)RES_WORD_USER,               CT_FALSE, { (char *)"user" } },
    { (uint32)RES_WORD_UTCTIMESTAMP,       CT_TRUE,  { (char *)"utc_timestamp" } },
};

static key_word_t g_datetime_unit_words[] = {
    { (uint32)IU_DAY,         CT_TRUE, { "DAY", 3 } },
    { (uint32)IU_HOUR,        CT_TRUE, { "HOUR", 4 } },
    { (uint32)IU_MICROSECOND, CT_TRUE, { "MICROSECOND", 11 } },
    { (uint32)IU_MINUTE,      CT_TRUE, { "MINUTE", 6 } },
    { (uint32)IU_MONTH,       CT_TRUE, { "MONTH", 5 } },
    { (uint32)IU_QUARTER,     CT_TRUE, { "QUARTER", 7 } },
    { (uint32)IU_SECOND,      CT_TRUE, { "SECOND", 6 } },
    { (uint32)IU_DAY,         CT_TRUE, { "SQL_TSI_DAY", 11 } },
    { (uint32)IU_MICROSECOND, CT_TRUE, { "SQL_TSI_FRAC_SECOND", 19 } },
    { (uint32)IU_HOUR,        CT_TRUE, { "SQL_TSI_HOUR", 12 } },
    { (uint32)IU_MINUTE,      CT_TRUE, { "SQL_TSI_MINUTE", 14 } },
    { (uint32)IU_MONTH,       CT_TRUE, { "SQL_TSI_MONTH", 13 } },
    { (uint32)IU_QUARTER,     CT_TRUE, { "SQL_TSI_QUARTER", 15 } },
    { (uint32)IU_SECOND,      CT_TRUE, { "SQL_TSI_SECOND", 14 } },
    { (uint32)IU_WEEK,        CT_TRUE, { "SQL_TSI_WEEK", 12 } },
    { (uint32)IU_YEAR,        CT_TRUE, { "SQL_TSI_YEAR", 12 } },
    { (uint32)IU_WEEK,        CT_TRUE, { "WEEK", 4 } },
    { (uint32)IU_YEAR,        CT_TRUE, { "YEAR", 4 } },
};

static key_word_t g_hint_key_words[] = {
    { (uint32)ID_HINT_CB_MTRL,          CT_FALSE, { (char *)"cb_mtrl", 7 } },
    { (uint32)ID_HINT_DB_VERSION,       CT_FALSE, { (char *)"db_version", 10 } },
    { (uint32)ID_HINT_FULL,             CT_FALSE, { (char *)"full", 4 } },
    { (uint32)ID_HINT_HASH_AJ,          CT_FALSE, { (char *)"hash_aj", 7 } },
    { (uint32)ID_HINT_HASH_BUCKET_SIZE, CT_FALSE, { (char *)"hash_bucket_size", 16 } },
    { (uint32)ID_HINT_HASH_SJ,          CT_FALSE, { (char *)"hash_sj", 7 } },
    { (uint32)ID_HINT_HASH_TABLE,       CT_FALSE, { (char *)"hash_table", 10 } },
    { (uint32)ID_HINT_INDEX,            CT_FALSE, { (char *)"index", 5 } },
    { (uint32)ID_HINT_INDEX_ASC,        CT_FALSE, { (char *)"index_asc", 9 } },
    { (uint32)ID_HINT_INDEX_DESC,       CT_FALSE, { (char *)"index_desc", 10 } },
    { (uint32)ID_HINT_INDEX_FFS,        CT_FALSE, { (char *)"index_ffs", 9 } },
    { (uint32)ID_HINT_INDEX_SS,         CT_FALSE, { (char *)"index_ss", 8 } },
    { (uint32)ID_HINT_INLINE,           CT_FALSE, { (char *)"inline", 6 } },
    { (uint32)ID_HINT_LEADING,          CT_FALSE, { (char *)"leading", 7 } },
    { (uint32)ID_HINT_MATERIALIZE,      CT_FALSE, { (char *)"materialize", 11 } },
    { (uint32)ID_HINT_NL_BATCH,         CT_FALSE, { (char *)"nl_batch", 8 } },
    { (uint32)ID_HINT_NL_FULL_MTRL,     CT_FALSE, { (char *)"nl_full_mtrl", 12 } },
    { (uint32)ID_HINT_NL_FULL_OPT,      CT_FALSE, { (char *)"nl_full_opt", 11 } },
    { (uint32)ID_HINT_NO_CB_MTRL,       CT_FALSE, { (char *)"no_cb_mtrl", 10 } },
    { (uint32)ID_HINT_NO_HASH_TABLE,    CT_FALSE, { (char *)"no_hash_table", 13 } },
    { (uint32)ID_HINT_NO_INDEX,         CT_FALSE, { (char *)"no_index", 8 } },
    { (uint32)ID_HINT_NO_INDEX_FFS,     CT_FALSE, { (char *)"no_index_ffs", 12 } },
    { (uint32)ID_HINT_NO_INDEX_SS,      CT_FALSE, { (char *)"no_index_ss", 11 } },
    { (uint32)ID_HINT_NO_OR_EXPAND,     CT_FALSE, { (char *)"no_or_expand", 12 } },
    { (uint32)ID_HINT_NO_PUSH_PRED,     CT_FALSE, { (char *)"no_push_pred", 12 } },
    { (uint32)ID_HINT_NO_UNNEST,        CT_FALSE, { (char *)"no_unnest", 9 } },
    { (uint32)ID_HINT_OPTIM_MODE,       CT_FALSE, { (char *)"optimizer_mode", 14 } },
    { (uint32)ID_HINT_OPT_ESTIMATE,     CT_FALSE, { (char *)"opt_estimate", 12 } },
    { (uint32)ID_HINT_OPT_PARAM,        CT_FALSE, { (char *)"opt_param", 9 } },
    { (uint32)ID_HINT_ORDERED,          CT_FALSE, { (char *)"ordered", 7 } },
    { (uint32)ID_HINT_OR_EXPAND,        CT_FALSE, { (char *)"or_expand", 9 } },
    { (uint32)ID_HINT_FEATURES_ENABLE,  CT_FALSE, { (char *)"outline_features_enable", 23 } },
    { (uint32)ID_HINT_PARALLEL,         CT_FALSE, { (char *)"parallel", 8 } },
    { (uint32)ID_HINT_RULE,             CT_FALSE, { (char *)"rule", 4 } },
    { (uint32)ID_HINT_SEMI_TO_INNER,    CT_FALSE, { (char *)"semi_to_inner", 13 } },
#ifdef Z_SHARDING
    { (uint32)ID_HINT_SHD_READ_MASTER,  CT_FALSE, { (char *)"shd_read_master", 15 } },
    { (uint32)ID_HINT_SQL_WHITELIST,    CT_FALSE, { (char *)"sql_whitelist", 13 } },
#endif
    { (uint32)ID_HINT_THROW_DUPLICATE,  CT_FALSE, { (char *)"throw_duplicate", 15 } },
    { (uint32)ID_HINT_UNNEST,           CT_FALSE, { (char *)"unnest", 6 } },
    { (uint32)ID_HINT_USE_CONCAT,       CT_FALSE, { (char *)"use_concat", 10 } },
    { (uint32)ID_HINT_USE_HASH,         CT_FALSE, { (char *)"use_hash", 8 } },
    { (uint32)ID_HINT_USE_MERGE,        CT_FALSE, { (char *)"use_merge", 9 } },
    { (uint32)ID_HINT_USE_NL,           CT_FALSE, { (char *)"use_nl", 6 } },
};

const key_word_t g_method_key_words[] = {
    {(uint32)METHOD_COUNT,  CT_TRUE, { (char *)"COUNT",  5 } },
    {(uint32)METHOD_DELETE, CT_TRUE, { (char *)"DELETE", 6 } },
    {(uint32)METHOD_EXISTS, CT_TRUE, { (char *)"EXISTS", 6 } },
    {(uint32)METHOD_EXTEND, CT_TRUE, { (char *)"EXTEND", 6 } },
    {(uint32)METHOD_FIRST,  CT_TRUE, { (char *)"FIRST",  5 } },
    {(uint32)METHOD_LAST,   CT_TRUE, { (char *)"LAST",   4 } },
    {(uint32)METHOD_LIMIT,  CT_TRUE, { (char *)"LIMIT",  5 } },
    {(uint32)METHOD_NEXT,   CT_TRUE, { (char *)"NEXT",   4 } },
    {(uint32)METHOD_PRIOR,  CT_TRUE, { (char *)"PRIOR",  5 } },
    {(uint32)METHOD_TRIM,   CT_TRUE, { (char *)"TRIM",   4 } }
};

const key_word_t g_pl_attr_words[] = {
    { (uint32)PL_ATTR_WORD_FOUND,     CT_TRUE, { (char *)"FOUND",    5 } },
    { (uint32)PL_ATTR_WORD_ISOPEN,    CT_TRUE, { (char *)"ISOPEN",   6 } },
    { (uint32)PL_ATTR_WORD_NOTFOUND,  CT_TRUE, { (char *)"NOTFOUND", 8 } },
    { (uint32)PL_ATTR_WORD_ROWCOUNT,  CT_TRUE, { (char *)"ROWCOUNT", 8 } },
    { (uint32)PL_ATTR_WORD_ROWTYPE,   CT_TRUE, { (char *)"ROWTYPE",  7 } },
    { (uint32)PL_ATTR_WORD_TYPE,      CT_TRUE, { (char *)"TYPE",     4 } },
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
            return CT_TRUE;
        } else if (cmp_result < 0) {
            end_pos = mid_pos - 1;
        } else {
            begin_pos = mid_pos + 1;
        }
    }

    return CT_FALSE;
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
    if (lex_try_fetch_1of2(lex, "SIGNED", "UNSIGNED", &signed_flag) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (signed_flag == 1) {
        word->id = unsigned_type;
    }
    return CT_SUCCESS;
}

static inline status_t lex_match_datatype(struct st_lex *lex, word_t *word)
{
    bool32 result = CT_FALSE;
    /* special handling PG's datatype:
     * + character varying
     * + double precision */
    switch (word->id) {
        case DTYP_CHAR:
            if (lex_try_fetch(lex, "varying", &result) != CT_SUCCESS) {
                return CT_ERROR;
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
    return CT_SUCCESS;
}

status_t lex_try_match_datatype(struct st_lex *lex, word_t *word, bool32 *matched)
{
    const datatype_word_t *dt_word = lex_match_datatype_words(g_datatype_words, DATATYPE_WORDS_COUNT, word);

    if (dt_word == NULL) {
        if (SECUREC_UNLIKELY(lex->key_word_count != 0)) {  // match external key words only
            if (!lex_match_subset((key_word_t *)lex->key_words, (int32)lex->key_word_count, word)) {
                *matched = CT_FALSE;
                return CT_SUCCESS;
            }
        } else {
            *matched = CT_FALSE;
            return CT_SUCCESS;
        }
    } else {
        word->id = (uint32)dt_word->id;
    }

    word->type = WORD_TYPE_DATATYPE;
    if (lex_match_datatype(lex, word) != CT_SUCCESS) {
        return CT_ERROR;
    }
    *matched = CT_TRUE;
    return CT_SUCCESS;
}

status_t lex_match_keyword(struct st_lex *lex, word_t *word)
{
    lex->ext_flags = 0;
    if (SECUREC_UNLIKELY(lex->key_word_count != 0)) {  // match external key words only
        if (lex_match_subset((key_word_t *)lex->key_words, (int32)lex->key_word_count, word)) {
            word->type = WORD_TYPE_KEYWORD;
            lex->ext_flags = LEX_SINGLE_WORD | LEX_WITH_OWNER;
            return CT_SUCCESS;
        }
    }

    if (lex_match_subset((key_word_t *)g_reserved_words, RESERVED_WORDS_COUNT, word)) {
        word->type = WORD_TYPE_RESERVED;
        return CT_SUCCESS;
    }

    if (lex_match_subset((key_word_t *)g_key_words, KEY_WORDS_COUNT, word)) {
        word->type = WORD_TYPE_KEYWORD;
        if (word->id == KEY_WORD_PRIOR) {
            word->type = WORD_TYPE_OPERATOR;
            word->id = OPER_TYPE_PRIOR;
        }
        return CT_SUCCESS;
    }

    const datatype_word_t *dt_word = lex_match_datatype_words(g_datatype_words, DATATYPE_WORDS_COUNT, word);
    if (dt_word != NULL) {
        word->type = WORD_TYPE_DATATYPE;
        word->id = (uint32)dt_word->id;
        word->namable = dt_word->namable;
        return CT_SUCCESS;
    }

    return CT_SUCCESS;
}

status_t lex_match_hint_keyword(struct st_lex *lex, word_t *word)
{
    if (lex_match_subset((key_word_t *)g_hint_key_words, HINT_KEY_WORDS_COUNT, word)) {
        word->type = WORD_TYPE_HINT_KEYWORD;
    }

    return CT_SUCCESS;
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
        return CT_ERROR;
    }

    switch (dt_word->id) {
        case DTYP_UINTEGER:
        case DTYP_BINARY_UINTEGER:
            typmod->datatype = CT_TYPE_UINT32;
            typmod->size = sizeof(uint32);
            break;
        case DTYP_SMALLINT:
        case DTYP_USMALLINT:
        case DTYP_TINYINT:
        case DTYP_UTINYINT:
        case DTYP_INTEGER:
        case DTYP_BINARY_INTEGER:
            typmod->datatype = CT_TYPE_INTEGER;
            typmod->size = sizeof(int32);
            break;

        case DTYP_BIGINT:
        case DTYP_SERIAL:
        case DTYP_BINARY_BIGINT:
            typmod->datatype = CT_TYPE_BIGINT;
            typmod->size = sizeof(int64);
            break;

        case DTYP_DOUBLE:
        case DTYP_BINARY_DOUBLE:
        case DTYP_FLOAT:
        case DTYP_BINARY_FLOAT:
            typmod->datatype = CT_TYPE_REAL;
            typmod->size = sizeof(double);
            typmod->precision = CT_UNSPECIFIED_REAL_PREC;
            typmod->scale = CT_UNSPECIFIED_REAL_SCALE;
            break;

        default:
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

bool32 lex_match_coll_method_name(sql_text_t *method_name, uint8 *method_id)
{
    if (method_name == NULL) {
        *method_id = METHOD_END;
        return CT_FALSE;
    }

    word_t word;
    word.text = *method_name;
    if (lex_match_subset((key_word_t *)g_method_key_words, METHOD_KEY_WORDS_COUNT, &word)) {
        *method_id = (uint8)word.id;
        return CT_TRUE;
    } else {
        *method_id = METHOD_END;
        return CT_FALSE;
    }
}


#ifdef __cplusplus
}
#endif
