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
 * cm_error.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_error.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_text.h"
#include "cm_log.h"

#ifdef WIN32
#include "winsock.h"
#endif

#ifndef WIN32
#include <execinfo.h>
#endif
#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
__declspec(thread) error_info_t g_tls_error = { 0 };
__declspec(thread) tls_plc_error_t g_tls_plc_error = { 0 };

#else
__thread error_info_t g_tls_error = { 0 };
__thread tls_plc_error_t g_tls_plc_error = { 0 };
#endif

bool32 g_enable_err_superposed = GS_FALSE;
/*
 * one error no corresponds to one error desc
 * Attention: keep the array index same as error no
 */
const char *g_error_desc[] = {
    [ERR_ERRNO_BASE] = "Normal, no error reported",
    [ERR_ALLOC_MEMORY] = "Failed to allocate %llu bytes for %s",
    [ERR_OPEN_FILE] = "Failed to open the file %s, the error code was %d",
    [ERR_CREATE_FILE] = "Failed to create the file %s, the error code was %d",
    [ERR_READ_FILE] = "Failed to read data from the file, the error code was %d",
    [ERR_WRITE_FILE] = "Failed to write the file, the error code was %d",
    [ERR_INVALID_FILE_NAME] = "The file name (%s) exceeded the maximum length (%u)",
    [ERR_FILE_SIZE_MISMATCH] = "File size(%lld) does not match with the expected(%llu)",
    [ERR_CREATE_DIR] = "Failed to create the path %s, error code %d",
    [ERR_RENAME_FILE] = "Failed to rename the file %s to %s, error code %d",
    [ERR_REMOVE_FILE] = "Failed to remove file %s, error code %d",
    [ERR_CREATE_THREAD] = "Failed to create a new thread, %s",
    [ERR_INIT_THREAD] = "Failed to init thread attribute",
    [ERR_SET_THREAD_STACKSIZE] = "Failed to set thread stacksize",
    [ERR_CREATE_SEMAPORE] = "Failed to create IPC semaphore",
    [ERR_ATTACH_SEMAPORE] = "Failed to attach IPC semaphore",
    [ERR_CREATE_SHARED_MEMORY] = "Failed to create IPC shared memory",
    [ERR_CREATE_EVENT] = "Failed to initialize event notification, error code %d",
    [ERR_LOAD_LIBRARY] = "Failed to load library '%s': error code %d",
    [ERR_LOAD_SYMBOL] = "Failed to load symbol '%s': error reason %s",
    [ERR_INIT_SYSTEM] = "Failed to get program name: error code %d",
    [ERR_GENERATE_GUID] = "Failed to generate guid: %s",
    [ERR_GENERATE_SHA1] = "Failed to generate sha1 hash for '%s'",
    [ERR_FILE_ALREADY_EXIST] = "File %s already exist: %s",
    [ERR_INVALID_DIR] = "Directory '%s' not exist or not reachable or invalid",
    [ERR_FILE_PATH_TOO_LONG] = "File path is too long (maximum %u)",
    [ERR_ALLOC_MEMORY_REACH_LIMIT] = "Have reach the memory limit %lld",
    [ERR_STACK_LIMIT_EXCEED] = "Stack depth limit exceeded",
    [ERR_WRITE_FILE_PART_FINISH] =
        "Write size %d, expected size %d, mostly because file size is larger than disk, please delete the incomplete file",
    [ERR_RESET_MEMORY] = "Failed to reset %s",
    [ERR_READ_DEVICE_INCOMPLETE] = "Read size %d, expected size %d, please check incomplete file",
    [ERR_LOCK_LIMIT_EXCEED] = "Lock numbers limit exceeded",
    [ERR_SEEK_FILE] = "Failed to seek file, offset:%llu, origin:%d, error code %d",
    [ERR_TRUNCATE_FILE] = "Failed to truncate file, offset:%llu, error code %d",
    [ERR_FILE_HAS_EXIST] = "File %s already exist",
    [ERR_LOCK_FILE] = "Failed to lock file, error code %d",
    [ERR_PROC_BIND_CPU] = "Failed to bind process/thread to CPU node, error code %d",
    [ERR_TOO_MANY_CPUS] = "Too many CPU node bind, exceeds the maximum %u",
    [ERR_THREAD_VARIANT_FAIL] = "Failed to operate thread variant %s, reason [%d] %s",
    [ERR_FILE_ACCESS] = "Failed to access file, error code %d",
    [ERR_SYSTEM_CALL] = "Secure C lib has thrown an error %d",
    [ERR_DATAFILE_FSYNC] = "Failed to fsync the file, the error code was %d",
    [ERR_DATAFILE_FDATASYNC] = "Failed to fdatasync the file, the error code was %d",
    [ERR_DATAFILE_EXTEND_PARTIALLY] =
        "Extend datafile partially, extended size %lld, expected size %lld, mostly because there is no enough space on disk",
    [ERR_SYSTEM_TIME] = "System time increased exceeds the range allowed, database time: %ld, system time: %ld",
    [ERR_EXECUTE_FILE] = "Failed to execute the file, the error code was %d",
    [ERR_REMOVE_DIR] = "Failed to remove directory %s",
    [ERR_FALLOCATE_FILE] = "Failed to fallocate the file, the error code was %d",
    [ERR_READ_LONGSQL_FILE] = "Failed to read data from the longsql file",
    [ERR_MEM_ZONE_INIT] = "Failed to init buddy memory zone",
    [ERR_MEM_OUT_OF_MEMORY] = "Failed to allocate %llu bytes from buddy memory pool",
    [ERR_UNLOCK_FILE] = "Failed to unlock file, error code %d",
    /* internal errors or common errors */
    [ERR_STACK_OVERFLOW] = "Session stack overflow",
    [ERR_EXECUTER_STACK_OVERFLOW] = "PL/SQL executor block stack overflow",
    [ERR_STACK_OVERSPACE] = "No more space in the stack",
    [ERR_OBJECT_STACK_OVERDEPTH] = "Too many tables or subqueries or triggers exceeds maximum stack depth",
    [ERR_TEXT_FORMAT_ERROR] = "Invalid format of %s",
    [ERR_COVNERT_FORMAT_ERROR] = "Too many bytes to converting as %s",
    [ERR_MUTIPLE_FORMAT_ERROR] = "There were duplicate strings in the time format",
    [ERR_UNRECOGNIZED_FORMAT_ERROR] = "Unrecognized format code",
    [ERR_CAPABILITY_NOT_SUPPORT] = "Capability: %s not supported",
    [ERR_ONLY_SUPPORT_STR] = "Capability: %s only supported %s",
    [ERR_OUT_OF_INDEX] = "%s out of index,limits is %u",
    [ERR_ROW_SIZE_TOO_LARGE] = "The size of row is too large, max_row_size=%u",
    [ERR_MAX_COLUMN_SIZE] = "Column count exceeded the limit %d",
    [ERR_ALLOC_GA_MEMORY] = "Can't allocate page from %s",
    [ERR_ENCRYPTION_ERROR] = "Failed to encrypt password",
    [ERR_DECODE_ERROR] = "Failed to decode password",
    [ERR_REUSED_PASSWORD_ERROR] = "Can not reused the password",
    [ERR_COMPRESS_INIT_ERROR] = "%s failed to init stream context, errno=%d, %s",
    [ERR_COMPRESS_ERROR] = "%s failed to compress, errno=%d, %s",
    [ERR_MALLOC_BYTES_MEMORY] = "Can't malloc %u bytes",
    [ERR_MALLOC_MAX_MEMORY] = "Malloc number(%d) already be max",
    [ERR_HASH_TABLE_TOO_LARGE] = "Hash table too large to be created, buckets=%d",
    [ERR_BUFFER_OVERFLOW] = "Current text buffer is %d, longer than the maximum %d",
    [ERR_BUFFER_UNDERFLOW] = "Current text buffer is %d, shorter than the minimum %d",
    [ERR_DEVICE_NOT_SUPPORT] = "The device type was not supported",
    [ERR_PROTOCOL_NOT_SUPPORT] = "Protocol not supported",
    [ERR_INVALID_COMMAND] = "Invalid %s command",
    [ERR_OPERATIONS_NOT_SUPPORT] = "Operation %s is not supported on %s",
    [ERR_LOB_SIZE_TOO_LARGE] = "Lob size limits to %s",
    [ERR_MAX_PART_KEY] = "The size of part key exceed max column size: %u",
    [ERR_DECOMPRESS_ERROR] = "%s failed to decompress, errno=%d, %s",
    [ERR_WRITE_LOG_FAILED] = "Failed to write %s",
    [ERR_RAFT_MODULE_NOT_INITED] = "RAFT: raft is not enabled, or raft module is not initialized",
    [ERR_ASSERT_ERROR] = "Assert raised, expect: %s",
    [ERR_COMPRESS_FREE_ERROR] = "%s failed to free stream context, errno=%d, %s",
    [ERR_CRYPTION_ERROR] = "cryption failed, %s",
    [ERR_ENCRYPTION_NOT_SUPPORT_DDL] = "encryption not support: %s %d",
    [ERR_FAILED_PARALL_GATHER_STATS] = "Gather statistics parallel failed",
    [ERR_SYSTEM_BUSY] = "The system is busy, please check modifying lsnr/shutdown/promote/demote",
    [ERR_SCSI_LOCK_OCCUPIED] = "The lock is already occupied",
    [ERR_SCSI_REG_CONFLICT] = "Register conflict, rk %llu",
    [ERR_SKLIST_ERR] = "sklist is invalid",
    [ERR_SKLIST_NOT_INIT] = "sklist is not initial",
    [ERR_SKLIST_NOT_EXIST] = "sklist is not existed",
    [ERR_SKLIST_EXIST] = "sklist is already exist",

    /* invalid configuration errors */
    [ERR_FILE_SIZE_TOO_LARGE] = "The size of config file %s is too large",
    [ERR_INVALID_PARAMETER_NAME] = "The parameter name \"%s\" was invalid",
    [ERR_INVALID_PARAMETER] = "The parameter value \"%s\" was invalid",
    [ERR_ALTER_READONLY_PARAMETER] = "%s is a readonly parameter",
    [ERR_CONFIG_BUFFER_FULL] = "Configuration buf is full",
    [ERR_LINE_SIZE_TOO_LONG] = "The length of row %d is too long",
    [ERR_LL_SYNTAX_ERROR] = "Syntax analysis error",
    [ERR_DUPLICATE_PARAMETER] = "Duplicate or conflicting parameter %s",
    [ERR_DUPLICATE_FILE] = "Duplicate or conflicting file %s",
    [ERR_RANDOM_GENERATE] = "Could not generate random encryption vector",
    [ERR_RANDOM_INIT] = "Could not initialize openssl random bit generator",
    /*
     * newly added in 09.26 for configuration error. the "PARAMETER"
     * here refers to the config parameter in the configuration,
     * do not be confused with the argument in the function of C programming language
     */
    [ERR_UNSUPPORTED_EMBEDDED_PARAMETER] = "Parameter \"%s\" is not supported in an embedded parameter file",
    [ERR_PARAMETER_TOO_SMALL] = "The value of parameter \"%s\" is too small, at least %lld",
    [ERR_PARAMETER_TOO_LARGE] = "The value of parameter \"%s\" is too large, at most %lld",
    [ERR_PARAMETER_OVER_RANGE] = "The value of parameter \"%s\" should be in [%lld, %lld]",
    [ERR_INVALID_PARAMETER_ENUM] = "The value of parameter \"%s\" cannot be recognized: \"%s\"",
    [ERR_PARAMETER_CANNOT_IGNORE] = "Parameter \"%s\" must be set",
    [ERR_INVALID_SYSINFO] = "Invalid value of system information \"%s\": %d",
    [ERR_ASYNC_ONLY_PARAMETER] = "%s should run in asynchronous mode",
    [ERR_UPDATE_PARAMETER_FAIL] = "Updating \"%s\" failed. cause: %s",
    [ERR_NLS_INTERNAL_ERROR] = "Nls internal error, invalid %s",
    [ERR_LOG_ARCHIVE_CONFIG_TOO_MANY] = "The value of \"ARCHIVE_CONFIG\" more than 1 %s config",
    [ERR_PARAMETER_NOT_MODIFIABLE] = "The parameter \"%s\" is not modifiable with this option",

    [ERR_INVALID_HBA_ITEM] = "%s line(%d) format is not correct",
    [ERR_EXCEED_HBA_MAX_SIZE] = "Hba entry exceed the max size(%d)",
    [ERR_HBA_MOD_FAILED] = "Hba entry modified failed, input: %s",
    [ERR_HBA_ITEM_NOT_FOUND] = "Hba entry modified failed, entry not found, input: %s",
    [ERR_PATH_NOT_EXIST_OR_ACCESSABLE] = "%s does not exist or is not readable or writable",
    [ERR_PATH_NOT_EXIST] = "%s is not an existing folder",
    [ERR_PATH_NOT_ACCESSABLE] = "%s is not a readable or writable folder",
    [ERR_CIPHER_NOT_SUPPORT] = "Cipher \"%s\" is invalid or not supported",
    [ERR_EMPTY_STRING_NOT_ALLOWED] = "Empty string is not allowed here",
    [ERR_FUNC_NULL_ARGUMENT] = "Null is not allowed for the function argument",
    [ERR_FUNC_ARGUMENT_WRONG_TYPE] = "The argument %d should be type %s",
    [ERR_FUNC_ARGUMENT_OUT_OF_RANGE] = "The function argument is out of range",
    [ERR_INVALID_REGEXP_INSTR_PARAM] =
        "Invalid parameters for \"REGEXP_INSTR\", offset=%d, occur=%d, subexpr=%d, return_opt=%d",
    [ERR_INVALID_REGEXP_INSTR_PARAM_NO_OPT] =
        "Invalid parameters for \"REGEXP_INSTR\", offset=%d, occur=%d, subexpr=%d",
    [ERR_FUNC_ARG_NEEDED] = "Argument %d for \"%s\" is needed",
    [ERR_ANALYTIC_FUNC_NO_CLAUSE] = "There must be at least one clause for the analytic function",
    [ERR_INVALID_SEPARATOR] = "Invalid separator specified in \"%s\"",
    [ERR_INVALID_TABFUNC_1ST_ARG] = "The 1st argument of table function needs a normal table name",
    [ERR_NO_ORDER_BY_CLAUSE] = "Order-by clause should be specified for the function \"%s\"",
    [ERR_TCP_VALID_NODE_CHECKING] =
        "For invited and excluded nodes is both empty, ip whitelist function can't be enabled",
    [ERR_TCP_NODE_EMPTY_CONFIG] =
        "Ip whitelist function is enabled, invited and excluded nodes can't set to both empty",
    [ERR_CMD_NOT_ALLOWED_TO_EXEC] = "Cmd whitelist is enabled,cmd \"%s\" is not allowed to execute",
    [ERR_PATH_NOT_ALLOWED_TO_ACCESS] = "Path whitelist is enabled, path \"%s\" is not allowed to access",
    [ERR_LSNR_IP_DELETE_ERROR] = "It is the only listening IP address and cannot be deleted",
    [ERR_IPADDRESS_LOCAL_NOT_EXIST] = "IP address %s is not local ip, please check your ifconfig",
    [ERR_INVALID_REPL_PORT] = "Can not get valid replication port for peer node",
    [ERR_UNDO_TABLESPACE_NOT_MATCH] = "Parameter UNDO_TABLESPACE value %s does not match with database value %s",
    [ERR_GENERIC_INTERNAL_ERROR] = "Internal logical error, message: %s",

    /* network errors */
    [ERR_INIT_NETWORK_ENV] = "Init network env failed, %s",
    [ERR_PROTOCOL_INCOMPATIBALE] = "The protocol version of client and server is incompatible",
    [ERR_ESTABLISH_TCP_CONNECTION] = "Failed to establish tcp connection to [%s]:[%u], errno %d",
    [ERR_PEER_CLOSED] = "%s connection is closed",
    [ERR_TCP_TIMEOUT] = "%s timeout",
    [ERR_INVALID_TCP_PACKET] = "The packet is invalid, action: \"%s\", expect size: %u, actual size: %u",
    [ERR_CREATE_SOCKET] = "Failed to create new socket, errno %d",
    [ERR_SET_SOCKET_OPTION] = "Failed to set SO_REUSEADDR option for listener socket",
    [ERR_TCP_PORT_CONFLICTED] = "Tcp port conflict %s:%u",
    [ERR_SOCKET_BIND] = "Failed to bind socket for %s:%u, error code %d",
    [ERR_SOCKET_LISTEN] = "Failed to %s, error code %d",
    [ERR_CREATE_AGENT] = "Failed to create new %s",
    [ERR_INVALID_PROTOCOL] = "Unknown request, protocol error",
    [ERR_SOCKET_TIMEOUT] = "Socket wait timeout, timeout=[%ds]",
    [ERR_IPC_LSNR_CLOSED] = "Ipc listener is closed",
    [ERR_IPC_CONNECT_ERROR] = "Failed to connect to ipc server, reason: %s",
    [ERR_IPC_UNINITIALIZED] = "Ipc uninitialized",
    [ERR_IPC_PROCESS_NOT_EXISTS] = "The server process does not exist",
    [ERR_IPC_STARTUP] = "The server start timeout(3s), or the shm block is invalid",
    [ERR_GENERATE_CIPHER] = "Failed to generate login cipher",
    [ERR_TCP_RECV] = "Failed to recv from %s pipe, errno %d",
    [ERR_SESSION_CLOSED] = "%s, stop accepting new connection any more",
    [ERR_PRI_NOT_CONNECT] = "Log receiver is not ready, can not get %s",
    [ERR_FULL_PACKET] = "%s packet size(%u) exceeds the max value(%u)",
    [ERR_PACKET_READ] = "Receive packet has no more data to read, packet size: %u, offset: %u, read: %u",
    [ERR_REPLICA_AGENT] = "Replica agent error, remote ip [%s] not configured in archive destination",
    [ERR_PASSWORD_EXPIRED] = "The user password has expired",
    [ERR_ACCOUNT_LOCK] = "The account was locked",
    [ERR_ACCOUNT_AUTH_FAILED] = "Incorrect user or password",
    [ERR_TCP_INVALID_IPADDRESS] = "Invalid IP address: %s",
    [ERR_CLI_INVALID_IP_LOGIN] =
        "IP list rejects connection for user \"%s\", ip \"%s\", current date \"%s\", please check zhba.conf or tcp valid node configuration",

    [ERR_ESTABLISH_UDS_CONNECTION] = "Failed to establish uds connection to [%s], errno=%d",
    [ERR_SSL_INIT_FAILED] = "SSL init error: %s",
    [ERR_EXCEED_SESSIONS_PER_USER] = "Number of sessions per user exceeds the maximum %d",
    [ERR_INVALID_IPADDRESS_LENGTH] = "Invalid IP address length: %u",
    [ERR_IPADDRESS_NUM_EXCEED] = "Number of IP address exceeds the maximum(%u)",
    [ERR_DB_RESTRICT_STATUS] = "Database is in restricted status, only allow %s access",
    [ERR_TCP_TIMEOUT_REMAIN] = "Waiting for request head(size) timeout, %d bytes remained",
    [ERR_PEER_CLOSED_REASON] = "%s connection is closed, reason: %d",
    [ERR_TCP_PKT_VERIFY] = "Failed to verify %s",
    [ERR_SSL_VERIFY_CERT] = "Failed to verify SSL certificate, reason %s",
    [ERR_REPL_PORT_ACCESS] = "REPL_PORT is used for replication only, external service will be rejected",
    [ERR_SSL_NOT_SUPPORT] = "SSL is required but the server doesn't support it",
    [ERR_SSL_CA_REQUIRED] = "SSL CA certificate is required when ssl_mode is SSL_VERIFY_CA or SSL_VERIFY_FULL",
    [ERR_SSL_CONNECT_FAILED] = "The SSL connection failed, %s",
    [ERR_SSL_FILE_PERMISSION] = "SSL certificate file \"%s\" has execute, group or world access permission",
    [ERR_SSL_CONNECT_REQUIRED] = "SSL encrypted connection is required for user \"%s\" from \"%s\"",
    [ERR_UDS_BIND] = "Failed to bind unix domain socket for %s, error code %d",
    [ERR_UDS_CONFLICTED] = "Unix domain socket conflict %s",
    [ERR_PACKET_SEND] = "Send packet has no more space to put data, buff size: %u, head size: %u, put size: %u",
    [ERR_INVALID_ENCRYPTION_ITERATION] = "Iteration must between %u and %u",
    [ERR_SSL_RECV_FAILED] = "Failed to recv from ssl pipe, sslerr: %d, errno: %d, errmsg: %s",
    [ERR_MAX_NORMAL_EMERGE_SESS] = "Emergency session's connection of normal user reaches the maximum",
    [ERR_UDS_INVALID_URL] =
        "Invalid unix domain socket url:%s, length %d. Eg:server_locator=\"UDS:UNIX_emserver.domain\"",

    /* instance */
    [ERR_HOME_PATH_NOT_FOUND] = "Environment variant %s not found",
    [ERR_TOO_MANY_CONNECTIONS] = "Too many connections exceed pool maximum",
    [ERR_TOO_MANY_RM_OBJECTS] = "Too many RM objects exceed pool maximum %u",
    [ERR_INVALID_RM_GTID] = "invalid RM gtid %s",
    [ERR_NESTED_AUTON_SESSIONS] = "Can not begin nested autonomous session",
    [ERR_START_INSTANCE_ERROR] = "Start kernel instance failed",
    [ERR_TOO_MANY_STAT_OBJECTS] = "Too many STAT objects exceed pool maximum %d",
    [ERR_USER_DDL_LOCKED] = "user ddl has been locked %d",

    /* client errors */
    [ERR_CLT_INVALID_ATTR] = "Invalid %s: %s",
    [ERR_CLT_INVALID_VALUE] = "Invalid %s: %u",
    [ERR_CLT_STRING_BUF_TOO_SMALL] = "%s %u as string buffer is too small",
    [ERR_CLT_INVALID_BIND] = "Failed to bind parameter, %s",
    [ERR_CLT_INVALID_COLUMN] = "Row column count(%u) is not equal to stmt %s count(%u)",
    [ERR_CLT_OUT_OF_INDEX] = "There was out-of-range behavior on the index: %s",
    [ERR_CLT_TOO_MANY_BINDS] = "Size of bindings exceed the maximum(%u)",
    [ERR_CLT_OUT_OF_API_SEQUENCE] = "Out of API sequence, %s",
    [ERR_CLT_COL_SIZE_TOO_SMALL] = "Column %u %s buffer is too small, buffer size: %u, size required: %u",
    [ERR_CLT_BIND_SIZE_SMALL] = "Column %u %s buffer is too small, buffer size: %u",
    [ERR_CLT_BUF_SIZE_TOO_SMALL] = "Buffer is too small to %s",
    [ERR_CLT_OBJECT_IS_NULL] = "%s is null",
    [ERR_CLT_TRANS_CHARSET] = "Failed to translate charset, column: %s, value: %s",
    [ERR_CLT_CONN_CLOSE] = "Connect is not established",
    [ERR_CLT_MULTIPLE_SQL] = "Multiple sql must use query mode to execute",
    [ERR_CLT_WSR_ERR] = "Err occur when generate WSR report, msg: %s",
    [ERR_CLT_PARALLEL_LOCK] = "Parallel operation is not supported, sid=[%u], current tid=[%u]",
    [ERR_CLT_FETCH_INVALID_FLAGS] = "Fetch but get invalid flags",
    [ERR_CLT_WRITE_FILE_ERR] = "Err occur when write file, errno=%d",
    [ERR_CLT_IMP_DATAFILE] = "Import error occur when %s, detail: %s",
    [ERR_CLT_API_NOT_SUPPORTED] = "%s not supported",
    [ERR_CLT_UDS_FILE_EMPTY] = "Unix domain socket path is empty",
    [ERR_CLT_UNEXPECTED_CMD] = "Unexpected packet cmd, expect %u, recieve %u",

    [ERR_CLT_CLUSTER_INVALID] = "Cluster error: %s",

    [ERR_CONSTRAINT_VIOLATED] = "No insert/update/delete on table with some constraints disabled and validated",
    [ERR_TABLE_IS_REFERENCED] = "The unique index or primary key was referenced by a foreign key",
    [ERR_TABLE_NOT_EMPTY] = "Table %s.%s is not empty, hint: use force option to flashback truncate",
    [ERR_INVALID_FLASHBACK_TYPE] = "Invalid flashback type %d",
    [ERR_INVALID_PURGE_TYPE] = "Invalid purge type %u",

    [ERR_INVALID_ARCHIVE_LOG] = "Invalid archive file %s",

    /* sql engine */
    [ERR_SQL_VIEW_ERROR] = "View %s has errors",
    [ERR_SQL_SYNTAX_ERROR] = "Sql syntax error: %s",
    [ERR_SQL_TOO_LONG] = "Sql text is too long, length = %u",
    [ERR_COORD_NOT_SUPPORT] = "%s not supported on coordinator node",
    [ERR_DUPLICATE_NAME] = "Duplicate %s name %s",
    [ERR_GROUPING_NOT_ALLOWED] = "GROUPING function is not allowed here",
    [ERR_TYPE_MISMATCH] = "Inconsistent datatypes, expected %s - got %s",
    [ERR_INVALID_DATA_TYPE] = "Invalid datatype for %s",
    [ERR_INVALID_EXPRESSION] = "Invalid expression",
    [ERR_EXPR_NOT_IN_GROUP_LIST] = "Expression not in group list",
    [ERR_GROUPING_NO_GROUPBY] = "GROUPING function is supported only with GROUP BY clause",
    [ERR_REQUEST_OUT_OF_SQUENCE] = "No sql %s",
    [ERR_EXPECTED_AGGR_FUNTION] = "Aggregation function expected, but %s found",
    [ERR_INVALID_OPERATION] = "Invalid operation%s",
    [ERR_INVALID_FUNC_PARAMS] = "Parameter error: %s",
    [ERR_INVALID_FUNC_PARAM_COUNT] = "Invalid argument number for %s, min=%u, max=%u",
    [ERR_TTREE_OVERFLOW_REBALANCE] = "",
    [ERR_SQL_INVALID_PRECISION] = "",
    [ERR_INVALID_COLUMN_NAME] = "The column '%s' was invalid",
    [ERR_COLUMNS_MISMATCH] =
        "The number of columns specified in view creation was inconsistent with that of columns covered in query",
    [ERR_COLUMN_NOT_NULL] = "Can't set NULL value for column '%s'",
    [ERR_SQL_TOO_COMPLEX] = "Too many material result sets",
    [ERR_NO_FREE_VMEM] = "Virtual memory capacity error,details is '%s'",
    [ERR_SQL_PLAN_ERROR] = "Sql execute error,detail is '%s',plan type is %d",
    [ERR_INVALID_COL_TYPE] = "The distinct column type [%d] is not supported",
    [ERR_EXPR_DATA_TYPE_NOT_MATCH] = "", /* internal error code,not in used now */
    [ERR_NOT_COMPATIBLE] = "Set %s is not supported",
    [ERR_STRUCT_MEMBER_NULL] = "", /* internal error code,not in used now */
    [ERR_EXECUTE_DML] = "",        /* internal error code,not in used now */
    [ERR_VM] = "Virtual memory error,detail is '%s'",
    [ERR_FUNC_DATE_INVALID] = "",   /* internal error code,not in used now */
    [ERR_FUNC_RESULT_INVALID] = "", /* internal error code,not in used now */
    [ERR_SQL_STACK_FULL] = "",      /* internal error code,not in used now */
    [ERR_CREATE_INDEX_ON_TYPE] = "Cannot create %s index on column with datatype '%s'",
    [ERR_TOO_MANY_BIND] = "Sql has too many bind parameters, count = %d, max = %d",
    [ERR_BIND_NOT_MATCH] = "Number of output parameter not match binding",
    [ERR_SEQUENCE_NOT_ALLOWED] = "Sequences were not supported",
    [ERR_DUPLICATE_AUTO_COLUMN] = "There can be only one auto column and it must be defined as a key",
    [ERR_DUPLICATE_TABLE] = "%s.%s already exists",
    [ERR_UNKNOWN_LOB_TYPE] = "Unknown lob type when %s",
    [ERR_CONVERT_TYPE] = "Convert %s type to %s type failed",
    [ERR_UNSUPPORT_DATATYPE] = "Data type '%s' is not supported",
    [ERR_UNKNOWN_PLAN_TYPE] = "Unknown plan type %d when %s",
    [ERR_COLUMN_DATA_TYPE] = "Data type %s mismatched with column '%s'",
    [ERR_CAST_TO_COLUMN] = "%s cast to column '%s' failed",
    [ERR_UNSUPPORT_OPER_TYPE] = "Unsupported %s type=%d",
    [ERR_DISTRI_COLUMN_DATA_TYPE] = "Datatype %s is not allowed for distribute column %s",
    [ERR_COMMENT_OBJECT_TYPE] = "Comment object %s.%s is not table or view type",
    [ERR_MUST_BE_FIX_DATATYPE] = "%s must be %s",
    [ERR_KEY_EXPECTED] = "%s expected",
    [ERR_INVALID_ATTR_NAME] = "Invalid attribute name %s",
    [ERR_COMPARE_TYPE] = "Compare type is error",
    [ERR_UNEXPECTED_KEY] = "Unexpected %s",
    [ERR_UNEXPECTED_ARRG] = "Unexpected aggregation '%s'",
    [ERR_UNKNOWN_DATATYPE] = "Unknown datatype %d",
    [ERR_NUM_OVERFLOW] = "High-Precision numeric overflow",
    [ERR_UNDEFINED_OPER] = "Undefined operator: %s %s %s",
    [ERR_UNKNOWN_ARRG_OPER] = "Unknown aggr operation",
    [ERR_CALC_EXPRESSION] = "Calculate %s failed.",
    [ERR_UNSUPPORT_FUNC] = "%s not supported %s",
    [ERR_INVOKE_FUNC_FAIL] = "%s failed",
    [ERR_TOO_MANY_ARRG] = "Too many aggregation",
    [ERR_INVALID_FUNC] = "The function ID %d was invalid.",
    [ERR_PARAM_VALUE_OUT_RANGE] = "Argument value is out of range",
    [ERR_INVALID_PACKAGE] = "The package ID %d was invalid.",
    [ERR_FORBID_CREATE_SYS_USER] = "Cannot create a user with the name same as sys user",
    [ERR_NO_OPTION_SPECIFIED] = "The SQL syntax %s was incorrect with no operation specified.",
    [ERR_XA_TRANS_EXEC] = "Only accept commit prepared or rollback prepared",
    [ERR_READ_LOB_NULL] = "Has no more lob data to read",
    [ERR_DATANODE_EXIST] = "Node 'node_name = %s' already exists",
    [ERR_DATANODE_NOT_EXIST] = "Node 'node_name = %s' does not exist",
#ifdef Z_SHARDING
    [ERR_REBALANCE_TASK_NOT_EXIST] = "Rebalnace task 'id = %s, table name = %s' not exist",
    [ERR_OLNY_FOR_COORDNODE] = "Only the CN supports the logical capacity expansion command.",
    [ERR_TABLE_FROZEN_STATUS] = "Table is working in frozen status.",
#endif
    [ERR_COORDNODE_FORBIDDEN] = "Coordinator node don't allow %s",
    [ERR_DISTRI_COLUMN_FORBIDDEN] = "Cannot %s distribute column \"%s\" %s",
    [ERR_INVALID_SEL4UPDATE] = "Select .. for update syntax error: %s",
    [ERR_NO_SORT_ITEM_REMOTE] = "No sort items in remote scan plan",
    [ERR_AUTOINC_READ_FAILED] = "Failed to read auto-increment value from storage engine",
    [ERR_MAX_KEYLEN_EXCEEDED] = "The total size of index columns within an index exceeded the maximum (%d)",
    [ERR_INVALID_CONN] = "Minconn(%u) should less than maxconn(%u)",
    [ERR_ZERO_DIVIDE] = "The divisor was zero",
    [ERR_LOGIN_DENIED] = "Login using %s is not allowed",
    [ERR_INVALID_ROWID] = "The row ID was invalid",
    [ERR_PRIMRY_KEY_ALREADY_EXISTS] = "The table had more than one primary key",
    [ERR_INVALID_SCAN_MODE] = "Invalid scan mode %d",
    [ERR_NO_MATCH_CONSTRAINT] =
        "The column referenced by a foreign key was not the unique or primary key of the referenced table",
    [ERR_INDEX_ENFORCEMENT] = "The index cannot be deleted because it is referenced by a primary key or unique index",
    [ERR_MUTI_DEFAULT_VALUE] = "Multiple default values specified for column \"%s\"",
    [ERR_EXCEED_MAX_ROW_SIZE] = "The size of one row is %u, must be less than %u",
    [ERR_INVALID_PAGE_TYPE] = "Unsupported page type",
    [ERR_INVALID_PAGE_ID] = "Invalid page id%s",
    [ERR_INVALID_SEGMENT_ENTRY] = "Can not get valid segment entry, because concurrent deletion may exist",
    [ERR_DC_CORRUPTED] = "Segment is corrupted or tablespace is offline",
    [ERR_PASSWORD_IS_TOO_SIMPLE] = "Password is too simple, password should contain at least "
                                   "three of the following character types:\n"
                                   "A. at least one lowercase letter\n"
                                   "B. at least one uppercase letter\n"
                                   "C. at least one digit\n"
                                   "D. at least one special character: `~!@#$%%^&*()-_=+\\|[{}]:\'\",<.>/? and space",
    [ERR_TYPE_OVERFLOW] = "%s out of range",
    [ERR_CONNECT_BY_LOOP] = "There was an infinite loop in CONNECT BY execution",
    [ERR_PASSWORD_FORMAT_ERROR] = "The password was invalid: %s",
    [ERR_INVALID_PURGE_OPER] = "The purge operation was invalid: %s",
    [ERR_INVALID_NUMBER] = "Invalid number %s",
    [ERR_TYPE_DATETIME_OVERFLOW] =
        "DATETIME out of range, it must be between %04d-01-01 00:00:00 and %04d-12-31 23:59:59",
    [ERR_TYPE_TIMESTAMP_OVERFLOW] =
        "TIMESTAMP out of range, it must be between %04d-01-01 00:00:00.000000 and %04d-12-31 23:59:59.999999",
    [ERR_TOO_LESS_ARGS] = "Too few arguments for %s",
    [ERR_NOT_SUPPORT_TYPE] = "Not supported type: %d",
    [ERR_VALUE_ERROR] = "Value error: %s",
    [ERR_SIZE_ERROR] = "The size(%u) of value can't larger than defined size(%u) of %s",
    [ERR_ARGUMENT_NOT_FOUND] = "Argument %s is not found in procedure/function",
    [ERR_INVALID_DATAFILE_NUMBER] = "Invalid datafile number %d (min=%d, max=%d)",
    [ERR_STORED_PROCEDURE] = "%s is stored procedure %s",
    [ERR_FEW_FILLED] = "%lu node_id expected to be filled but only %u filled",
    [ERR_COLUM_LIST_EXCEED] = "Winsort funcs in column list can't exceed %u",
    [ERR_INVALID_PROTOCOL_INVOKE] = "Invalid protocal invoke, %s",
    [ERR_INVALID_STATEMENT_ID] = "Statement id is invalid: %u",
    [ERR_DML_INSIDE_QUERY] = "DML statements were not allowed in query statements.",
    [ERR_FUNCTION_NOT_INDEXABLE] = "Function %s is not indexable",
    [ERR_EXCEED_MAX_FIELD_LEN] = "The column \"%s\" length exceeded the maximum, (actual: %u, maximum: %u).",
    [ERR_RESERV_SQL_CURSORS_DECREASE] = "The number of reserved sql cursors can not decrease",
    [ERR_SELECT_ROWID] = "Querying views containing DISTINCT, GROUP BY, or ROWNUM for ROWID was not allowed.",
#ifdef Z_SHARDING
    [ERR_SELECT_ROWNODEID] = "Querying views containing DISTINCT, GROUP BY, or ROWNUM for ROWNODEID was not allowed.",
#endif
    [ERR_INVALID_NUMBER_FORAMT] = "The input was not of the NUMBER type.",
    [ERR_INVALID_SESSION_TYPE] = "Can only kill user or job sessions",
    [ERR_SQL_MAP_ONLY_SUPPORT_DML] = "SQL mapping only supports DML and DQL statements",
    [ERR_SQL_MAP_NOT_EXIST] = "SQL mapping does not exist",
    [ERR_TF_ONLY_ONE_TABLE] = "Dynamic Table function multi-table associations are not supported",
    [ERR_TF_TABLE_NAME_NULL] = "Table function table name is null",
    [ERR_EXCEED_MAX_STMTS] = "The number of statements exceeds the maximum: %u",
    [ERR_DEFAULT_LEN_TOO_LARGE] = "The default size (%d) is too large for column \"%s\" (%d)",
    [ERR_TF_TABLE_DIST_DDL_ID_NULL] = "Table function distributed ddl id is null",
    [ERR_TF_QUERY_DDL_INFO_FAILED] = "Table function query distributed ddl failed",
    [ERR_FOR_UPDATE_NOT_ALLOWED] = "FOR UPDATE is not allowed in this query expression",
    [ERR_EXPECT_COLUMN_HERE] = "Expect user.table.column, table.column, or column specification here",
    [ERR_FOR_UPDATE_FROM_VIEW] = "Cannot select FOR UPDATE from view or sub-select with AGGREGATION, UNION, ROWNUM etc",
    [ERR_CALC_COLUMN_NOT_ALLOWED] = "Computable column is not allowed here",
    [ERR_INVALID_ARRAY_FORMAT] = "Invalid array format",
    [ERR_WRONG_ELEMENT_COUNT] = "Source array elements count does not match",
    [ERR_INDEX_ON_ARRAY_FIELD] = "Can not create index on column '%s' with array type",
    [ERR_DATATYPE_NOT_SUPPORT_ARRAY] = "Datatype %s does not support array type",
    [ERR_INVALID_ARG_TYPE] = "Invalid function argument type",
    [ERR_CONVERT_CODE_FAILED] = "%s, errno %d",
    [ERR_REF_ON_ARRAY_COLUMN] = "Can not create reference for array column",
    [ERR_SET_DEF_ARRAY_VAL] = "Can not set default value for array column",
    [ERR_INVALID_SUBSCRIPT] = "Invalid array subscript",
    [ERR_USE_WRONG_SUBSCRIPT] = "Can not subscript column %s because it is not an array",
    [ERR_ARRAY_NOT_SUPPORT] = "Current client version does not support array feature",
    [ERR_MODIFY_ARRAY_COLUMN] = "Can not modify column(%s) to %sarray type",
    [ERR_MODIFY_ARRAY_DATATYPE] = "Can not modify column(%s)'s datatype",
    [ERR_WRONG_TABLE_TYPE] = "Can not create array column in non-heap table",
    [ERR_TF_DDL_ID_NULL] = "Table function ddl id is null",
    [ERR_TF_DDL_INFO_NULL] = "Table function ddl info is null",
    [ERR_TF_DDL_ID_OVER_LEN] = "Table function ddl id over the length limit",
    [ERR_TF_DDL_INFO_OVER_LEN] = "Table function ddl info over the length limit",
    [ERR_ARRAY_TO_STR_FAILED] = "Convert array to string failed, invalid statement or virtual memory pool",

    [ERR_PARALLEL_EXECUTE_FAILED] = "Parallel execute error, %s",
    [ERR_SPACE_DISABLED] = "Tablespace %s is disabled in current tenant",
    [ERR_SPACE_INVALID] = "Can not specify %s tablespace as current tenant usable tablespace",
    [ERR_SPACE_ALREADY_USABLE] = "Tablespace %s is already usable in current tenant",
    [ERR_TENANT_NOT_EXIST] = "The tenant %s does not exist.",
    [ERR_TENANT_IS_REFERENCED] = "The tenant %s is being used, %s.",

    [ERR_ALCK_MAP_THRESHOLD] = "Advisory lock map number limit %u reached",
    [ERR_CURSOR_SHARING] = "Cursor sharing execute error, %s",

    [ERR_DBLINK_NOT_EXIST] = "The dblink %s does not exist",

    /* resource manager error */
    [ERR_EXCEED_CGROUP_SESSIONS] = "Total sessions of control group '%s' exceeds the maximum %u",
    [ERR_EXCEED_MAX_WAIT_TIME] = "Session of control group '%s' exceeded maximum wait time %u seconds",
    [ERR_CGROUP_IS_REFERENCED] = "Control group '%s' is inused and cannot be deleted or modified",
    [ERR_CANNOT_MODIFY_CGROUP] = "Control group DEFAULT_GROUPS is mandatory and cannot be deleted or modified",
    [ERR_RSRC_PLAN_INVALIDATED] = "Resource plan dictionary cache is invalidated",
    [ERR_LICENSE_CHECK_FAIL] = "License check failed,%s",

    /* VPD policy */
    [ERR_POLICY_FUNC_CLAUSE] = "Error occurs in the policy predicate",
    [ERR_POLICY_EXEC_FUNC] = "Unable to execute policy function, reason: %s",

    [ERR_FILE_EXEC_PRIV] = "The owner of file %s is not the database user and execution is forbidden",

    /* privilege error */
    [ERR_NO_LOGIN_PRIV] = "Sys user only can login with local host",
    [ERR_INSUFFICIENT_PRIV] = "Permissions were insufficient",
    [ERR_PRIVS_NOT_GRANT] = "Privileges %s has not granted to %s",
    [ERR_ROLE_CIRCLE_GRANT] = "Grant role in a circle",
    [ERR_INVALID_REVOKEE] = "Can not revoke privilege from %s",
    [ERR_PRI_GRANT_SELF] = "Users cannot grant permissions to or revoke permissions from themselves",
    [ERR_LACK_CREATE_SESSION] = "The user lacks create session privilege",
    [ERR_ROLE_NOT_GRANT] = "Role %s has not granted to %s",
    [ERR_GRANTEE_EXCEED_MAX] = "The number of %s exceeds the maximum %u",
    [ERR_GRANT_OBJ_EXCEED_MAX] = "The number of granted objects exceeds the maximum %u",
    [ERR_REVOKE_FROM_OBJ_HOLDERS] = "Object permissions cannot be revoked from object holders",
    [ERR_NO_INHERIT_PRIV] = "Insufficient inherit privileges",
    [ERR_RECOMPILE_SYS_OBJECTS] = "Cannot recompile SYS objects, only itself",
    [ERR_NO_SPACE_PRIV] = "The user lacks privilege to use %s tablespace",

    /* partition error */
    [ERR_INVALID_PART_NAME] = "The (sub)partition name violated the naming conventions.",
    [ERR_PARTCNT_NOT_MATCH] = "The number of index (sub)partitions was different from that of table partitions.",
    [ERR_INVALID_PART_TYPE] = "Invalid (sub)partition %s type %s",
    [ERR_INVALID_PART_KEY] = "Invalid (sub)partition key, %s",
    [ERR_LOB_PART_COLUMN] = "The LOB column can not be used as the (sub)partition key.",
    [ERR_MODIFY_PART_COLUMN] = "The column used as the (sub)partition key can not be modified.",
    [ERR_DROP_PART_COLUMN] = "Can not drop (sub)partitioning column",
    [ERR_DUPLICATE_PART_NAME] = "There were duplicate partition or subpartition names.",
    [ERR_EXCEED_MAX_PARTCNT] = "The number of (sub)partitions exceeds the maximum %lu",
    [ERR_DROP_ONLY_PART] =
        "Cannot drop the only partition of a partitioned table, or the only subpartition of a parent partition",
    [ERR_OPERATIONS_NOT_ALLOW] = "The operation %s was not allowed",
    [ERR_PART_INDEX_COALESCE] = "The local index of the partitioned table was treated as a common index",
    [ERR_MODIFY_PART_INDEX] = "The common index was treated as a (sub)partitioned index",
    [ERR_DUPLICATE_PART_KEY] = "The %u%s partition key already exists in (sub)partition %s",
    [ERR_PART_RANGE_NOT_SAME] = "The table partition %s range does not same on all dns",
    [ERR_PART_HAS_NO_DATA] = "The table partition %s  has no data in current dn",
    [ERR_DUPLICATE_SUBPART_NAME] = "There were duplicate subpartition names.",
    [ERR_INVALID_DEST_PART] =
        "Some rows cannot be inserted into the new partition because of a boundary value mismatch",
    [ERR_EXCEED_MAX_SUBPARTCNT] = "The number of subpartitions of one parent partition exceeds the maximum %u",
    [ERR_INDEX_PART_UNUSABLE] = "Partition %s of index %s is unusable, need to rebuild index first.",
    [ERR_INVALID_REBUILD_PART_RANGE] = "(SUB)PARTITION count out of range, it must be less than %u.",
    [ERR_PAGE_SOFT_DAMAGED] = "Data page %u-%u was loaded using the NOLOGGING option.",
    [ERR_ROW_IS_REFERENCED] = "The row is referenced by child record",

    /* sql engine */
    [ERR_INVALID_SYNONYM_OBJ_TYPE] = "Synonym object %s.%s is not table or view type",
    [ERR_CONNECT_BY_LEVEL_MAX] = "CONNECT BY level can not exceed %u",
    [ERR_VALUE_CAST_FAILED] = "Value size(%u) from cast operand is larger than cast target size(%u)",
    [ERR_ILEGAL_LOB_READ] = "Lob value too large in expression (actual: %u, maximum: %u)",
    [ERR_ILEGAL_LOB_TYPE] = "Unknown lob type: %s",
    [ERR_ILEGAL_LOB_WRITE] = "",
    [ERR_PGS_TOO_MANY_BINDS] = "",
    [ERR_INVALID_INTERVAL_TEXT] = "Invalid interval text %s",
    [ERR_INVALID_INTERVAL_FIELD] = "%s field exceeds the specified precision (%u)",
    [ERR_INTERVAL_FIELD_OVERFLOW] = "Invalid interval text -- %s field out of range (<=%u)",
    [ERR_INVALID_RESOURCE_LIMIT] = "Values in resource limit settings were invalid",
    [ERR_SHUTDOWN_IN_PROGRESS] = "Shutdown current session (sid %d) is prohibited",
    [ERR_ANCESTOR_LEVEL_MISMATCH] = "Column ancestor level mismatch",
    [ERR_INVALID_OR_LACK_ESCAPE_CHAR] = "Invalid or lack character after escape",
    [ERR_INDEX_NOT_SUITABLE] = "The index cannot be used as a constraint",
    [ERR_MAX_PART_CLOUMN_SIZE] = "Specified length of column %s too long(> %u) for its datatype in (sub)partition key",
    [ERR_REGEXP_COMPILE] = "Regular expression compiling error, errloc=%d, errmsg=[%s]",
    [ERR_REGEXP_EXEC] = "",
    [ERR_INVALID_SESSION_ID] = "The session ID was missing or invalid",
    [ERR_CANT_KILL_CURR_SESS] = "The current session cannot be killed",
    [ERR_REFERENCED_NO_PRIMARY_KEY] = "The referenced table had no primary key",
    [ERR_MAX_ROLE_COUNT] = "Maximum number of %s (%u) exceeded",
    [ERR_TOO_MANY_VALUES] = "Values were too many",

    /* knl_backup */
    [ERR_INVALID_FINISH_SCN] = "Finish scn can not little than prepare scn %llu",
    [ERR_INVALID_BACKUPSET] = "Invalid backupset, %s",
    [ERR_BACKUP_TAG_EXISTS] = "Backup tag :%s already exists",
    [ERR_BACKUP_RECORD_FAILED] = "Failed to save backupset info",
    [ERR_BACKUP_NOT_PREPARE] = "Backupset of tag :%s not prepare",
    [ERR_NO_VALID_BASE_BACKUPSET] = "No valid base backupset, can not execute incremental backup",
    [ERR_BACKUP_RESTORE] = "%s failed, %s",
    [ERR_LOG_ARCH_DEST_IN_USE] = "ARCHIVE_DEST is in use, please disable it firstly",
    [ERR_EXCEED_MAX_BACKUP_PATH_LEN] = "%s exceed max backup path len :%u",
    [ERR_EXCEED_MAX_INCR_BACKUP] = "Exceed max incremental backup number",
    [ERR_ALTER_DB_TIMEZONE_FAILED] =
        "Cannot alter database timezone when database has TIMESTAMP WITH LOCAL TIME ZONE columns",
    [ERR_NO_AUTO_INCREMENT_COLUMN] = "The table has no auto increment column",
    [ERR_ROW_LOCKED_NOWAIT] =
        "The resource requested in NOWAIT mode was being occupied or not released after the request timed out",
    [ERR_UNKNOWN_FORUPDATE_MODE] = "Unknown mode of select for update",
    [ERR_SEND_RECORD_REQ_FAILED] = "Send backup record to primary failed",
    [ERR_RECORD_BACKUP_FAILED] = "Wait primary record backup set failed",
    [ERR_EXCLUDE_SPACES] = "Can not exclude space %s",

#ifdef Z_SHARDING
    // XA error
    [ERR_XA_EXECUTE_FAILED] = "Error for modifying XA transaction state",
    [ERR_XA_WITHOUT_TIMESTAMP] = "Xa need timestamp to synchronize datanode logic clock",

    // node info error
    [ERR_DATANODE_COUNT_ERROR] = "Node count error",
    [ERR_INVALID_NODE_ID] = "Invalid node id %s",
    [ERR_DATANODE_CONFIGE_FAILED] = "This node(LSNR_ADDR=%s,LSNR_PORT=%d) is not configured in SYS_DATA_NODES",
    [ERR_REBALANC_CTX_NOT_INIT] = "The rebalance context is not initialized.",
    [ERR_NODE_DUP_IP_PORT] = "Node with the same host and port exists.",

    // connect error
    [ERR_NO_CONN] = "Wrong connect: %s",
    [ERR_CONN_REACH_LIMIT] =
        "Wrong connect cause %s reaches upper limit: current num is %u, max num is %u, node id is %u",
    [ERR_CONN_TIMESTAMP_FAILED] = "Failed to get timestamp from gts (node id=%u), error number = %05d",
    [ERR_REMOTE_ERROR] = "Node id = %u, error number = CT-%05d, error message = '%s'",
    [ERR_SLOT_RELEASE] = "Some slot not released",
    [ERR_GTS_GETTIME_FAILED] = "Failed to get timestamp, %s",
    [ERR_GTS_INVALID_TIMESTAMP] =
        "The timestamp from CN is invalid, because it's less than the init time of the database",
    [ERR_GTS_NODE_NOT_EXIST] = "The GTS node does not exist",
    [ERR_BAD_CONN_PIPE] = "Connection status unexpected, node id = %u, error number = CT-%05d, error message = '%s'",
    [ERR_BAD_GROUP_INFO] = "The replication group(%u) does not define the master node",

    // other error
    [ERR_NODE_FORBIDDEN_USERNAME] = "Username can't be %s",
    [ERR_START_NOT_FINISHED] = "The instance is starting, and this operation is not allowed",
    [ERR_SHARD_REFUSESQL] = "SQL has been refused for crossing data node.",

    // re-balance error
    [ERR_TABLE_NOT_CONS_HASH_OR_REP] = "Table %s is not a consistent hash nor a replicate table",
    [ERR_NO_REBALANCE_TABLE_FOUND] = "No tables were found that need to be rebalanced",
    [ERR_CALC_REBALANCE_TASK] = "Failed to calculate rebalance task for table %s",
    [ERR_ONLY_ROLLBACK_ACCEPTABLE] = "Only rollback operation acceptable",
    [ERR_NO_REBALANCE_TASK_FOUND] = "No tasks were found by rebalance id %s",
    [ERR_TABLE_NOT_HEAP] = "Table %s is not a heap table.",

    // other error
    [ERR_GET_LOGIN_UID] = "Get login uid error.",

    [ERR_SHARD_SAVEPOINT_OPERATION] = "%s, so this transaction can only be rollbacked, error message:%s.",
    [ERR_STMT_ID_NOT_EXISTS] = "dml statement id is not exist.",
    [ERR_DML_FAIL_RB_FAIL] = "%s, this dml rollback failed, so this transaction can only be rollbacked.",

#endif

    [ERR_CONSTRAINT_VIOLATED_CHECK_FAILED] = "Check constraint violated",
    [ERR_CONSTRAINT_VIOLATED_NO_FOUND] = "Integrity constraint violated - %s",
    [ERR_DROP_LOGICAL_LOG] = "Failed to drop logical log",
    [ERR_REFERENCED_BY_LOGICAL_LOG] = "Index or constraint is referenced by logic log",
    [ERR_INVALID_LOGICAL_INDEX] = "Cannot find logical index",
    [ERR_DB_ROLE_MISMATCH] = "Database role mismatch%s, node id = %u",
    [ERR_FLASHBACK_NO_SUPPORT] = "Flashback table (sub)partition to timestamp(scn or before drop) not supported",
    [ERR_INVALID_SEQUENCE_CACHE] = "Cannot get sequence from invalid cache",

    /* database */
    [ERR_KEYS_RECYCLED] = "The btree keys recycled, snapshot was outdated.",
    [ERR_CONTROL_FILE_NOT_COMPLETED] = "The control file was damaged.",
    [ERR_LOAD_CONTROL_FILE] = "Failed to load ctrl file, %s",
    [ERR_BUILD_CANCELLED] = "Build has been cancelled",
    [ERR_INVALID_CHARSET] = "Invalid charset: %s",
    [ERR_INVALID_DATABASE_DEF] = "Invalid database def because %s",
    [ERR_TOO_MANY_OBJECTS] = "The number %u reached the upper limit of %s.",
    [ERR_INVALID_DC] = "Invalid dictionary of table %s",
    [ERR_OBJECT_NOT_EXISTS] = "The object %s %s does not exist",
    [ERR_COLUMN_HAS_NULL] = "Found null value, cannot set not null constraint",
    [ERR_DC_BUFFER_FULL] = "Dictionary buffer is full",
    [ERR_INVALID_RCV_END_POINT] = "Log replay stopped at %u:%u, it did not reach the least recovery point (LRP) %u:%u.",
    [ERR_INVALID_BATCH] = "Invalid batch %s",
    [ERR_NO_FREE_UNDO_PAGE] = "No free undo page",
    [ERR_LOG_FILE_SIZE_TOO_SMALL] = "Log file size should be larger than log keep size %lld",
    [ERR_SNAPSHOT_TOO_OLD] = "The snapshot was outdated.",
    [ERR_DEAD_LOCK] = "Found %s deadlock in session (%u)",
    [ERR_LOCK_TIMEOUT] = "Locking timed out while the operation was waiting.",
    [ERR_OPERATION_CANCELED] = "Current operation was canceled by the user",
    [ERR_OPERATION_KILLED] = "Session killed",
    [ERR_TOO_MANY_PENDING_TRANS] = "Too many pending transaction",
    [ERR_THREAD_EXIT] = "%s thread already exited",
    [ERR_DC_INVALIDATED] = "Dictionary cache is invalidated, caused by DDL operation or statistics refresh",
    [ERR_RESOURCE_BUSY] =
        "The resource to be locked was occupied, and the wait for the resource timed out or the NOWAIT mode was used.",
    [ERR_TOO_MANY_INDEXES] = "Too many indexes on table %s.%s",
    [ERR_COLUMN_ALREADY_INDEXED] = "The column has been indexed by %s.",
    [ERR_RECORD_SIZE_OVERFLOW] = "%s size %u exceeds the limitation %u",
    [ERR_FIND_FREE_SPACE] = "Failed to find free space size : %u",
    [ERR_DUPLICATE_KEY] = "Unique constraint violated%s",
    [ERR_DUPLICATE_ENTRY] = "Duplicate entry for key %s.%s",
    [ERR_NO_DB_ACTIVE] = "Database has not been created or is not open",
    [ERR_MAX_DATAFILE_PAGES] = "File hwm pages %u exceeds maximum of %u pages in space %s",
    [ERR_TXN_IN_PROGRESS] = "Error occurred when the transaction is in progress, %s",
    [ERR_INVALID_ISOLATION_LEVEL] = "Invalid transaction isolation level %u",
    [ERR_SERIALIZE_ACCESS] = "Failed to set the transaction isolation level to Serializable.",
    [ERR_SAVEPOINT_NOT_EXIST] = "The savepoint '%s' does not exist.",
    [ERR_TOO_MANY_SAVEPOINTS] = "Session holds too many savepoints",
    [ERR_DATABASE_ALREADY_MOUNT] = "The database is already in the MOUNT state",
    [ERR_DATABASE_ALREADY_OPEN] = "The database cannot be opened repeatedly.",
    [ERR_NO_MORE_LOCKS] = "No more free locks",
    [ERR_TOO_MANY_PENDING_RESULTSET] = "Too many pending result set",
    [ERR_TABLESPACES_IS_NOT_EMPTY] = "Tablespace %s is not empty, %s",
    [ERR_DATAFILE_NUMBER_NOT_EXIST] = "Datafile number %u not exists",
    [ERR_DATAFILE_HAS_BEEN_USED] = "Datafile %s has already been used, can not remove it in space %s",
    [ERR_DATAFILE_ALREADY_EXIST] = "The data file %s already exists.",
    [ERR_NAME_TOO_LONG] = "%s name length is exceeded. name len = %d, max_len = %d",
    [ERR_DROP_SPACE_NOT_IN_MOUNT] = "Drop tablespace %s failed, database must be in mount mode",
    [ERR_FORBID_ALTER_DATABASE] = "Alter database is forbidden during backup or build",
    [ERR_BACKUP_IN_PROGRESS] = "%s already running, can not start another process",
    [ERR_RESTORE_IN_PROGRESS] = "Database is in recovery, please use 'shutdown abort' or try later",
    [ERR_OBJECT_EXISTS] = "The object %s %s already exists.",
    [ERR_OBJECT_ID_EXISTS] = "%s %u already exists",
    [ERR_TOO_MANY_COLUMNS] = "%s exceeded max number",
    [ERR_COLUMN_IN_CONSTRAINT] = "The column was referenced as a constraint.",
    [ERR_OFFLINE_DATAFILE_NOT_EXIST] = "Offline datafile %s failed, this file not exists in space %s",
    [ERR_SPACE_OFFLINE] = "The tablespace %s is offline, %s",
    [ERR_INDEX_INVALID] = "Participant of merge sort cannot be found due to invalid index: %d",
    [ERR_DATAFILE_BREAKDOWN] = "Datafile %s break down, %s",
    [ERR_OFFLINE_WRONG_SPACE] = "Could not offline datafile in space %s",
    [ERR_DROP_OFFLINE_SPACE_IN_OPEN] = "Drop offline tablespace %s must be in open mode",
    [ERR_SPACE_NAME_INVALID] = "The tablespace name already exists.",
    [ERR_DATABASE_NOT_OPEN] = "%s must in OPEN status",
    [ERR_DATABASE_NOT_COMPLETED] = "Database is not created completely",
    [ERR_DATAFILE_SIZE_NOT_ALLOWED] = "%s property for %s exceeds or smaller than size that system allowed",
    [ERR_DATABASE_NOT_MOUNT] = "Operation %s can only be executed in mount status",
    [ERR_SPACE_HAS_REPLACED] = "Tablespace %s has a larger scn, origin tablespace replaced by tablespace %s",
    [ERR_SHUTDOWN_IN_TRANS] = "Not all transactions were committed when the database was shut down.",
    [ERR_FILE_NOT_EXIST] = "%s file %s does not exist",
    [ERR_RAFT_ENABLED] = "Switchover cannot be issued when raft is enabled",
    [ERR_DATABASE_ROLE] = "%s can not be done when database is %s",
    [ERR_FAILOVER_IN_PROGRESS] = "Failover in progress, can not be connected",
    [ERR_INVALID_SWITCH_REQUEST] = "Invalid switch request, %s",
    [ERR_NO_MORE_LOB_ITEMS] = "No more free lob items",
    [ERR_DB_TOO_MANY_PRIMARY] = "Too many primary, %s",
    [ERR_DATABASE_NOT_ARCHIVE] = "Database not in archive mode, %s",
    [ERR_BUILD_INDEX_PARALLEL] = "Index build failed: %s",
    [ERR_NO_SYNC_STANDBY] = "MAXIMIZE PROTECTION mode need at least 1 sync standby",
    [ERR_LRCV_NOT_READY] = "Log receiver thread not ready",
    [ERR_ALLOC_EXTENT] = "Could not find datafile to extend extent in tablespace %s",
    [ERR_IN_SHUTDOWN_CANCELED] = "Shutdown was canceled",
    [ERR_SPACE_ALREADY_EXIST] = "Tablespace %s already exists",
    [ERR_CONS_EXISTS] = "The foreign key constraint already exists.",
    [ERR_DROP_SPACE_CHECK_FAILED] = "Failed to drop tablespace %s, because %s",
    [ERR_CASCADED_STANDBY_CONNECTED] = "Local is cascaded standby, and another database has connected",
    [ERR_DEFAULT_SPACE_TYPE_INVALID] = "Can not specify %s tablespace as user default tablespace.",
    [ERR_TEMP_SPACE_TYPE_INVALID] =
        "The tablespace specified for the user to be created was not a temporary tablespace.",
    [ERR_NO_ARCHIVE_LOG] = "Log file [%u_%u] is not archived",
    [ERR_THREAD_IS_CLOSED] = "%s thread is closed",
    [ERR_OBJECT_ID_NOT_EXIST] = "%s id %d does not exists",
    [ERR_SEQ_INVALID] = "Invalid sequence because %s",
    [ERR_COLUMN_NOT_EMPTY] = "Column %s is not empty in table %s",
    [ERR_TOO_OLD_SCN] = "Scn too old and %s",
    [ERR_USER_HAS_LOGIN] = "The user %s has logged in, can not be dropped now",
    [ERR_PARTITION_NOT_READY] = "The %s partition %s is not ready, invalid operation.",
    [ERR_XATXN_IN_PROGRESS] = "Transaction error because %s",
    [ERR_DB_START_IN_PROGRESS] = "Can not start database concurrently",
    [ERR_LOG_FILE_NOT_ENOUGH] = "Database requires at least 3 log files.",
    [ERR_LOG_BLOCK_NOT_MATCH] = "RAFT: block size of logfiles should be the same",
    [ERR_ROW_SELF_UPDATED] = "Row has been updated by current statement",
    [ERR_USER_IS_REFERENCED] = "%s %s is %s, can not drop",
    [ERR_LOCAL_UNIQUE_INDEX] = "Table partition key should be subsets of local primary or unique index",
    [ERR_COL_TYPE_MISMATCH] =
        "In the FOREIGN KEY constraint, the column type does not match the type of the referenced column.",
    [ERR_PROFILE_HAS_USED] = "Profile has been assigned to user, can not been dropped without cascade option",
    [ERR_RAFT_INIT_FAILED] = "RAFT: failed to %s",
    [ERR_BTREE_LEVEL_EXCEEDED] = "Btree level has exceeded limit %d",
    [ERR_RECOVER_TIME_INVALID] = "Can not recover to history time",
    [ERR_INVALID_OLD_PASSWORD] =
        "When the password of an existing database user was changed, the original password was incorrectly entered.",
    [ERR_INDEX_NOT_STABLE] = "Index %s is unusable, need to rebuild index first.",
    [ERR_SYSDBA_LOGIN_FAILED] = "Login as sysdba is prohibited",
    [ERR_INVALID_BACKUP_PACKET] = "Invalid backup packet, len:%d",
    [ERR_NOT_EXPECTED_BACKUP_PACKET] = "Expected packet %d, but receive %d",
    [ERR_DATABASE_NOT_AVAILABLE] = "Invalid operation when database isn't available",
    [ERR_USER_OBJECT_NOT_EXISTS] = "%s %s.%s does not exist",
    [ERR_GET_SPIN_LOCK_AREA] = "Can't get spin lock stat area",
    [ERR_CLEAN_ARC_FILE] = "Failed to clean archived files in ARCHIVE_DEST_%d",
    [ERR_LOG_FILE_NOT_EXIST] = "The log file does not exist.",
    [ERR_PARAMETER_NOT_MATCH] = "Parameter %s value %u does not match with database value %u",
    [ERR_LOG_FILE_NAME_MISS] = "No file name was entered.",
    [ERR_DUPLICATE_LOG_ARCHIVE_DEST] = "ARCHIVE_DEST_%d destination is the same as ARCHIVE_DEST_%d destination",
    [ERR_FLUSH_REDO_FILE_FAILED] = "Flush redo file:%s, offset:%u, size:%lu failed",
    [ERR_DIR_NOT_EXISTS] = "The directory %s does not exist.",
    [ERR_LOG_IN_USE] = "Log file is in use, can not be dropped",
    [ERR_LOGFILE_OPERATION_CANCELED] = "Logfile operation canceled, try again later",
    [ERR_SPACE_OPEARTION_CANCELED] = "Space operation canceled, try again later",
    [ERR_READMODE_OPEARTION_CANCELED] = "Read mode operation canceled, try again later",
    [ERR_INVALID_ARCHIVE_PARAMETER] = "Invalid parameter(%s)",
    [ERR_INDEX_NOT_EXIST] = "Index %s.%s does not exist",
    [ERR_RECYCLE_OBJ_NOT_EXIST] = "Recyclebin object %s.%s does not exist",
    [ERR_SEQ_NOT_EXIST] = "The sequence %s.%s does not exist.",
    [ERR_TABLE_OR_VIEW_NOT_EXIST] = "The table or view %s.%s does not exist.",
    [ERR_USER_NOT_EXIST] = "The user %s does not exist.",
    [ERR_ROLE_NOT_EXIST] = "The role %s does not exist.",
    [ERR_PROFILE_NOT_EXIST] = "Profile %s does not exist",
    [ERR_COLUMN_NOT_EXIST] = "The column %s.%s does not exist.",
    [ERR_FUNCTION_NOT_EXIST] = "Function %s does not exist",
    [ERR_TABLE_ID_NOT_EXIST] = "Table or view id %u.%u does not exist",
    [ERR_NEED_RESTART] = "SQL need restart",
    [ERR_PROFILE_ID_NOT_EXIST] = "Profile id %u does not exist",
    [ERR_OBJECT_ALREADY_DROPPED] = "%s has been dropped or truncate",
    [ERR_RECYCLEBIN_MISMATCH] = "Recyclebin object does not match, %s",
    [ERR_PARTITION_NOT_EXIST] = "A %s (sub)partition %s does not exist.",
    [ERR_PARTNO_NOT_EXIST] = "Partition no %d does not exist.",
    [ERR_SYNONYM_NOT_EXIST] = "Synonym %s.%s does not exist",
    [ERR_DEF_CHANGED] = "The table definition of %s.%s has been changed.",
    [ERR_CONS_NOT_EXIST] = "The constraint %s does not exist.",
    [ERR_DROP_CONS] = "This unique/primary key is referenced by %s",
    [ERR_SPACE_NOT_EXIST] = "The tablespace %s does not exist.",
    [ERR_DISTRIBUTE_RULE_NOT_EXIST] = "Distribute rule %s does not exist",
    [ERR_XA_EXTEND_BUFFER_EXCEEDED] = "Session holds too many table locks or lob columns",
    [ERR_XATXN_CHANGED_TEMP_TABLE] = "Xa transaction can't change temp table",
    [ERR_ALLOC_TEMP_EXTENT] = "Could not alloc temp extent",
    [ERR_RECYCLE_PARTITION_NOT_EXIST] = "Recyclebin object %s.%s (sub)partition %s does not exist",
    [ERR_PERMANENTOBJ_IN_TEMPSPACE] = "Attempt to create permanent object in a temporary tablespace",
    [ERR_CANNOT_CLOSE_ARCHIVE] = "High availability configured, database must run in archive mode",
    [ERR_OPEN_RESETLOGS] = "Recovery point %llu less than least recovery point %llu, open resetlogs failed",
    [ERR_CANNOT_MODIFY_COLUMN] = "The current constraint forbids the column data type from being modified.",
    [ERR_SHRINK_EXTEND] = "segment should not extend for shrinking insert",

    [ERR_RENAME_FUNC_INDEX] = "Cannot rename function index column %s",
    [ERR_ENFORCE_INDEX] = "The index cannot be converted to a constraint.",
    [ERR_DATABASE_IS_ROLLING_BACK] = "Invalid operation when database is rolling back",
    [ERR_TOO_MANY_TABLES] = "Tables and views of user %s exceeded the limit %d",
    [ERR_CHECKSUM_FAILED] = "Checksum failed when read data from file %s",
    [ERR_NOLOGGING_SPACE] = "%s tablespace must be created first for nologging table",
    [ERR_MISUSE_UNDO_SPACE] = "%s tablespace cannot be used to create user object",
    [ERR_PART_LIST_COUNT] = "The count of partition table list exceeded  500",
    [ERR_USER_ID_NOT_EXIST] = "User id %u does not exist",
    [ERR_SHRINK_SPACE_SIZE] = "%s contains used data beyond requested value",
    [ERR_CANNOT_OPEN_DATABASE] = "Cannot open database after %s, please %s",
    [ERR_PAGE_CORRUPTED] = "Page %u-%u corrupted",
    [ERR_DATAFILE_RESIZE_TOO_SMALL] = "File size specified is smaller than minimum required",
    [ERR_INDEX_ALREADY_DROPPED] = "Index %s has been dropped or truncate",
    [ERR_DATAFILE_RESIZE_EXCEED] = "File size %lld bytes exceeds maximum of %lld bytes",
    [ERR_OBJECT_INVALID] = "The %s %s.%s is invalid",
    [ERR_LIBRARY_NOT_EXIST] = "Library %s.%s does not exist",
    [ERR_XA_IN_AUTON_TRANS] = "Cannot prepare XA in autonomous transaction",
    [ERR_XATXN_CHANGED_NOLOGGING_TABLE] = "Xa transaction can't change nologging table",
    [ERR_STANDBY_LESS_QUORUM] = "MAXIMIZE PROTECTION mode standby num %d less than quorum num %d",
    [ERR_ALCK_RECURSIVE_LEVEL] = "Advisory lock recursive limit %u reached",
    [ERR_ALCK_LOCK_THRESHOLD] = "Advisory lock number limit %u reached",
    [ERR_PAGE_NOT_BELONG_TABLE] = "The %s page does not belong to any table",
    [ERR_UPDATE_MASTER_KEY] = "Update master key failed when %s",
    [ERR_NO_BKINFO_REBUILD_CTRL] = "There is no backup info to rebuild control files",
    [ERR_EXCEED_SEGMENT_MAXSIZE] = "INITIAL storage option larger than MAXSIZE storage option",
    [ERR_MAX_SEGMENT_SIZE] = "add %d pages to segment with max pages(%d)",
    [ERR_BACKUP_TIMEOUT] = "timeout for break-point building",
    [ERR_LOG_SIZE_NOT_MATCH] = "RAFT: size of logfiles should be the same",
    [ERR_SWITCH_LOGFILE] = "switch logfile failed, %s",
    /* pl error: 900- */
    [ERR_RETURN_WITHOUT_VALUE] = "The user-defined function did not return any value.",
    [ERR_ACCESS_INTO_NULL] = "The referenced object type was not initialized.",
    [ERR_FUNC_LOCATION] = "%s function is not allowed here.",
    [ERR_CASE_NOT_FOUND] = "The declaration of CASE was not found when the CASE statement was executed.",
    [ERR_COLLECTION_IS_NULL] = "Reference to uninitialized collection",
    [ERR_CURSOR_ALREADY_OPEN] = "Cursor is already opened",
    [ERR_INVALID_CURSOR] = "The cursor was invalid.",
    [ERR_NO_DATA_FOUND] =
        "In PL/SQL, running SELECT INTO or EXECUTE IMMEDIATE INTO to grant values to variables had no data found.",
    [ERR_NOT_LOGGED_ON] = "The user did not log in.",
    [ERR_PROGRAM_ERROR_FMT] = "PL/SQL internal program error(%s).",
    [ERR_TRIG_COMMIT] = "Cannot COMMIT in a trigger",
    [ERR_SELF_IS_NULL] = "Method dispatch on NULL SELF argument is disallowed",
    [ERR_STORAGE_ERROR] = "PL/SQL: storage error",
    [ERR_SUBSCRIPT_BEYOND_COUNT] = "Subscript beyond count",
    [ERR_SUBSCRIPT_OUTSIDE_LIMIT] = "Subscript outside of limit",
    [ERR_INVOKE_EXT_FUNC_ERR] = "Invoke external function %s failed, error info %s",
    [ERR_TOO_MANY_ROWS] =
        "More than one return value of SELECT INTO, EXECUTE IMMEDIATE, or a cursor was assigned to a common variable.",
    [ERR_PL_SYNTAX_ERROR_FMT] = "PL/SQL:syntax error(%s)",
    [ERR_THREAD_NOT_START] = "Thread not start",
    [ERR_NO_ARCH_FILE_IN_PRIMARY] = "Primary miss the archived file",
    [ERR_PUTBUF_INSUF] = "Exceed putline buff size",
    [ERR_UNDEFINED_SYMBOL_FMT] = "Undefined symbol %s",
    [ERR_PLSQL_VALUE_ERROR_FMT] = "The PL/SQL values (%s) were incorrect.",
    [ERR_PLSQL_ILLEGAL_LINE_FMT] = "PL/SQL: illegal line(%s)",
    [ERR_NOT_ENOUGH_VALUES] = "Values were not enough",
    [ERR_CURSOR_NOT_OPEN] = "Cursor not open",
    [ERR_NO_DATA_NEEDED] = "No more rows needed",
    [ERR_RESULT_NOT_MATCH] = "PL/SQL: Return types of Result Set variables or query do not match",
    [ERR_TAB_MUTATING] =
        "The trigger or user-defined function used by a SQL statement which is adjusting a table %s.%s did not find the table.",
    [ERR_TRIG_DDL_DCL] = "DDL or DCL is not allowed in a trigger",
    [ERR_TOO_MANY_RETURN_RESULT] = "The number of sys_refcursor can be returned extend the max size:%d",
    [ERR_UNHANDLED_USER_EXCEPTION] = "There were user-defined PL/SQL exceptions not handled",
    [ERR_SHRINK_IN_PROGRESS_FMT] = "Table %s.%s shrink in progress",
    [ERR_PL_KEYWORD_ERROR] = "Keyword(eg.select,update,delete,if,etc) expected but encounter bracket",
    [ERR_EXCEED_TRIGGER_MAX_FMT] = "Triggers in a table cannot exceed %u",
    [ERR_SOURCE_SIZE_TOO_LARGE_FMT] = "Source code length %u exceed limit %u",
    [ERR_TRIG_ALREADY_IN_TAB_FMT] = "The trigger %s.%s already exists on another table",
    [ERR_PL_BEGIN_AUTOTRANS] =
        "When the session that hold some session level temporary tables is not committed, it is not supported to start autonomous transactions",
    [ERR_PL_UNDER_STANDYBY] = "Database under standby mode",
    [ERR_ILEGAL_RETURN_RESULT] = "Return_result be allowed in procedure or anonymous block",
    [ERR_PL_ATTR_TYPE_FMT] = "'%s.%s'.TYPE was not a variable, column, or attribute.",
    [ERR_PL_ATTR_ROWTYPE_FMT] = "With ROWTYPE attribute, '%s' must name a table, cursor or cursor-variable",
    [ERR_PL_BLOCK_TOO_DEEP_FMT] = "PL/SQL: block too complex, depth exceed the limitation %d",
    [ERR_PL_COMP_FMT] = "PL/SQL(%s.%s) terminated with compiling errors\n%s",
    [ERR_PL_PARAM_USE] = "Param only allowed in dml or anonymous block or call",
    [ERR_PL_REPLAY_UNKNOWN_FMT] = "Unknown replay type %u",
    [ERR_PL_DUP_OBJ_FMT] = "Duplicate object name %s",
    [ERR_PL_DUP_ARG_FMT] = "Duplicate argument %s in %s",
    [ERR_PL_ARG_FMT] = "The %uth argument of %s %s",
    [ERR_PL_EXPR_AS_LEFT_FMT] =
        "The expression %s was used as the assignment target (left operand of the assignment statement).",
    [ERR_PL_EXPR_AS_INTO_FMT] = "The expression %s was used as the assignment target of INTO.",
    [ERR_PL_CONTEXT_EMPTY] = "No prepare context",
    [ERR_PL_CONTEXT_TYPE_MISMATCH_FMT] = "%s sql-context type expected but %u found",
    [ERR_PL_EXPECTED_FAIL_FMT] = "%s expected but %s found",
    [ERR_PL_UNEXPECTED_FMT] = "Unexpected %s found",
    [ERR_PL_INVALID_EXCEPTION_FMT] = "Invalid exception name %s",
    [ERR_PL_INCOMPLETE_DECL_FMT] = "The declaration of the variable %s was incomplete.",
    [ERR_PL_UNSUPPORT] = "Unsupported feature",
    [ERR_PL_EXCEED_LABEL_MAX] = "Exceed label max %u in one block",
    [ERR_PL_OUT_PARAM_WITH_DFT] = "The OUT and IN OUT parameters were not allowed to contain a default expression.",
    [ERR_PL_ENCOUNT_PRIOR] = "The keyword PRIOR of a function or pseudo-column can be used only in SQL statements.",
    [ERR_PL_INVALID_ATTR_FMT] = "Invalid cursor attribute",
    [ERR_PL_ENTRY_LOCK] = "Could not lock pl object '%s'",
    [ERR_PL_DC_INVALIDATED] = "Pl dictionary cache is invalidated",
    [ERR_PL_EXPR_WRONG_TYPE] = "Expression is of wrong type",
    [ERR_PL_LABEL_INVALID_TYPE] = "Label type is invalid",
    [ERR_PL_INVALID_LOOP_INDEX] = "The using of loop index %s is invalid",
    [ERR_PL_INVALID_PROCEDURE] = "The procedure or function '%s.%s' has been dropped or changed",
    [ERR_DYNAMIC_WRONG_TYPE] = "The content datatype of 'execute immediate' must be string",
    [ERR_DYNAMIC_ILLEGAL_INTO] = "The into clause and select need to appear together in 'execute immediate'",
    [ERR_UDF_DDL_DCL] =
        "There was a statement that affects transaction commission or rollback in the user-defined function invoked by the DML operation.",
    [ERR_UNEXPECTED_PL_VARIANT] = "Unexpected pl variant",
    [ERR_PKG_OBJECT_NODEFINED_FMT] =
        "Subprogram or variant '%s' has declared in package, but not defined in package body",
    [ERR_PKG_OBJECT_NOMATCH_FMT] =
        "Subprogram or variant '%s' has defined in package body, but not matched with package specification",
    [ERR_EXT_PROC_NOT_STARTED] = "External process does not start, please check \"EXT_PROC_STARTUP\" parameter",
    [ERR_EXT_PROC_NOT_WORK] = "External process is not working",

    [ERR_DEBUG_CAN_NOT_ATTACHED] = "Session can not be attached, because %s",
    [ERR_DEBUG_SESSION_TYPE] = "Session type error, expect %s, the session id: %d",
    [ERR_DEBUG_FORCE_ABORT] = "Program has been forced to terminate",
    [ERR_DEBUG_BREAK_POINT_EXCEED] = "All breakpoints are in busy, the maximum count of breakpoints is %d",
    [ERR_DEBUG_TIMEOUT] = "Timeout when debug",
    [ERR_DEBUG_OPR_BREAK] = "Error occurred when handling breakpoint id %d, %s",
    [ERR_DEBUG_SESSION_STATUS] = "Session status error, expect %s, but %s",
    [ERR_PL_INDEX_ID_OVERFLOW] = "The index %d of %s is overflow, must be less than %d",
    [ERR_DEBUG_CAN_NOT_UNINIT] = "Session can not be uninited, because %s",
    [ERR_TRIG_INVALID_VIEW] = "Instead of trigger cannot create on view %s with calculating column %s",
    [ERR_TEMP_TABLE_HOLD] = "Attempt to access a transactional temp table %s.%s already in use",
    [ERR_PLE_OUT_PARAM_NOT_FOUND] = "Cannot found out parameter association follow a named association",
    [ERR_PLE_CURSOR_IN_OPEN] = "IN cursor %s cannot be OPEN again",
    /* user defined exception */
    [ERR_USER_DEFINED_EXCEPTION] = "User Defined Exception",

    /* job error, range [1400,1449] */
    [ERR_INTERVAL_TOO_EARLY] = "The interval of jobs was not a future time.",
    [ERR_JOB_UNSUPPORT] = "Job unsupport %s",
    [ERR_PARALLEL_PARAMS] = "Parallel grouping is too large",

    /* XA Errors */
    [ERR_XA_ALREADY_IN_LOCAL_TRANS] = "Doing work in a local transaction",
    [ERR_XA_RESUME_TIMEOUT] = "Timeout when waiting for the transaction branch to be available",
    [ERR_XA_BRANCH_NOT_EXISTS] = "Specified branch does not exists",
    [ERR_XA_RM_FAULT] = "Other resource manager error",
    [ERR_XA_RDONLY] = "Branch is read only",
    [ERR_XA_INVALID_XID] = "Invalid global transaction ID, %s",
    [ERR_XA_DUPLICATE_XID] = "Duplicate global transaction ID",
    [ERR_XA_TIMING] = "Invalid global transaction timing",
    [ERR_SHD_LOCAL_NODE_EXISTS] = "Local node already exists",
    [ERR_XA_IN_ABNORMAL_MODE] = "Unsure if specified branch exists when database in abnormal mode",
    [ERR_XA_OUTSIDE] = "Resource manager doing work outside global transaction",

    /* PLSQL ERROR 1600-1699 */
    [ERR_PL_ROLLBACK_EXCEED_SCOPE] = "cannot find this savepoint %s using of rollback in this plsql block",
    // SPM, range [1700, 1799]
    [ERR_SPM_NOT_ENABLED] = "SPM is not enabled",
    [ERR_SPM_NOT_SUPPORTED] = "SPM does not support %s",
    [ERR_SPM_NOT_FOUND] = "Cannot find %s in SPM",
    [ERR_SPM_DUPLICATE_PLAN] = "There is already a duplicate plan (signature:%s) in SPM",
    [ERR_SPM_FIX_EXISTS] = "There is already a fixed plan of destination sql in SPM",
    [ERR_SPM_STATUS_NOT_ALLOWED] = "Cannot %s with %s status",

    /* DLS */
    [ERR_DLS_LOCK_FAILED] = "dls lock(%u,%u) failed",
    [ERR_DLS_LOCK_TIMEOUT] = "dls lock(%u,%u) timeout",
    [ERR_DLS_INVALID_CMD] = "dls lock(%u,%u) invalid message type",

    // other error
    [ERR_SPACE_NO_DATAFILE] = "Space has no datafile",

    // cantian File System, range [2000, 2500]
    [ERR_GSS_OPEN_VOLUME] = "Open volume '%s' failed, reason %d",
    [ERR_GSS_READ_VOLUME] = "Read volume '%s' failed, volume id %d, reason %d",
    [ERR_GSS_WRITE_VOLUME] = "Write volume '%s' failed, volume id %d, reason %d",
    [ERR_GSS_SEEK_VOLUME] = "Seek volume '%s' failed, volume id %d, reason %d",
    [ERR_GSS_INVALID_PARAM] = "Invalid GSS parameter: %s",
    [ERR_ZFS_CREATE_SESSION] = "Create new GSS session failed, no free sessions, %d sessions used",
    [ERR_GSS_DUPLICATED_DIR] = "Make dir or Create file failed, %s has already existed",
    [ERR_GSS_NO_SPACE] = "gss no space in the vg",
    [ERR_OAMAP_DUP_KEY_ERROR] = "Hash map duplicated key",
    [ERR_OAMAP_INSERTION_FAILED] = "Failed to insert hash map ",
    [ERR_OAMAP_FETCH_FAILED] = "Failed to fetch hash map",
    [ERR_GSS_VG_NOT_INITIALIZED] = "The volume group has not been initialized.",
    [ERR_GSS_ENV_NOT_INITIALIZED] = "The gss env has not been initialized.",
    [ERR_GSS_DIR_NOT_EMPTY] = "The dir is not empty, can not remove.",
    [ERR_GSS_DIR_NOT_EXISTED] = "The dir or file %s is not existed.",
    [ERR_GSS_CLI_EXEC_FAIL] = "GSS client exec cmd '%s' failed, reason %s.",
    [ERR_GSS_VG_OPEN] = "Open volume group %s failed",
    [ERR_GSS_VG_LOCK] = "Lock volume group %s failed",
    [ERR_GSS_VG_REMOVE] = "Forbidden remove volume group's superblock",
    [ERR_GSS_ADD_EXISTED_VOLUME] = "Add an existed volume %s of volume-group %s failed",
    [ERR_GSS_REMOVE_NOEXIST_VOLUME] = "Remove a non-existent volume %s of volume-group %s failed",
    [ERR_GSS_REMOVE_NONEMPTY_VOLUME] = "Remove a nonempty volume %s failed",
    [ERR_GSS_REMOVE_SUPER_BLOCK] = "Remove super block %s failed",
    [ERR_GSS_LOCK_OCCUPIED] = "The lock is already occupied",
    [ERR_GSS_PATH_ILL] = "Path %s decode error %s",
    [ERR_GSS_VG_CHECK] = "Check volume group %s failed, reason %s",
    [ERR_GSS_REDO_ILL] = "GSS redo log error, reason %s",
    [ERR_GSS_FNODE_CHECK] = "GSS fnode error, reason %s",
    [ERR_GSS_GA_INIT] = "GSS ga init error, reason %s",
    [ERR_GSS_SHM_CREATE] = "Failed to create shared memory, key=0x%08x, size=%llu",
    [ERR_GSS_SHM_CHECK] = "Failed to check shared memory ctrl, key=0x%08x, reason=%s",
    [ERR_GSS_VG_CREATE] = "Create volume group %s failed, reason %s",
    [ERR_GSS_REG_CONFLICT] = "Register conflict, rk %llu",
    [ERR_GSS_INVALID_SESSION] = "Invalid session %d",
    [ERR_GSS_VG_CONF] = "Please check gss_vg_conf.ini, reason %s",
    [ERR_GSS_CHECK_RENAME] = "Rename failed, reason %s",
    [ERR_GSS_LOCK_TIMEOUT] = "GSS lock timeout",
    [ERR_GSS_SERVER_IS_DOWN] = "GSS server is down",
    [ERR_GSS_CHECK_SIZE] = "Failed to specify size %d which is not aligned with GSS allocate-unit size %d",
    [ERR_GSS_FILE_IS_OPEN] = "GSS file is open",
    [ERR_GSS_MES_ILL] = "GSS message contact error, reason %s",
    // JSON, range [2501, 2599]
    [ERR_JSON_INVLID_CLAUSE] = "Invalid %s clause, %s",
    [ERR_JSON_OUTPUT_TOO_LARGE] = "Output value too large",
    [ERR_JSON_PATH_SYNTAX_ERROR] = "JSON path expression syntax error, %s",
    [ERR_JSON_SYNTAX_ERROR] = "JSON syntax error, %s",
    [ERR_JSON_UNKNOWN_TYPE] = "Unknown json type %d when %s",
    [ERR_JSON_VALUE_MISMATCHED] = "%s evaluated to %s value",
    [ERR_JSON_INSUFFICIENT_MEMORY] = "JSON insufficient memory, %s",
    [ERR_JSONB_SYNTAX_ERROR] = "JSONB format error, %s",
    [ERR_JSONB_EXP_ERROR] = "JSONB export error, %s",

    // PLSQL UDT, RANGE[2600, 2699]
    [ERR_PL_WRONG_ARG_METHOD_INVOKE] = "Wrong number or types of arguments in call to '%s'",
    [ERR_PL_REF_VARIABLE_FAILED] = "Invalid reference to variable '%s'",
    [ERR_PL_MULTIPLE_RECORD_FAILED] = "Coercion into multiple record targets not supported",
    [ERR_PL_NO_DATA_FOUND] = "no data found",
    [ERR_PL_NOT_ALLOW_COLL] = "Collection types not allowed in current statements",
    [ERR_PL_WRONG_ADDR_TYPE] = "Complex type has unexpected address type",
    [ERR_PL_WRONG_TYPE_VALUE] = "%s has wrong type value(%d)",
    [ERR_PL_REC_FIELD_INVALID] = "Invalid record field address",
    [ERR_PL_HSTB_INDEX_TYPE] = "associative array's index of type must be integer or varchar",

    // MES, range [2700, 2799]
    [ERR_MES_INIT_FAIL] = "MES init failed, %s.",
    [ERR_MES_CREATE_AREA] = "MES create mes area failed, %s",
    [ERR_MES_CREATE_SOCKET] = "MES create socket failed.",
    [ERR_MES_INVALID_CMD] = "MES invalid mes command, %s",
    [ERR_MES_RECV_FAILED] = "MES recv failed, %s",
    [ERR_MES_CREATE_MUTEX] = "MES create mutex failed, %s",
    [ERR_MES_ILEGAL_MESSAGE] = "MES invalid message, %s",
    [ERR_MES_PARAMETER] = "MES invalid parameter, %s",
    [ERR_MES_ALREADY_CONNECT] = "MES has already connected before, %s",

    // CMS, range [3100, 3199]
    [ERR_CMS_OPEN_DISK] = "open disk failed, errno %d",
    [ERR_CMS_SEEK_DISK] = "seek disk failed, errno %d",
    [ERR_CMS_READ_DISK] = "read disk failed, errno %d",
    [ERR_CMS_WRITE_DISK] = "write disk failed, errno %d",
    [ERR_CMS_CREATE_SOCKET] = "create %s socket failed, errno %d",
    [ERR_CMS_OBJECT_EXISTS] = "%s already exists",
    [ERR_CMS_OBJECT_NOT_FOUND] = "%s is not found",
    [ERR_CMS_NUM_EXCEED] = "number of %s exceeds the maximum %llu",
    [ERR_CMS_DEFAULT_RES_GROUP] = "the resource group 'default' can't be deleted",
    [ERR_CMS_RES_GROUP_NOT_NULL] = "the resource group has resource(s)",
    [ERR_CMS_SAME_RESOURCE_TYPE] = "the resource type already exists in resource group %s",
    [ERR_CMS_RES_INVALID_ATTR] = "invalid attribute pairs",
    [ERR_CMS_SERVER_RUNNING] = "Another cms server is running",
    [ERR_CMS_GCC_EXPORT] = "export %s error",
    [ERR_CMS_GCC_IMPORT] = "import gcc error: %s",
    [ERR_CMS_INVALID_RES_ATTRS] = "resource attribute pairs have invalid keyword",
    [ERR_CMS_GCC_LOCK] = "% gcc failed, error code: %d",
    [ERR_CMS_GCC_NODE_UNREGISTERED] = "the node is unregistered",
    [ERR_CMS_PORT_OUT_RANGE] = "port is out of range[%u, %u]",
    [ERR_CMS_INVALID_PATH] = "%s path includes special character, is invalid",
    [ERR_CMS_GCC_VERSION_MISMATCH] = "%s cannot match current gcc version",
    [ERR_CMS_INVALID_VOTEDISK] = "the votedisk is not a file, block device or symbol link",
    [ERR_CMS_VOTEDISK_AUTHORITY] = "the votedisk is not readable and writable",
    [ERR_CMS_VOTEDISK_PATH] = "the real path of the votedisk is too long (maximum %u)",

    [ERR_CMS_INVALID_GCC] = "current gcc in GCC_HOME is invalid",
    [ERR_CMS_CONVERT_VALUE] = "cannot convert '%s' to %s type",

    [ERR_ACCESS_DEPOSIT_INST] = "failed to access deposit instance, logical id %d physical id %d",

    [ERR_CLUSTER_DDL_DISABLED] = "cluster DDL operation not available, please check whether other instances are open",
    [ERR_CM_OPEN_DISK] = "open disk failed, errno %d",
    [ERR_CM_SEEK_DISK] = "seek disk failed, errno %d",
    [ERR_CM_READ_DISK] = "read disk failed, errno %d",
    [ERR_CM_WRITE_DISK] = "write disk failed, errno %d",

    // SHM and TSE
    [ERR_SEM_FAULT] = "shm sem error",
    [ERR_BATCH_DATA_HANDLE_FAILED] = "shm handle batch data error",
    [ERR_SHM_SEND_MSG_FAILED] = "shm send message error",
    [ERR_INSTANCE_REG_FAILED] = "mysql instance req failed",
    [ERR_CONNECTION_FAILED] = "share mem message queue com error",
    [ERR_USER_NOT_EMPTY_4MYSQL] = "The user already exists and is not empty when creating db for mysql.",
    [ERR_FK_NO_INDEX_PAREN_4MYSQL] =
        "Failed to add the foreign key constraint. Missing index for constraint '%s' in the referenced table '%s'",
    [ERR_CHILD_DUPLICATE_KEY] = "Foreign key constraint would lead to a duplicate entry in child table",

    /*
     * NOTICE: the error code defined should be smaller than ERR_ERRNO_CEIL.
     */
    [ERR_ERRNO_CEIL] = "",
};

/** A global handler for handling error */
static cm_error_handler g_error_handler = NULL;

error_info_t *cm_error_info(void)
{
    return &g_tls_error;
}

void cm_reset_error_pos(void)
{
    g_tls_error.err_file[0] = 0;
    g_tls_error.err_line = 0;
}

void cm_reset_error(void)
{
    g_tls_error.loc.line = 0;
    g_tls_error.loc.column = 0;
    g_tls_error.is_full = 0;
    cm_reset_error_pos();
    if (g_tls_plc_error.plc_flag && (g_tls_plc_error.plc_cnt == 0 || g_tls_error.code != ERR_PL_COMP_FMT)) {
        g_tls_error.message[g_tls_plc_error.last_head] = '\0';
        g_tls_error.code = 0;
        return;
    }

    g_tls_error.code = 0;
    g_tls_error.message[0] = '\0';
}

void cm_set_error_pos(const char *file, uint32 line)
{
    char *filename = NULL;
    if (g_tls_error.err_line == 0) {
#ifdef WIN32
        filename = strrchr(file, '\\');
#else
        filename = strrchr(file, '/');
#endif
        CM_ASSERT(filename != NULL);

        filename++;
        (void)strncpy_s(g_tls_error.err_file, sizeof(g_tls_error.err_file), filename, strlen(filename));
        g_tls_error.err_line = line;
    }
}

// if in pl, revert last error
void cm_revert_pl_last_error(void)
{
    if (g_tls_plc_error.plc_flag) {
        g_tls_error.message[g_tls_plc_error.last_head] = '\0';
        g_tls_plc_error.last_head = g_tls_plc_error.last_head_bak;
        g_tls_error.code = 0;
        return;
    } else {
        g_tls_error.code = 0;
        g_tls_error.message[0] = '\0';
        return;
    }
}

void cm_set_ignore_log(bool8 is_ignore_log)
{
    g_tls_error.is_ignore_log = is_ignore_log;
}

status_t cm_revert_error(int32 code, const char *message, source_location_t *loc)
{
    g_tls_error.code = code;
    if (g_tls_error.message != message) {
        MEMS_RETURN_IFERR(memcpy_sp(g_tls_error.message, GS_MESSAGE_BUFFER_SIZE, message, GS_MESSAGE_BUFFER_SIZE));
    }
    g_tls_error.loc.line = loc->line;
    g_tls_error.loc.column = loc->column;
    return GS_SUCCESS;
}

char *cm_get_t2s_addr(void)
{
    return g_tls_error.t2s_buf1;
}

char *cm_t2s(const char *buf, uint32 len)
{
    uint32 copy_size;
    errno_t errcode;
    copy_size = (len >= GS_T2S_LARGER_BUFFER_SIZE) ? GS_T2S_LARGER_BUFFER_SIZE - 1 : len;
    if (copy_size != 0) {
        errcode = memcpy_sp(g_tls_error.t2s_buf1, (size_t)GS_T2S_LARGER_BUFFER_SIZE, buf, (size_t)copy_size);
        if (SECUREC_UNLIKELY(errcode != EOK)) {
            GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return NULL;
        }
    }
    g_tls_error.t2s_buf1[copy_size] = '\0';
    return g_tls_error.t2s_buf1;
}

char *cm_concat_t2s(const char *buf1, uint32 len1, const char *buf2, uint32 len2, char c_mid)
{
    uint32 copy_size = 0;
    errno_t errcode;
    if (len1 + len2 + 1 < GS_T2S_LARGER_BUFFER_SIZE) {
        if (len1 > 0) {
            copy_size = len1;
            errcode = memcpy_sp(g_tls_error.t2s_buf1, (size_t)GS_T2S_LARGER_BUFFER_SIZE, buf1, (size_t)len1);
            if (SECUREC_UNLIKELY(errcode != EOK)) {
                GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
                return NULL;
            }
        }
        if (len1 > 0 && len2 > 0) {
            g_tls_error.t2s_buf1[copy_size] = c_mid;
            copy_size += 1;
        }
        if (len2 > 0) {
            errcode = memcpy_sp(g_tls_error.t2s_buf1 + copy_size, (size_t)GS_T2S_LARGER_BUFFER_SIZE, buf2,
                                (size_t)len2);
            if (SECUREC_UNLIKELY(errcode != EOK)) {
                GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
                return NULL;
            }
            copy_size += len2;
        }
    }
    g_tls_error.t2s_buf1[copy_size] = '\0';
    return g_tls_error.t2s_buf1;
}

char *cm_t2s_case(const char *buf, uint32 len, bool32 case_sensitive)
{
    uint32 copy_size;
    errno_t errcode;
    copy_size = (len >= GS_T2S_LARGER_BUFFER_SIZE) ? GS_T2S_LARGER_BUFFER_SIZE - 1 : len;
    if (copy_size != 0) {
        errcode = memcpy_sp(g_tls_error.t2s_buf1, (size_t)GS_T2S_LARGER_BUFFER_SIZE, buf, (size_t)copy_size);
        if (SECUREC_UNLIKELY(errcode != EOK)) {
            GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return NULL;
        }
    }
    g_tls_error.t2s_buf1[copy_size] = '\0';
    if (!case_sensitive) {
        cm_str_upper(g_tls_error.t2s_buf1);
    }
    return g_tls_error.t2s_buf1;
}

char *cm_t2s_ex(const char *buf, uint32 len)
{
    uint32 copy_size;
    errno_t errcode;
    copy_size = (len >= GS_T2S_BUFFER_SIZE) ? GS_T2S_BUFFER_SIZE - 1 : len;
    if (copy_size != 0) {
        errcode = memcpy_sp(g_tls_error.t2s_buf2, (size_t)GS_T2S_BUFFER_SIZE, buf, (size_t)copy_size);
        if (SECUREC_UNLIKELY(errcode != EOK)) {
            GS_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return NULL;
        }
    }
    g_tls_error.t2s_buf2[copy_size] = '\0';
    return g_tls_error.t2s_buf2;
}

void cm_get_error(int32 *code, const char **message, source_location_t *loc)
{
    *code = g_tls_error.code;
    *message = g_tls_error.message;

    if (loc != NULL) {
        *loc = g_tls_error.loc;
    }
}

void cm_set_error_loc(source_location_t loc)
{
    g_tls_error.loc = loc;
}

void cm_reset_error_loc(void)
{
    g_tls_error.loc.column = 0;
    g_tls_error.loc.line = 0;
}

void cm_try_set_error_loc(source_location_t loc)
{
    if (g_tls_error.loc.column == 0 && g_tls_error.loc.line == 0) {
        g_tls_error.loc = loc;
    }
}

int32 cm_get_error_code(void)
{
    return g_tls_error.code;
}

void cm_reset_error_user(int err_no, char *user, char *name, err_object_t type)
{
    int32 errcode = cm_get_error_code();
    if (errcode == ERR_USER_NOT_EXIST) {
        cm_reset_error();
        switch (type) {
            case ERR_TYPE_LIBRARY:
                GS_THROW_ERROR(err_no, "library", user, name);
                break;
            case ERR_TYPE_TYPE:
                GS_THROW_ERROR(err_no, "type spec", user, name);
                break;
            case ERR_TYPE_PROCEDURE:
                GS_THROW_ERROR(err_no, "object", user, name);
                break;
            case ERR_TYPE_TRIGGER:
                GS_THROW_ERROR(err_no, "trigger", user, name);
                break;
            case ERR_TYPE_SEQUENCE:
            case ERR_TYPE_TABLE_OR_VIEW:
                GS_THROW_ERROR(err_no, user, name);
                break;
            case ERR_TYPE_INDEX:
                GS_THROW_ERROR(err_no, user, name);
                break;
            default:
                break;
        }
    }
}

void cm_set_error(const char *file, uint32 line, gs_errno_t code, const char *format, ...)
{
    va_list args;

#ifndef IGNORE_ASSERT
    cm_assert(code != ERR_INVALID_ROWID);
    cm_assert(code != ERR_OBJECT_ALREADY_DROPPED);
#endif

    va_start(args, format);
    if (g_tls_plc_error.plc_flag) {
        cm_set_plc_error(file, line, code, format, args);
    } else if (g_error_handler == NULL) {
        cm_set_clt_error(file, line, code, format, args);
    } else {
        g_error_handler(file, line, code, format, args);
    }

    va_end(args);
}

void cm_set_error_ex(const char *file, uint32 line, gs_errno_t code, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    char tmp[GS_MAX_LOG_CONTENT_LENGTH];
    errno_t err = vsnprintf_s(tmp, GS_MAX_LOG_CONTENT_LENGTH, GS_MAX_LOG_CONTENT_LENGTH - 1, format, args);
    if (SECUREC_UNLIKELY(err == -1)) {
        cm_reset_error();
        GS_LOG_RUN_ERR("Secure C lib has thrown an error %d while setting error", err);
    }
    cm_set_error(file, line, code, g_error_desc[code], tmp);

    va_end(args);
#ifndef WIN32
    if (code == ERR_ASSERT_ERROR) {
        void *array[GS_MAX_BLACK_BOX_DEPTH] = { 0 };
        size_t size;
        char **stacks = NULL;
        size_t i;
        size = backtrace(array, GS_MAX_BLACK_BOX_DEPTH);
        stacks = backtrace_symbols(array, size);
        if (stacks == NULL) {
            return;
        }

        if (size <= GS_INIT_ASSERT_DEPTH) {
            CM_FREE_PTR(stacks);
            return;
        }

        GS_LOG_RUN_ERR("assert raised, expect: %s at %s:%u", tmp, file, line);
        for (i = GS_INIT_ASSERT_DEPTH; i < size; i++) {
            GS_LOG_RUN_ERR("#%-2u in %s", (uint32)i, stacks[i]);
        }

        CM_FREE_PTR(stacks);
    }
#endif
}

void cm_set_hint(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    g_tls_error.code = ERR_HINT;
    g_tls_error.loc.line = 0;
    g_tls_error.loc.column = 0;

    errno_t err = vsnprintf_s(g_tls_error.message, GS_MESSAGE_BUFFER_SIZE, GS_MESSAGE_BUFFER_SIZE - 1, format, args);
    if (SECUREC_UNLIKELY(err == -1)) {
        GS_LOG_RUN_ERR("Secure C lib has thrown an error %d while setting hint", err);
    }
    va_end(args);
}

void cm_set_superposed_error(gs_errno_t code, const char *log_msg)
{
    size_t exist_msg_len = strlen(g_tls_error.message);
    char tmp_msg[GS_MESSAGE_BUFFER_SIZE] = { 0 };
    char *msg_ptr = NULL;
    size_t tmp_msg_len;
    uint32 remain_buf_size;
    errno_t err;

    err = snprintf_s(tmp_msg, GS_MESSAGE_BUFFER_SIZE, GS_MESSAGE_BUFFER_SIZE - 1, "\r\nGS-%05d, %s", code, log_msg);
    if (SECUREC_UNLIKELY(err == -1)) {
        GS_LOG_RUN_ERR("Secure C lib has thrown an error %d while setting error", err);
        return;
    }

    tmp_msg_len = (uint32)strlen(tmp_msg);
    remain_buf_size = GS_MESSAGE_BUFFER_SIZE - (uint32)exist_msg_len;
    if (exist_msg_len + tmp_msg_len < GS_MESSAGE_BUFFER_SIZE) {
        msg_ptr = g_tls_error.message + exist_msg_len;
        err = strncpy_s(msg_ptr, (size_t)remain_buf_size, tmp_msg, (size_t)tmp_msg_len);
        if (SECUREC_UNLIKELY(err != EOK)) {
            GS_LOG_RUN_ERR("Secure C lib has thrown an error %d while setting error", err);
            return;
        }
    }
}

status_t cm_set_sql_error(const char *file, uint32 line, gs_errno_t code, const char *format, va_list args)
{
    char log_msg[GS_MAX_LOG_CONTENT_LENGTH] = { 0 };
    char *last_file = NULL;
    log_param_t *log_param = cm_log_param_instance();
    errno_t err;
#ifdef WIN32
    last_file = strrchr(file, '\\');
#else
    last_file = strrchr(file, '/');
#endif

    err = vsnprintf_s(log_msg, GS_MAX_LOG_CONTENT_LENGTH, GS_MAX_LOG_CONTENT_LENGTH - 1, format, args);
    if (SECUREC_UNLIKELY(err == -1)) {
        GS_LOG_RUN_ERR("Secure C lib has thrown an error %d while setting error", err);
    }
    if (!g_tls_error.is_ignore_log) {
        GS_LOG_DEBUG_ERR("CT-%05d : %s [%s:%u]", code, log_msg, last_file + 1, line);

        if (log_param->log_instance_startup || code == ERR_SYSTEM_CALL) {
            GS_LOG_RUN_ERR("CT-%05d : %s [%s:%u]", code, log_msg, last_file + 1, line);
        }
    }

    if (g_tls_error.code == 0 || g_tls_error.code == ERR_HINT) {
        g_tls_error.code = code;
        g_tls_error.loc.line = 0;
        g_tls_error.loc.column = 0;
        err = snprintf_s(g_tls_error.message, GS_MESSAGE_BUFFER_SIZE, GS_MESSAGE_BUFFER_SIZE - 1, "%s", log_msg);
        if (SECUREC_UNLIKELY(err == -1)) {
            GS_LOG_RUN_ERR("Secure C lib has thrown an error %d while setting error", err);
        }
    } else if (g_enable_err_superposed == GS_TRUE) {
        cm_set_superposed_error(code, log_msg);
    }
    return GS_SUCCESS;
}

status_t cm_set_srv_error(const char *file, uint32 line, gs_errno_t code, const char *format, va_list args)
{
    char log_msg[GS_MESSAGE_BUFFER_SIZE];

    errno_t err = vsnprintf_s(log_msg, GS_MESSAGE_BUFFER_SIZE, GS_MESSAGE_BUFFER_SIZE - 1, format, args);
    if (SECUREC_UNLIKELY(err == -1)) {
        GS_LOG_RUN_ERR("Secure C lib has thrown an error %d while setting error", err);
    }

    if (g_tls_error.code == 0 || !g_enable_err_superposed) {
        /* override srv error when err superposed disable */
        g_tls_error.code = code;
        g_tls_error.loc.line = 0;
        g_tls_error.loc.column = 0;

        MEMS_RETURN_IFERR(memcpy_sp(g_tls_error.message, GS_MESSAGE_BUFFER_SIZE, log_msg, GS_MESSAGE_BUFFER_SIZE));
    } else if (g_enable_err_superposed == GS_TRUE) {
        cm_set_superposed_error(code, log_msg);
    }
#ifdef DB_DEBUG_VERSION
    printf("%s:%u, CT-%05d: %s\n", file, line, code, g_tls_error.message);
#endif
    return GS_SUCCESS;
}

status_t cm_set_clt_error(const char *file, uint32 line, gs_errno_t code, const char *format, va_list args)
{
    char log_msg[GS_MESSAGE_BUFFER_SIZE];

    errno_t err = vsnprintf_s(log_msg, GS_MESSAGE_BUFFER_SIZE, GS_MESSAGE_BUFFER_SIZE - 1, format, args);
    if (SECUREC_UNLIKELY(err == -1)) {
        GS_LOG_RUN_ERR("Secure C lib has thrown an error %d while setting error", err);
    }

    if (g_tls_error.code == 0 || !g_enable_err_superposed) {
        /* override clt error when err superposed disable */
        g_tls_error.code = code;
        g_tls_error.loc.line = 0;
        g_tls_error.loc.column = 0;

        MEMS_RETURN_IFERR(memcpy_sp(g_tls_error.message, GS_MESSAGE_BUFFER_SIZE, log_msg, GS_MESSAGE_BUFFER_SIZE));
    } else if (g_enable_err_superposed == GS_TRUE) {
        cm_set_superposed_error(code, log_msg);
    }
    return GS_SUCCESS;
}

static status_t cm_connect_plc_error(const char *tmp_msg)
{
    size_t exist_msg_len = strlen(g_tls_error.message);
    size_t tmp_msg_len = (uint32)strlen(tmp_msg);
    uint32 remain_buf_size = GS_MESSAGE_BUFFER_SIZE - (uint32)exist_msg_len;

    if (exist_msg_len + tmp_msg_len < GS_MESSAGE_BUFFER_SIZE) {
        char *msg_ptr = g_tls_error.message + exist_msg_len;
        MEMS_RETURN_IFERR(strncpy_s(msg_ptr, (size_t)remain_buf_size, tmp_msg, (size_t)tmp_msg_len));
        g_tls_plc_error.last_head_bak = g_tls_plc_error.last_head;
        g_tls_plc_error.last_head = (uint16)exist_msg_len;
    } else {
        g_tls_error.is_full = GS_TRUE;
    }
    return GS_SUCCESS;
}

static status_t cm_set_superposed_plc_error(gs_errno_t code, const char *log_msg)
{
    char tmp_msg[GS_MESSAGE_BUFFER_SIZE] = { 0 };
    source_location_t loc = g_tls_error.loc;

    // return value of security fuction snpritf_s/vsnprintf_s which in
    if (g_tls_error.loc.line == 0 || g_tls_error.loc.column == 0) {
        PRTS_RETURN_IFERR(
            snprintf_s(tmp_msg, GS_MESSAGE_BUFFER_SIZE, GS_MESSAGE_BUFFER_SIZE - 1, "PLC-%05d %s\n", code, log_msg));
    } else {
        PRTS_RETURN_IFERR(snprintf_s(tmp_msg, GS_MESSAGE_BUFFER_SIZE, GS_MESSAGE_BUFFER_SIZE - 1,
                                     "[%u:%u] PLC-%05d %s\n", loc.line, loc.column, code, log_msg));
    }
    if (g_tls_error.code == ERR_PL_COMP_FMT && g_tls_plc_error.plc_cnt <= GS_MAX_PLC_CNT) {
        g_tls_error.message[g_tls_plc_error.start_pos[g_tls_plc_error.plc_cnt - 1]] = '\0';
    }
    return cm_connect_plc_error(tmp_msg);
}

status_t cm_set_plc_error(const char *file, uint32 line, gs_errno_t code, const char *format, va_list args)
{
    char log_msg[GS_MAX_LOG_CONTENT_LENGTH] = { 0 };
    char *last_file = NULL;
#ifdef WIN32
    last_file = strrchr(file, '\\');
#else
    last_file = strrchr(file, '/');
#endif

    // return value of security fuction snpritf_s/vsnprintf_s which in cm_error.c or cm_log.c can be void
    int32 rc_memzero = vsnprintf_s(log_msg, GS_MAX_LOG_CONTENT_LENGTH, GS_MAX_LOG_CONTENT_LENGTH - 1, format, args);
    if (rc_memzero == -1) {
        GS_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "PLSQL's error message is too long, exceed %d",
                          GS_MAX_LOG_CONTENT_LENGTH - 1);
        return GS_ERROR;
    }

    GS_LOG_DEBUG_ERR("CT-%05d : %s [%s:%u]", code, log_msg, last_file + 1, line);
    g_tls_error.code = code;

    return cm_set_superposed_plc_error(code, log_msg);
}

status_t cm_set_superposed_plc_loc(source_location_t loc, gs_errno_t code, const char *log_msg)
{
    if (g_tls_error.loc.line == 0 || g_tls_error.loc.column == 0 || strlen(g_tls_error.message) < 1 ||
        g_tls_error.message[g_tls_plc_error.last_head] == '[') {
        return GS_SUCCESS;
    }

    char tmp_msg[GS_MESSAGE_BUFFER_SIZE] = { 0 };
    char tmp_log[GS_MESSAGE_BUFFER_SIZE] = { 0 };
    MEMS_RETURN_IFERR(strncpy_s(tmp_log, GS_MESSAGE_BUFFER_SIZE, g_tls_error.message + g_tls_plc_error.last_head,
                                strlen(g_tls_error.message) - g_tls_plc_error.last_head));
    g_tls_error.message[g_tls_plc_error.last_head] = '\0';

    PRTS_RETURN_IFERR(snprintf_s(tmp_msg, GS_MESSAGE_BUFFER_SIZE, GS_MESSAGE_BUFFER_SIZE - 1, "[%u:%u] %s", loc.line,
                                 loc.column, tmp_log));
    return cm_connect_plc_error(tmp_msg);
}

void cm_init_error_handler(cm_error_handler handler)
{
    g_error_handler = handler;
}

int cm_get_os_error(void)
{
#ifdef WIN32
    return GetLastError();
#else
    return errno;
#endif
}

int cm_get_sock_error(void)
{
#ifdef WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

void cm_set_sock_error(int32 e)
{
#ifdef WIN32
    WSASetLastError(e);
#else
    errno = e;
#endif
}

const char *cm_get_errormsg(int32 code)
{
    const char *msg = NULL;

    if (code < ERR_ERRNO_BASE || code > ERR_ERRNO_CEIL) {
        return "message of error code not found";
    }

    msg = g_error_desc[code];

    if (msg == NULL || strlen(msg) == 0) {
        return "message of error code not found";
    }

    return msg;
}

void cm_log_protocol_error(void)
{
    int32 err_code = 0;
    const char *err_message = NULL;
    cm_get_error(&err_code, &err_message, NULL);
    GS_LOG_RUN_INF("protocol interaction failed,err_code is [%d].", err_code);
}

#ifdef __cplusplus
}
#endif
