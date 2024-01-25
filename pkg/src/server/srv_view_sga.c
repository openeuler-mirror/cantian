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
 * srv_view_sga.c
 *
 *
 * IDENTIFICATION
 * src/server/srv_view_sga.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_module.h"
#include "knl_log.h"
#include "knl_context.h"
#include "srv_view_sga.h"
#include "srv_instance.h"
#include "srv_param.h"
#include "dml_executor.h"
#include "knl_spm.h"
#include "dtc_database.h"

#define SGA_VALUE_BUFFER_NAME 40
#define SGA_VALUE_BUFFER_LEN 40
#define SGA_SQL_ID_LEN (uint32)10
#define SGA_PDOWN_BUFFER_LEN (uint32)1000
#define SGA_MAX_SQL_ID_NUM (uint32)90

typedef struct st_vw_sqlarea_assist {
    sql_context_t vw_ctx;
    uint32 pages;
    uint32 alloc_pos;
    char pdown_sql_buffer[SGA_PDOWN_BUFFER_LEN + 1];
    text_t pdown_sql_id;
    text_t sql_text;
    uint32 sql_hash;
    uint32 ref_count;
} vw_sqlarea_assist_t;

knl_column_t g_sga_columns[] = {
    { 0, "NAME", 0, 0, CT_TYPE_CHAR, SGA_VALUE_BUFFER_NAME, 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "VALUE", 0, 0, CT_TYPE_CHAR, SGA_VALUE_BUFFER_LEN, 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_system_columns[] = {
    { 0, "ID",           0, 0, CT_TYPE_INTEGER, sizeof(uint32),    0, 0, CT_FALSE, 0, { 0 } },
    { 1, "NAME",         0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN,   0, 0, CT_FALSE, 0, { 0 } },
    { 2, "VALUE",        0, 0, CT_TYPE_VARCHAR, CT_MAX_NUMBER_LEN, 0, 0, CT_TRUE,  0, { 0 } },
    { 3, "COMMENTS",     0, 0, CT_TYPE_VARCHAR, CT_COMMENT_SIZE,   0, 0, CT_FALSE, 0, { 0 } },
    { 4, "ACCUMULATIVE", 0, 0, CT_TYPE_BOOLEAN, sizeof(bool32),    0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_temp_pool_columns[] = {
    { 0,  "ID",              0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 1,  "TOTAL_VIRTUAL",   0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 2,  "FREE_VIRTUAL",    0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 3,  "PAGE_SIZE",       0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 4,  "TOTAL_PAGES",     0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 5,  "FREE_PAGES",      0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 6,  "PAGE_HWM",        0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 7,  "FREE_LIST",       0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 8,  "CLOSED_LIST",     0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 9,  "DISK_EXTENTS",    0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 10, "SWAP_COUNT",      0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 11, "FREE_EXTENTS",    0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 12, "MAX_SWAP_COUNT",  0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_vm_func_stack_columns[] = {
    { 0, "FUNC_STACK", 0, 0, CT_TYPE_VARCHAR, CT_VM_FUNC_STACK_SIZE, 0, 0, CT_TRUE, 0, { 0 } },
    { 1, "REF_COUNT", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_TRUE, 0, { 0 } },
};

static knl_column_t g_sqlarea_columns[] = {
    { 0, "SQL_TEXT", 0, 0, CT_TYPE_VARCHAR, CT_MAX_COLUMN_SIZE, 0, 0, CT_TRUE, 0, { 0 } },
    { 1, "SQL_ID", 0, 0, CT_TYPE_VARCHAR, CT_MAX_UINT32_STRLEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "EXECUTIONS", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 3, "DISK_READS", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 4, "BUFFER_GETS", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 5, "CR_GETS", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 6, "SORTS", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 7, "PARSE_TIME", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 8, "PARSE_CALLS", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 9, "PROCESSED_ROWS", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 10, "PARSING_USER_ID", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 11, "PARSING_USER_NAME", 0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 12, "MODULE", 0, 0, CT_TYPE_VARCHAR, CT_MAX_NAME_LEN, 0, 0, CT_FALSE, 0, { 0 } },
    { 13, "IO_WAIT_TIME", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 14, "CON_WAIT_TIME", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 15, "CPU_TIME", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 16, "ELAPSED_TIME", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 17, "LAST_LOAD_TIME", 0, 0, CT_TYPE_DATE, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 18, "PROGRAM_ID", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 19, "PROGRAM_LINE#", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 20, "LAST_ACTIVE_TIME", 0, 0, CT_TYPE_DATE, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 21, "REF_COUNT", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 22, "IS_FREE", 0, 0, CT_TYPE_BOOLEAN, sizeof(bool32), 0, 0, CT_FALSE, 0, { 0 } },
    { 23, "CLEANED", 0, 0, CT_TYPE_BOOLEAN, sizeof(bool32), 0, 0, CT_FALSE, 0, { 0 } },
    { 24, "PAGES", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 25, "VALID", 0, 0, CT_TYPE_INTEGER, sizeof(uint32), 0, 0, CT_FALSE, 0, { 0 } },
    { 26, "SHARABLE_MEM", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 27, "VM_OPEN_PAGES", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 28, "VM_CLOSE_PAGES", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 29, "VM_SWAPIN_PAGES", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 30, "VM_FREE_PAGES", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 31, "NETWORK_TIME", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 32, "PDOWN_SQL_ID", 0, 0, CT_TYPE_VARCHAR, SGA_PDOWN_BUFFER_LEN, 0, 0, CT_TRUE, 0, { 0 } },
    { 33, "VM_ALLOC_PAGES", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 34, "VM_MAX_OPEN_PAGES", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 35, "VM_SWAPOUT_PAGES", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 36, "DCS_BUFFER_GETS", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 37, "DCS_CR_GETS", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
    { 38, "DCS_NET_TIME", 0, 0, CT_TYPE_BIGINT, sizeof(uint64), 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_sga_stat_columns[] = {
    { 0, "AREA", 0, 0, CT_TYPE_VARCHAR, 32, 0, 0, CT_FALSE, 0, { 0 } },
    { 1, "POOL", 0, 0, CT_TYPE_VARCHAR, 32, 0, 0, CT_FALSE, 0, { 0 } },
    { 2, "NAME", 0, 0, CT_TYPE_VARCHAR, 32, 0, 0, CT_FALSE, 0, { 0 } },
    { 3, "VALUE", 0, 0, CT_TYPE_VARCHAR, 32, 0, 0, CT_FALSE, 0, { 0 } },
};

static knl_column_t g_sqlpool_columns[] = {
    { 0,  "SQL_ID",           0, 0, CT_TYPE_VARCHAR, CT_MAX_UINT32_STRLEN, 0, 0, CT_FALSE, 0, { 0 } },                                                                           // sql_context->ctrl.hash_value
    { 1,  "SQL_TYPE",         0, 0, CT_TYPE_INTEGER, sizeof(uint32),       0, 0, CT_FALSE, 0, { 0 } },  // sql_context->type
    { 2,  "UID",              0, 0, CT_TYPE_INTEGER, sizeof(uint32),       0, 0, CT_FALSE, 0, { 0 } },       // sql_context->ctrl.uid
    { 3,  "REF_COUNT",        0, 0, CT_TYPE_INTEGER, sizeof(uint32),       0, 0, CT_FALSE, 0, { 0 } }, // sql_context->ctrl.ref_count
    { 4,  "VALID",            0, 0, CT_TYPE_BOOLEAN, sizeof(bool32),       0, 0, CT_FALSE, 0, { 0 } },
    { 5,  "CLEANED",          0, 0, CT_TYPE_BOOLEAN, sizeof(bool32),       0, 0, CT_FALSE, 0, { 0 } },
    { 6,  "IS_FREE",          0, 0, CT_TYPE_BOOLEAN, sizeof(bool32),       0, 0, CT_FALSE, 0, { 0 } },
    { 7,  "MCTX_PAGE_COUNT",  0, 0, CT_TYPE_INTEGER, sizeof(uint32),       0, 0, CT_FALSE, 0, { 0 } }, // sql_context->ctrl.memory->pages.count
    { 8,  "MCTX_PAGE_FIRST",  0, 0, CT_TYPE_INTEGER, sizeof(uint32),       0, 0, CT_FALSE, 0, { 0 } }, // sql_context->ctrl.memory->pages.first
    { 9,  "MCTX_PAGE_LAST",   0, 0, CT_TYPE_INTEGER, sizeof(uint32),       0, 0, CT_FALSE, 0, { 0 } }, // sql_context->ctrl.memory->pages.last
    { 10, "CURRENT_PAGE_ID",  0, 0, CT_TYPE_INTEGER, sizeof(uint32),       0, 0, CT_FALSE, 0, { 0 } }, // sql_context->ctrl.memory->curr_page_id
    { 11, "MCTX_PAGES",       0, 0, CT_TYPE_VARCHAR, CT_MAX_COLUMN_SIZE,   0, 0, CT_TRUE,  0, { 0 } }, // sql_context->ctrl.memory.pool.map
    { 12, "LARGE_PAGE",       0, 0, CT_TYPE_INTEGER, sizeof(uint32),       0, 0, CT_TRUE,  0, { 0 } }, // sql_context->large_page_id
    { 13, "FIRST_OPTMZ_VARS", 0, 0, CT_TYPE_INTEGER, sizeof(uint32),       0, 0, CT_FALSE, 0, { 0 } },                                                                            // sql_context->fexec_vars_cnt
    { 14, "FIRST_OPTMZ_BUFF", 0, 0, CT_TYPE_INTEGER, sizeof(uint32),       0, 0, CT_FALSE, 0, { 0 } }, // sql_context->fexec_vars_bytes
    { 15, "LAST_LOAD_TIME",   0, 0, CT_TYPE_DATE,    sizeof(date_t),       0, 0, CT_FALSE, 0, { 0 } }, // sql_context->stat.last_load_time
    { 16, "LAST_ACTIVE_TIME", 0, 0, CT_TYPE_DATE,    sizeof(date_t),       0, 0, CT_FALSE, 0, { 0 } }, // sql_context->stat.last_active_time
};

#define SGA_COLS (sizeof(g_sga_columns) / sizeof(knl_column_t))
#define SYSTEM_COLS (sizeof(g_system_columns) / sizeof(knl_column_t))
#define TEMP_POOL_COLS (sizeof(g_temp_pool_columns) / sizeof(knl_column_t))
#define SQLAREA_COLS (sizeof(g_sqlarea_columns) / sizeof(knl_column_t))
#define SGA_STAT_COLS (sizeof(g_sga_stat_columns) / sizeof(knl_column_t))
#define SQLPOOL_COLS (sizeof(g_sqlpool_columns) / sizeof(knl_column_t))
#define SQL_PLAN_COLS (sizeof(g_sql_plan_columns) / sizeof(knl_column_t))

typedef struct st_sga_row {
    char *name;
    char value[SGA_VALUE_BUFFER_LEN];
} sga_row_t;

static sga_row_t g_sga_rows[] = {
    { "data buffer",       { 0 } },
    { "cr pool",           { 0 } },
    { "log buffer",        { 0 } },
    { "shared pool",       { 0 } },
    { "transaction pool",  { 0 } },
    { "dbwr buffer",       { 0 } },
    { "lgwr buffer",       { 0 } },
    { "lgwr cipher buffer", { 0 } },
    { "lgwr async buffer", { 0 } },
    { "lgwr head buffer",  { 0 } },
    { "large pool",        { 0 } },
    { "temporary buffer",  { 0 } },
    { "index buffer",      { 0 } },
    { "variant memory area",       { 0 } },
    { "large variant memory area", { 0 } },
    { "private memory area",       { 0 } },
    { "buffer iocbs", { 0 } },
    { "GMA total", { 0 } },
};

static bool32 g_sga_ready = CT_FALSE;

static spinlock_t g_sga_lock = 0;

#define SGA_ROW_COUNT (sizeof(g_sga_rows) / sizeof(sga_row_t))
#define VM_SYSTEM_ROWS (TOTAL_OS_RUN_INFO_TYPES)
#define VM_FUNC_STACK_COLS (sizeof(g_vm_func_stack_columns) / sizeof(knl_column_t))
#define VM_SGA_WRITE_VAL(idx, val)                                                                                 \
    do {                                                                                                           \
        int iret_snprintf = 0;                                                                                     \
        iret_snprintf = snprintf_s(g_sga_rows[idx].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%.2fM", \
            ((double)(val)) / SIZE_M(1));                                                                          \
        if (iret_snprintf == -1) {                                                                                 \
            cm_spin_unlock(&g_sga_lock);                                                                           \
            CT_THROW_ERROR(ERR_SYSTEM_CALL, (iret_snprintf));                                                      \
            return CT_ERROR;                                                                                       \
        }                                                                                                          \
        (idx)++;                                                                                                   \
    } while (0)

status_t vw_sga_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    uint64 id = cursor->rowid.vmid;
    row_assist_t ra;
    knl_attr_t *attr = &((knl_session_t *)session)->kernel->attr;
    uint32 idx = 0;

    if (id >= SGA_ROW_COUNT) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    if (!g_sga_ready) {
        cm_spin_lock(&g_sga_lock, NULL);

        if (!g_sga_ready) {
            g_sga_ready = CT_TRUE;
            VM_SGA_WRITE_VAL(idx, attr->data_buf_size);
            VM_SGA_WRITE_VAL(idx, attr->cr_pool_part_size);
            VM_SGA_WRITE_VAL(idx, attr->log_buf_size);
            VM_SGA_WRITE_VAL(idx, attr->shared_area_size);
            VM_SGA_WRITE_VAL(idx, attr->tran_buf_size);
            VM_SGA_WRITE_VAL(idx, attr->dbwr_buf_size);
            VM_SGA_WRITE_VAL(idx, attr->lgwr_buf_size);
            VM_SGA_WRITE_VAL(idx, attr->lgwr_cipher_buf_size);
            VM_SGA_WRITE_VAL(idx, attr->lgwr_async_buf_size);
            VM_SGA_WRITE_VAL(idx, attr->lgwr_head_buf_size);
            VM_SGA_WRITE_VAL(idx, attr->large_pool_size);
            VM_SGA_WRITE_VAL(idx, attr->temp_buf_size);
            VM_SGA_WRITE_VAL(idx, attr->index_buf_size);
            VM_SGA_WRITE_VAL(idx, attr->vma_size);
            VM_SGA_WRITE_VAL(idx, attr->large_vma_size);
            VM_SGA_WRITE_VAL(idx, attr->pma_size);
            VM_SGA_WRITE_VAL(idx, attr->buf_iocbs_size);
            VM_SGA_WRITE_VAL(idx, g_instance->sga.size);
            CM_ASSERT(idx == SGA_ROW_COUNT);
        }
        cm_spin_unlock(&g_sga_lock);
    }

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, SGA_COLS);
    CT_RETURN_IFERR(row_put_str(&ra, g_sga_rows[id].name));
    CT_RETURN_IFERR(row_put_str(&ra, g_sga_rows[id].value));

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;
    return CT_SUCCESS;
}

#ifndef WIN32
#include <sys/param.h>

/* ----------
 * Macros of the os statistic file system path.
 * ----------
 */
#define JIFFIES_GET_CENTI_SEC(x) ((x) * (100 / HZ))
#define PROC_PATH_MAX 4096
#define VM_STAT_FILE_READ_BUF 4096
#define SYS_FILE_SYS_PATH "/sys/devices/system"
#define SYS_CPU_PATH "/sys/devices/system/cpu/cpu%u"
#define THR_SIBLING_FILE "/sys/devices/system/cpu/cpu0/topology/thread_siblings"
#define CORE_SIBLING_FILE "/sys/devices/system/cpu/cpu0/topology/core_siblings"
/*
 * this is used to represent the numbers of cpu time we should read from file.BUSY_TIME will be
 * calculate by USER_TIME plus SYS_TIME,so it wouldn't be counted.
 */
#define NUM_OF_CPU_TIME_READS (AVG_IDLE_TIME - IDLE_TIME)
/*
 * we calculate cpu numbers from sysfs, so we should make sure we can access this file system.
 */
static bool32 check_sys_file_system(void)
{
    /* Read through sysfs. */
    if (access(SYS_FILE_SYS_PATH, F_OK)) {
        return CT_FALSE;
    }

    if (access(THR_SIBLING_FILE, F_OK)) {
        return CT_FALSE;
    }

    if (access(CORE_SIBLING_FILE, F_OK)) {
        return CT_FALSE;
    }

    return CT_TRUE;
}

/*
 * check whether the SYS_CPU_PATH is accessable.one accessable path represented one logical cpu.
 */
static bool32 check_logical_cpu(uint32 cpuNum)
{
    char pathbuf[PROC_PATH_MAX] = "";
    int iret_snprintf;

    iret_snprintf = snprintf_s(pathbuf, PROC_PATH_MAX, PROC_PATH_MAX - 1, SYS_CPU_PATH, cpuNum);
    if (iret_snprintf == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, iret_snprintf);
    }
    return access(pathbuf, F_OK) == 0;
}
/* count the set bit in a mapping file */
#define pg_isxdigit(c)                                                               \
    (((c) >= (int)'0' && (c) <= (int)'9') || ((c) >= (int)'a' && (c) <= (int)'f') || \
        ((c) >= (int)'A' && (c) <= (int)'F'))
static uint32 parse_sibling_file(const char *path)
{
    int c;
    uint32 result = 0;
    char s[2];
    FILE *fp = NULL;
    union {
        uint32 a : 4;
        struct {
            uint32 a1 : 1;
            uint32 a2 : 1;
            uint32 a3 : 1;
            uint32 a4 : 1;
        } b;
    } d;
    fp = fopen(path, "r");
    if (fp != NULL) {
        c = fgetc(fp);
        while (c != EOF) {
            if (pg_isxdigit(c)) {
                s[0] = c;
                s[1] = '\0';
                d.a = strtoul(s, NULL, 16);
                result += d.b.a1;
                result += d.b.a2;
                result += d.b.a3;
                result += d.b.a4;
            }
            c = fgetc(fp);
        }
        fclose(fp);
    }

    return result;
}

/*
 * This function is to get the number of logical cpus, cores and physical cpus of the system.
 * We get these infomation by analysing sysfs file system. If we failed to get the three fields,
 * we just ignore them when we report. And if we got this field, we will not analyse the files
 * when we call this function next time.
 *
 * Note: This function must be called before getCpuTimes because we need logical cpu number
 * to calculate the avg cpu consumption.
 */
static void get_cpu_nums(void)
{
    uint32 cpuNum = 0;
    uint32 threadPerCore = 0;
    uint32 threadPerSocket = 0;

    /* if we have already got the cpu numbers. it's not necessary to read the files again. */
    if (g_instance->os_rinfo[NUM_CPUS].desc->got && g_instance->os_rinfo[NUM_CPU_CORES].desc->got &&
        g_instance->os_rinfo[NUM_CPU_SOCKETS].desc->got) {
        return;
    }

    /* if the sysfs file system is not accessable. we can't get the cpu numbers. */
    if (check_sys_file_system()) {
        /* check the SYS_CPU_PATH, one accessable path represented one logical cpu. */
        while (check_logical_cpu(cpuNum)) {
            cpuNum++;
        }

        if (cpuNum > 0) {
            /* cpu numbers */
            g_instance->os_rinfo[NUM_CPUS].int32_val = cpuNum;
            g_instance->os_rinfo[NUM_CPUS].desc->got = CT_TRUE;

            /*
            parse the mapping files ThreadSiblingFile and CoreSiblingFile.
            if we failed open the file or read wrong data, we just ignore this field.
            */
            threadPerCore = parse_sibling_file(THR_SIBLING_FILE);
            if (threadPerCore > 0) {
                /* core numbers */
                g_instance->os_rinfo[NUM_CPU_CORES].int32_val = cpuNum / threadPerCore;
                g_instance->os_rinfo[NUM_CPU_CORES].desc->got = CT_TRUE;
            }

            threadPerSocket = parse_sibling_file(CORE_SIBLING_FILE);
            if (threadPerSocket > 0) {
                /* socket numbers */
                g_instance->os_rinfo[NUM_CPU_SOCKETS].int32_val = cpuNum / threadPerSocket;
                g_instance->os_rinfo[NUM_CPU_SOCKETS].desc->got = CT_TRUE;
            }
        }
    }
}

static void get_os_run_load(void)
{
    char *loadAvgPath = "/proc/loadavg";
    FILE *fd = NULL;
    size_t len = 0;
    g_instance->os_rinfo[RUNLOAD].desc->got = CT_FALSE;

    /* reset the member "got" of osStatDescArray to false */
    /* open the /proc/loadavg file. */
    fd = fopen(loadAvgPath, "r");
    if (fd != NULL) {
        char line[CT_PROC_LOAD_BUF_SIZE];
        /* get the first line of the file and read the first number of the line. */
        len = CT_PROC_LOAD_BUF_SIZE;
        if (fgets(line, len, fd) != NULL) {
            g_instance->os_rinfo[RUNLOAD].float8_val = strtod(line, NULL);
            g_instance->os_rinfo[RUNLOAD].desc->got = CT_TRUE;
        }
        fclose(fd);
    }
}

/*
 * This function is to get the system cpu time consumption details. We read /proc/stat
 * file for this infomation. If we failed to get the ten fields, we just ignore them when we
 * report.
 * Note: Remember to call getCpuNums before this function.
 */
static void get_cpu_times(void)
{
    char *statPath = "/proc/stat";
    FILE *fd = NULL;
    size_t len = 0;
    uint64 readTime[NUM_OF_CPU_TIME_READS];
    char *temp = NULL;
    int i;

    /* reset the member "got" of osStatDescArray to false */
    MEMS_RETVOID_IFERR(memset_s(readTime, sizeof(readTime), 0, sizeof(readTime)));

    for (i = IDLE_TIME; i <= AVG_NICE_TIME; i++) {
        g_instance->os_rinfo[i].desc->got = CT_FALSE;
    }

    /* open /proc/stat file. */
    fd = fopen(statPath, "r");
    if (fd != NULL) {
        char line[CT_PROC_LOAD_BUF_SIZE];
        /* get the first line of the file and read the first number of the line. */
        len = CT_PROC_LOAD_BUF_SIZE;
        if (fgets(line, len, fd) != NULL) {
            /* get the second to sixth word of the line. */
            temp = line + sizeof("cpu");
            for (i = 0; i < NUM_OF_CPU_TIME_READS; i++) {
                readTime[i] = strtoul(temp, &temp, 10);
            }
            /* convert the jiffies time to centi-sec. for busy time, it equals user time plus sys time */
            g_instance->os_rinfo[USER_TIME].int64_val = JIFFIES_GET_CENTI_SEC(readTime[0]);
            g_instance->os_rinfo[NICE_TIME].int64_val = JIFFIES_GET_CENTI_SEC(readTime[1]);
            g_instance->os_rinfo[SYS_TIME].int64_val = JIFFIES_GET_CENTI_SEC(readTime[2]);
            g_instance->os_rinfo[IDLE_TIME].int64_val = JIFFIES_GET_CENTI_SEC(readTime[3]);
            g_instance->os_rinfo[IOWAIT_TIME].int64_val = JIFFIES_GET_CENTI_SEC(readTime[4]);
            g_instance->os_rinfo[BUSY_TIME].int64_val = JIFFIES_GET_CENTI_SEC(readTime[5]);

            /* as we have already got the cpu times, we set the "got" to true. */
            for (i = IDLE_TIME; i <= NICE_TIME; i++) {
                g_instance->os_rinfo[i].desc->got = CT_TRUE;
            }

            /* if the cpu numbers have been got, we can calculate the avg cpu times and set the "got" to true. */
            if (g_instance->os_rinfo[NUM_CPUS].desc->got) {
                uint32 cpu_nums = g_instance->os_rinfo[NUM_CPUS].int32_val;
                g_instance->os_rinfo[AVG_USER_TIME].int64_val = g_instance->os_rinfo[USER_TIME].int64_val / cpu_nums;
                g_instance->os_rinfo[AVG_NICE_TIME].int64_val = g_instance->os_rinfo[NICE_TIME].int64_val / cpu_nums;
                g_instance->os_rinfo[AVG_SYS_TIME].int64_val = g_instance->os_rinfo[SYS_TIME].int64_val / cpu_nums;
                g_instance->os_rinfo[AVG_IDLE_TIME].int64_val = g_instance->os_rinfo[IDLE_TIME].int64_val / cpu_nums;
                g_instance->os_rinfo[AVG_IOWAIT_TIME].int64_val =
                    g_instance->os_rinfo[IOWAIT_TIME].int64_val / cpu_nums;
                g_instance->os_rinfo[AVG_BUSY_TIME].int64_val = g_instance->os_rinfo[BUSY_TIME].int64_val / cpu_nums;

                for (i = AVG_IDLE_TIME; i <= AVG_NICE_TIME; i++) {
                    g_instance->os_rinfo[i].desc->got = CT_TRUE;
                }
            }
        }
        fclose(fd);
    }
}

/*
 * This function is to get the system virtual memory paging infomation (actually it will
 * get how many bytes paged in/out due to virtual memory paging). We read /proc/vmstat
 * file for this infomation. If we failed to get the two fields, we just ignore them when
 * we report.
 */
static void get_vm_stat(void)
{
    char *vmStatPath = "/proc/vmstat";
    int fd = -1;
    int ret;
    int len;
    char buffer[VM_STAT_FILE_READ_BUF + 1];
    char *temp = NULL;
    uint64 inPages = 0;
    uint64 outPages = 0;
    uint64 pageSize = sysconf(_SC_PAGE_SIZE);

    /* reset the member "got" of osStatDescArray to false */
    g_instance->os_rinfo[VM_PAGE_IN_BYTES].desc->got = CT_FALSE;
    g_instance->os_rinfo[VM_PAGE_OUT_BYTES].desc->got = CT_FALSE;

    /* open /proc/vmstat file. */
    fd = open(vmStatPath, O_RDONLY, 0);
    if (fd >= 0) {
        /* read the file to local buffer. */
        len = read(fd, buffer, VM_STAT_FILE_READ_BUF);
        if (len > 0) {
            buffer[len] = '\0';
            /* find the pgpgin and pgpgout field. if failed, we just ignore this field */
            temp = strstr(buffer, "pswpin");
            if (temp != NULL) {
                temp += sizeof("pswpin");
                inPages = strtoul(temp, NULL, 10);
                if (inPages < ULONG_MAX / pageSize) {
                    g_instance->os_rinfo[VM_PAGE_IN_BYTES].int64_val = inPages * pageSize;
                    g_instance->os_rinfo[VM_PAGE_IN_BYTES].desc->got = CT_TRUE;
                }
            }

            temp = strstr(buffer, "pswpout");
            if (temp != NULL) {
                temp += sizeof("pswpout");
                outPages = strtoul(temp, NULL, 10);
                if (outPages < ULONG_MAX / pageSize) {
                    g_instance->os_rinfo[VM_PAGE_OUT_BYTES].int64_val = outPages * pageSize;
                    g_instance->os_rinfo[VM_PAGE_OUT_BYTES].desc->got = CT_TRUE;
                }
            }
        }
        ret = close(fd);
        if (ret != 0) {
            CT_LOG_RUN_ERR("failed to close file with handle %d, error code %d", fd, errno);
        }
    }
}

/*
 * This function is to get the total physical memory size of the system. We read /proc/meminfo
 * file for this infomation. If we failed to get this field, we just ignore it when we report. And if
 * if we got this field, we will not read the file when we call this function next time.
 */
void get_total_mem(void)
{
    char *memInfoPath = "/proc/meminfo";
    FILE *fd = NULL;
    char line[CT_PROC_LOAD_BUF_SIZE + 1];
    char *temp = NULL;
    uint64 ret = 0;
    size_t len = CT_PROC_LOAD_BUF_SIZE;

    /* if we have already got the physical memory size. it's not necessary to read the files again. */
    if (g_instance->os_rinfo[PHYSICAL_MEMORY_BYTES].desc->got) {
        return;
    }

    /* open /proc/meminfo file. */
    fd = fopen(memInfoPath, "r");
    if (fd != NULL) {
        /* read the file to local buffer. */
        if (fgets(line, len, fd) != NULL) {
            temp = line + sizeof("MemTotal:");
            ret = strtoul(temp, NULL, 10);
            if (ret < ULONG_MAX / 1024) {
                g_instance->os_rinfo[PHYSICAL_MEMORY_BYTES].int64_val = ret * 1024;
                g_instance->os_rinfo[PHYSICAL_MEMORY_BYTES].desc->got = CT_TRUE;
            }
        }
        fclose(fd);
    }
}

#endif

static status_t vw_system_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    uint64 id;
    row_assist_t ra;

    id = cursor->rowid.vmid;
    if (id >= VM_SYSTEM_ROWS) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }
    if (id == 0) {
#ifndef WIN32
        get_cpu_nums();
        get_cpu_times();
        get_vm_stat();
        get_total_mem();
        get_os_run_load();
#else
        // WE NEED TO FETCH IN WINDOWS
#endif
    }
    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, SYSTEM_COLS);
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)id));
    CT_RETURN_IFERR(row_put_str(&ra, g_instance->os_rinfo[id].desc->name));

    if (g_instance->os_rinfo[id].desc->got == CT_TRUE) {
        char value[CT_MAX_NUMBER_LEN];

        switch (id) {
            case NUM_CPUS:
            case NUM_CPU_CORES:
            case NUM_CPU_SOCKETS:

                PRTS_RETURN_IFERR(sprintf_s(value, CT_MAX_NUMBER_LEN, "%u", g_instance->os_rinfo[id].int32_val));
                CT_RETURN_IFERR(row_put_str(&ra, value));
                break;

            case RUNLOAD:
                PRTS_RETURN_IFERR(sprintf_s(value, CT_MAX_NUMBER_LEN, "%lf", g_instance->os_rinfo[id].float8_val));
                CT_RETURN_IFERR(row_put_str(&ra, value));
                break;
            default:
                PRTS_RETURN_IFERR(sprintf_s(value, CT_MAX_NUMBER_LEN, "%llu", g_instance->os_rinfo[id].int64_val));
                CT_RETURN_IFERR(row_put_str(&ra, value));
                break;
        }
    } else {
        CT_RETURN_IFERR(row_put_null(&ra));
    }

    CT_RETURN_IFERR(row_put_str(&ra, g_instance->os_rinfo[id].desc->comments));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)g_instance->os_rinfo[id].desc->comulative));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);

    cursor->rowid.vmid++;
    return CT_SUCCESS;
}

static status_t vw_temp_pool_fetch(knl_handle_t se, knl_cursor_t *cursor)
{
    uint64 id;
    uint32 count;
    row_assist_t ra;
    vm_pool_t *pool = NULL;
    knl_session_t *session = (knl_session_t *)se;

    id = cursor->rowid.vmid;

    if (id >= session->kernel->temp_ctx_count) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    pool = &session->kernel->temp_pool[id];

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, TEMP_POOL_COLS);
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)id));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)(pool->map_count * VM_CTRLS_PER_PAGE)));

    count = pool->free_ctrls.count;
    count += pool->map_count * VM_CTRLS_PER_PAGE - pool->ctrl_hwm;
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)count));
    CT_RETURN_IFERR(row_put_int32(&ra, CT_VMEM_PAGE_SIZE));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)pool->page_count));

    count = pool->free_pages.count + pool->page_count - pool->page_hwm;
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)count));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)pool->page_hwm));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)pool->free_pages.count));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)vm_close_page_cnt(pool)));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)pool->get_swap_extents));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)pool->swap_count));
    CT_RETURN_IFERR(
        row_put_int32(&ra, (int32)((SPACE_GET(session, dtc_my_ctrl(session)->swap_space))->head->free_extents.count)));
    CT_RETURN_IFERR(row_put_int32(&ra, (int32)pool->max_swap_count));

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;
    return CT_SUCCESS;
}

static status_t vw_vm_func_stack_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    row_assist_t ra;
    vm_func_stack_t *func_stack = NULL;
    vm_pool_t *pool = NULL;

    if (g_vm_max_stack_count == 0) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    for (; cursor->rowid.vmid < g_vm_max_stack_count; cursor->rowid.vmid++) {
        pool = &((knl_session_t *)session)->kernel->temp_pool[cursor->rowid.vm_slot];
        if (pool->func_stacks == NULL) {
            continue;
        }
        cm_spin_lock(&pool->lock, NULL);
        func_stack = pool->func_stacks[cursor->rowid.vmid];
        if (func_stack == NULL || (func_stack->stack[0] == '\0' && func_stack->ref_count == 0)) {
            cm_spin_unlock(&pool->lock);
            continue;
        }

        row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, VM_FUNC_STACK_COLS);
        if (row_put_str(&ra, func_stack->stack) != CT_SUCCESS) {
            cm_spin_unlock(&pool->lock);
            return CT_ERROR;
        }
        if (row_put_int32(&ra, (int32)func_stack->ref_count) != CT_SUCCESS) {
            cm_spin_unlock(&pool->lock);
            return CT_ERROR;
        }

        cm_spin_unlock(&pool->lock);

        cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
        cursor->rowid.vmid++;
        cm_spin_unlock(&pool->lock);
        return CT_SUCCESS;
    }

    cursor->eof = CT_TRUE;
    return CT_SUCCESS;
}

typedef struct st_sga_stat_row {
    char *area;
    char *pool;
    char *name;
    char value[SGA_VALUE_BUFFER_LEN];
} sga_stat_row_t;

#define SGA_STAT_NULL_COL "-"

static sga_stat_row_t g_sga_stat_rows[] = {
    // shared area statistic
    { "shared area", SGA_STAT_NULL_COL, "page count",      { 0 } },
    { "shared area", SGA_STAT_NULL_COL, "page size",       { 0 } },
    { "shared area", SGA_STAT_NULL_COL, "page hwm",        { 0 } },
    { "shared area", SGA_STAT_NULL_COL, "free page count", { 0 } },

    // sql pool statistic
    { "shared area", "sql pool", "page count",           { 0 } },
    { "shared area", "sql pool", "page size",            { 0 } },
    { "shared area", "sql pool", "optimizer page count", { 0 } },
    { "shared area", "sql pool", "free page count",      { 0 } },
    { "shared area", "sql pool", "lru count",            { 0 } },
    { "shared area", "sql pool", "plsql lru count",      { 0 } },
    { "shared area", "sql pool", "plsql page count",     { 0 } },

    // dc pool
    { "shared area", "dc pool", "page count",           { 0 } },
    { "shared area", "dc pool", "page size",            { 0 } },
    { "shared area", "dc pool", "optimizer page count", { 0 } },
    { "shared area", "dc pool", "free page count",      { 0 } },

    // lock pool
    { "shared area", "lock pool", "page count",           { 0 } },
    { "shared area", "lock pool", "page size",            { 0 } },
    { "shared area", "lock pool", "optimizer page count", { 0 } },
    { "shared area", "lock pool", "free page count",      { 0 } },

    // lob pool
    { "shared area", "lob pool", "page count",           { 0 } },
    { "shared area", "lob pool", "page size",            { 0 } },
    { "shared area", "lob pool", "optimizer page count", { 0 } },
    { "shared area", "lob pool", "free page count",      { 0 } },

    // large pool statistic
    { SGA_STAT_NULL_COL, "large pool", "page count",           { 0 } },
    { SGA_STAT_NULL_COL, "large pool", "page size",            { 0 } },
    { SGA_STAT_NULL_COL, "large pool", "optimizer page count", { 0 } },
    { SGA_STAT_NULL_COL, "large pool", "free page count",      { 0 } },

    // variant memory area
    { "variant memory area", SGA_STAT_NULL_COL, "page count",      { 0 } },
    { "variant memory area", SGA_STAT_NULL_COL, "page size",       { 0 } },
    { "variant memory area", SGA_STAT_NULL_COL, "page hwm",        { 0 } },
    { "variant memory area", SGA_STAT_NULL_COL, "free page count", { 0 } },

    // large variant memory area
    { "large variant memory area", SGA_STAT_NULL_COL, "page count",      { 0 } },
    { "large variant memory area", SGA_STAT_NULL_COL, "page size",       { 0 } },
    { "large variant memory area", SGA_STAT_NULL_COL, "page hwm",        { 0 } },
    { "large variant memory area", SGA_STAT_NULL_COL, "free page count", { 0 } },

    // private memory area
    { "private memory area", SGA_STAT_NULL_COL, "page count",      { 0 } },
    { "private memory area", SGA_STAT_NULL_COL, "page size",       { 0 } },
    { "private memory area", SGA_STAT_NULL_COL, "page hwm",        { 0 } },
    { "private memory area", SGA_STAT_NULL_COL, "free page count", { 0 } },
};

#define SGA_STAT_ROW_COUNT (sizeof(g_sga_stat_rows) / sizeof(sga_stat_row_t))

static status_t vw_sga_stat_prepare_area(memory_area_t *area, uint32 *id)
{
    PRTS_RETURN_IFERR(
        snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u", area->page_count));
    ++(*id);

    PRTS_RETURN_IFERR(
        snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u", area->page_size));
    ++(*id);

    PRTS_RETURN_IFERR(
        snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u", area->page_hwm));
    ++(*id);

    PRTS_RETURN_IFERR(snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u",
        area->free_pages.count));
    ++(*id);
    return CT_SUCCESS;
}

static status_t vm_sga_stat_prepare_pool(memory_pool_t *pool, uint32 *id)
{
    PRTS_RETURN_IFERR(
        snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u", pool->page_count));
    ++(*id);
    PRTS_RETURN_IFERR(
        snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u", pool->page_size));
    ++(*id);
    PRTS_RETURN_IFERR(
        snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u", pool->opt_count));
    ++(*id);
    PRTS_RETURN_IFERR(snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u",
        pool->free_pages.count));
    ++(*id);
    return CT_SUCCESS;
}

static uint32 vw_sga_stat_get_pl_lru_page(pl_list_t *list)
{
    uint32 page_count = 0;
    bilist_node_t *node = NULL;
    pl_entity_t *entity = NULL;

    node = list->lst.head;
    while (node != NULL) {
        entity = (pl_entity_t *)BILIST_NODE_OF(pl_entity_t, node, lru_link);
        page_count += entity->memory->pages.count;
        node = BINODE_NEXT(node);
    }

    return page_count;
}

static status_t vw_sga_stat_prepare_pl(uint32 *id)
{
    pl_manager_t *mngr = GET_PL_MGR;
    pl_list_t *list = NULL;
    uint32 entity_count = 0;
    uint32 page_count = 0;
    int iret_snprintf;
    uint32 i;

    for (i = 0; i < PL_ENTITY_LRU_SIZE; i++) {
        list = &mngr->pl_entity_lru[i];
        cm_latch_s(&list->latch, CM_THREAD_ID, CT_FALSE, NULL);
        entity_count += list->lst.count;
        page_count += vw_sga_stat_get_pl_lru_page(list);
        cm_unlatch(&list->latch, NULL);
    }

    for (i = 0; i < PL_ANONY_LRU_SIZE; i++) {
        list = &mngr->anony_lru[i];
        cm_latch_s(&list->latch, CM_THREAD_ID, CT_FALSE, NULL);
        entity_count += list->lst.count;
        page_count += vw_sga_stat_get_pl_lru_page(list);
        cm_unlatch(&list->latch, NULL);
    }

    iret_snprintf =
        snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u", entity_count);
    if (iret_snprintf == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (iret_snprintf));
        return CT_ERROR;
    }
    ++(*id);

    iret_snprintf =
        snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u", page_count);
    if (iret_snprintf == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (iret_snprintf));
        return CT_ERROR;
    }
    ++(*id);

    return CT_SUCCESS;
}

static status_t vw_sga_lock_pool_stat(lock_area_t *lock_ctx, uint32 *id)
{
    uint32 free_pages;
    PRTS_RETURN_IFERR(snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u",
        lock_ctx->pool.page_count));
    ++(*id);
    PRTS_RETURN_IFERR(snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u",
        lock_ctx->pool.page_size));
    ++(*id);
    PRTS_RETURN_IFERR(snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u",
        lock_ctx->pool.opt_count));
    ++(*id);

    free_pages = (lock_ctx->capacity - lock_ctx->hwm + lock_ctx->free_items.count) / LOCK_PAGE_CAPACITY;
    PRTS_RETURN_IFERR(
        snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u", free_pages));
    ++(*id);
    return CT_SUCCESS;
}

static status_t vw_sga_lob_pool_stat(lob_area_t *lob_ctx, uint32 *id)
{
    uint32 free_pages;
    PRTS_RETURN_IFERR(snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u",
        lob_ctx->pool.page_count));
    ++(*id);
    PRTS_RETURN_IFERR(snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u",
        lob_ctx->pool.page_size));
    ++(*id);
    PRTS_RETURN_IFERR(snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u",
        lob_ctx->pool.opt_count));
    ++(*id);

    free_pages = (lob_ctx->capacity - lob_ctx->hwm + lob_ctx->free_items.count) / LOB_ITEM_PAGE_CAPACITY;
    PRTS_RETURN_IFERR(
        snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u", free_pages));
    ++(*id);
    return CT_SUCCESS;
}

static status_t vw_sga_stat_prepare(void)
{
    uint32 id = 0;

    // shared area
    CT_RETURN_IFERR(vw_sga_stat_prepare_area(&g_instance->sga.shared_area, &id));
    // sql pool
    context_pool_t *sql_pool_val = sql_pool;
    CT_RETURN_IFERR(vm_sga_stat_prepare_pool(sql_pool_val->memory, &id));

    PRTS_RETURN_IFERR(snprintf_s(g_sga_stat_rows[id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u",
        ctx_pool_get_lru_cnt(sql_pool_val)));
    ++id;

    // pl lru count and page count
    CT_RETURN_IFERR(vw_sga_stat_prepare_pl(&id));
    // dc pool
    CT_RETURN_IFERR(vm_sga_stat_prepare_pool(&g_instance->kernel.dc_ctx.pool, &id));
    // lock pool
    CT_RETURN_IFERR(vw_sga_lock_pool_stat(&g_instance->kernel.lock_ctx, &id));
    // lob pool
    CT_RETURN_IFERR(vw_sga_lob_pool_stat(&g_instance->kernel.lob_ctx, &id));
    // large pool statistic
    CT_RETURN_IFERR(vm_sga_stat_prepare_pool(&g_instance->sga.large_pool, &id));
    // small vma
    CT_RETURN_IFERR(vw_sga_stat_prepare_area(&g_instance->sga.vma.marea, &id));
    // large vma
    CT_RETURN_IFERR(vw_sga_stat_prepare_area(&g_instance->sga.vma.large_marea, &id));
    // private area
    CT_RETURN_IFERR(vw_sga_stat_prepare_area(&g_instance->sga.pma.marea, &id));
    CM_ASSERT(id == SGA_STAT_ROW_COUNT);
    return CT_SUCCESS;
}

static status_t vw_sga_stat_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    uint64 id;
    row_assist_t ra;

    id = cursor->rowid.vmid;
    if (id >= SGA_STAT_ROW_COUNT) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    if (id == 0) {
        cm_spin_lock(&g_sga_lock, NULL);
        if (vw_sga_stat_prepare() != CT_SUCCESS) {
            cm_spin_unlock(&g_sga_lock);
            return CT_ERROR;
        }
        cm_spin_unlock(&g_sga_lock);
    }

    row_init(&ra, (char *)cursor->row, CT_MAX_ROW_SIZE, SGA_STAT_COLS);
    CT_RETURN_IFERR(row_put_str(&ra, g_sga_stat_rows[id].area));
    CT_RETURN_IFERR(row_put_str(&ra, g_sga_stat_rows[id].pool));
    CT_RETURN_IFERR(row_put_str(&ra, g_sga_stat_rows[id].name));
    CT_RETURN_IFERR(row_put_str(&ra, g_sga_stat_rows[id].value));

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid++;
    return CT_SUCCESS;
}

static inline status_t vw_sqlarea_row_put_vm_ctx(row_assist_t *row, vw_sqlarea_assist_t *assist)
{
    int64 cpu_time;
    sql_context_t *vw_ctx = &assist->vw_ctx;
    CT_RETURN_IFERR(row_put_text(row, (text_t *)cs_get_login_client_name((client_kind_t)vw_ctx->module_kind)));
    CT_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.io_wait_time));
    CT_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.con_wait_time));
    cpu_time = (int64)(vw_ctx->stat.elapsed_time - vw_ctx->stat.io_wait_time - vw_ctx->stat.con_wait_time
        ) -
        vw_ctx->stat.dcs_wait_time;
    if (cpu_time < 0) {
        cpu_time = 0;
    }
    CT_RETURN_IFERR(row_put_int64(row, cpu_time));
    CT_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.elapsed_time));
    CT_RETURN_IFERR(row_put_date(row, vw_ctx->stat.last_load_time));    /* last_load_time */
    CT_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.proc_oid));  /* program_id */
    CT_RETURN_IFERR(row_put_int32(row, (int32)vw_ctx->stat.proc_line)); /* program_line# */
    CT_RETURN_IFERR(row_put_date(row, vw_ctx->stat.last_active_time));  /* last_active_time */
    CT_RETURN_IFERR(row_put_int32(row, (int32)assist->ref_count));
    CT_RETURN_IFERR(row_put_int32(row, (int32)vw_ctx->ctrl.is_free));
    CT_RETURN_IFERR(row_put_int32(row, (int32)vw_ctx->ctrl.cleaned));
    CT_RETURN_IFERR(row_put_int32(row, (int32)assist->pages));
    CT_RETURN_IFERR(row_put_int32(row, (int32)vw_ctx->ctrl.valid));
    if (assist->pages > 1) {
        CT_RETURN_IFERR(
            row_put_int64(row, (int64)(((int64)assist->pages - 1) * CT_SHARED_PAGE_SIZE + assist->alloc_pos)));
    } else {
        CT_RETURN_IFERR(row_put_int64(row, (int64)assist->alloc_pos));
    }
    CT_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.vm_stat.open_pages));
    CT_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.vm_stat.close_pages));
    CT_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.vm_stat.swap_in_pages));
    CT_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.vm_stat.free_pages));
    CT_RETURN_IFERR(row_put_int64(row, 0));

    if (IS_COORDINATOR && assist->pdown_sql_id.len > 0) {
        CT_RETURN_IFERR(row_put_text(row, &assist->pdown_sql_id)); /* pdown_sql_id */
    } else {
        CT_RETURN_IFERR(row_put_null(row));
    }
    CT_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.vm_stat.alloc_pages));
    CT_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.vm_stat.max_open_pages));
    CT_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.vm_stat.swap_out_pages));

    return CT_SUCCESS;
}

static inline status_t vw_sqlarea_row_put(knl_handle_t session, row_assist_t *row, vw_sqlarea_assist_t *assist)
{
    int32 errcode;
    char hash_valstr[CT_MAX_UINT32_STRLEN + 1], username_buf[CT_MAX_NAME_LEN + 1];
    text_t parse_username = {
        .str = username_buf,
        .len = 0
    };
    sql_context_t *vw_ctx = &assist->vw_ctx;
    if (assist->sql_text.len > 0) {
        CT_RETURN_IFERR(row_put_text(row, &assist->sql_text));
    } else {
        CT_RETURN_IFERR(row_put_null(row));
    }

    PRTS_RETURN_IFERR(sprintf_s(hash_valstr, (CT_MAX_UINT32_STRLEN + 1), "%010u", assist->sql_hash));
    CT_RETURN_IFERR(row_put_str(row, hash_valstr)); /* sql_id */
    CT_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.executions));
    CT_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.disk_reads));
    CT_RETURN_IFERR(row_put_int64(row, (int64)(vw_ctx->stat.buffer_gets + vw_ctx->stat.cr_gets)));
    CT_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.cr_gets));
    CT_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.sorts));
    CT_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.parse_time));
    CT_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.parse_calls));
    CT_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.processed_rows));
    CT_RETURN_IFERR(row_put_int32(row, (int32)vw_ctx->ctrl.uid)); /* parsing user id */

    if (knl_get_user_name(session, vw_ctx->ctrl.uid, &parse_username) != CT_SUCCESS) {
        const char *err_message = NULL;
        cm_get_error(&errcode, &err_message, NULL);
        CT_RETVALUE_IFTRUE(errcode != (int32)ERR_USER_NOT_EXIST, CT_ERROR);

        /*
         * we would like to keep the size of sql_context_t as little as possible.
         * so we didn't save the original user name when the sql_context_t created while the sql first hard-parsed.
         * however, when we tried to get the user name with the saved user id via knl_get_user_nmae() here,
         * the knl_get_user_name() might return an error when the user id already dropped.
         * we don't want an error here, so we ignore the error ERR_USER_NOT_EXIST
         * and fill the name with a fixed string under that circumstance
         */
        static const text_t dropped_user_const = {
            .str = "DROPPED USER",
            .len = 12
        };
        parse_username = dropped_user_const;
        cm_reset_error();
    }
    CT_RETURN_IFERR(row_put_text(row, &parse_username)); /* parsing user name */
    CT_RETURN_IFERR(vw_sqlarea_row_put_vm_ctx(row, assist));
    CT_RETURN_IFERR(row_put_int64(row, (int64)(vw_ctx->stat.dcs_buffer_gets + vw_ctx->stat.dcs_cr_gets)));
    CT_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.dcs_cr_gets));
    CT_RETURN_IFERR(row_put_int64(row, (int64)vw_ctx->stat.dcs_wait_time));
    return CT_SUCCESS;
}

static status_t vw_sqlarea_save_assist(context_ctrl_t *ctrl, char *sql_copy, vw_sqlarea_assist_t *assist)
{
    uint32 total_len = 0;
    assist->pdown_sql_id.len = 0;
    assist->vw_ctx = *((sql_context_t *)ctrl);
    assist->pages = ctrl->memory->pages.count;
    assist->alloc_pos = ctrl->memory->alloc_pos;
    assist->sql_hash = ctrl->hash_value;
    assist->ref_count = ctrl->ref_count;

    // save sql text
    ctx_read_first_page_text(sql_pool, &assist->vw_ctx.ctrl, &assist->sql_text);
    if (cm_text2str(&assist->sql_text, sql_copy, CT_MAX_COLUMN_SIZE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    assist->sql_text.str = sql_copy;
    assist->sql_text.len = (uint32)strlen(sql_copy);

    // save sql push down hash id
    if (IS_COORDINATOR && ctrl->pdown_sql_id != NULL) {
        for (uint32 i = 0; i < ctrl->pdown_sql_id->count && i < SGA_MAX_SQL_ID_NUM; i++) {
            if (total_len + SGA_SQL_ID_LEN >= SGA_PDOWN_BUFFER_LEN) {
                break;
            }
            uint32 *hash_value = (uint32 *)cm_galist_get(ctrl->pdown_sql_id, i);
            PRTS_RETURN_IFERR(sprintf_s(assist->pdown_sql_buffer + total_len, (SGA_PDOWN_BUFFER_LEN - total_len),
                "%010u", *hash_value));
            assist->pdown_sql_buffer[total_len + SGA_SQL_ID_LEN] = ',';
            total_len = total_len + SGA_SQL_ID_LEN + 1;
        }
    }
    if (total_len > 0) {
        assist->pdown_sql_id.str = assist->pdown_sql_buffer;
        assist->pdown_sql_id.len = total_len - 1;
    }
    return CT_SUCCESS;
}

static status_t vw_sqlarea_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    row_assist_t row;
    uint64 id = cursor->rowid.vmid;
    context_ctrl_t *ctrl = NULL;
    char *sql_copy = NULL;
    sql_stmt_t *stmt = ((session_t *)session)->current_stmt;
    vw_sqlarea_assist_t assist;

    CTSQL_SAVE_STACK(stmt);
    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_COLUMN_SIZE, (void **)&sql_copy));

    while (id < (sql_pool)->map->hwm) {
        if (ctx_get(g_instance->sql.pool, (uint32)id) == NULL) {
            ++id;
            continue;
        }

        cm_spin_lock(&sql_pool->lock, NULL);
        ctrl = ctx_get(g_instance->sql.pool, (uint32)id);
        if (ctrl != NULL) {
            if (vw_sqlarea_save_assist(ctrl, sql_copy, &assist) != CT_SUCCESS) {
                cm_spin_unlock(&sql_pool->lock);
                CTSQL_RESTORE_STACK(stmt);
                return CT_ERROR;
            }
            cm_spin_unlock(&sql_pool->lock);
            break;
        }
        cm_spin_unlock(&sql_pool->lock);
        ++id;
    }

    if (id >= (sql_pool)->map->hwm) {
        CTSQL_RESTORE_STACK(stmt);
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }

    row_init(&row, (char *)cursor->row, CT_MAX_ROW_SIZE, SQLAREA_COLS);
    if (vw_sqlarea_row_put(session, &row, &assist) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
    cursor->rowid.vmid = (++id);
    CTSQL_RESTORE_STACK(stmt);

    return CT_SUCCESS;
}

static void vw_plarea_save_assist(pl_entity_t *entity, vw_sqlarea_assist_t *assist)
{
    sql_context_t *sql_ctx = entity->context;
    memory_context_t *mem_ctx = entity->memory;
    anonymous_desc_t *desc = &entity->anonymous->desc;

    assist->pdown_sql_id.len = 0;
    assist->vw_ctx = *sql_ctx;
    assist->pages = mem_ctx->pages.count;
    assist->alloc_pos = mem_ctx->alloc_pos;
    assist->sql_text = desc->sql;
    assist->sql_hash = desc->sql_hash;
    assist->ref_count = entity->ref_count;
}

static status_t vw_plarea_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    pl_manager_t *mngr = GET_PL_MGR;
    pl_entity_t *entity = NULL;
    pl_list_t *list = NULL;
    bilist_node_t *node = NULL;
    row_assist_t row;
    sql_stmt_t *stmt = ((session_t *)session)->current_stmt;
    uint32 bucketid = (uint32)cursor->rowid.vm_slot;
    uint32 position = (uint32)cursor->rowid.vmid;
    vw_sqlarea_assist_t assist;
    status_t status = CT_ERROR;

    while (CT_TRUE) {
        if (bucketid >= PL_ANONY_LRU_SIZE) {
            cursor->eof = CT_TRUE;
            return CT_SUCCESS;
        }

        list = &mngr->anony_lru[bucketid];
        if (list->lst.count <= position) {
            bucketid++;
            position = 0;
            continue;
        }
        cm_latch_s(&list->latch, CM_THREAD_ID, CT_FALSE, NULL);
        if (list->lst.count <= position) {
            cm_unlatch(&list->latch, NULL);
            bucketid++;
            position = 0;
            continue;
        }
        break;
    }
    node = cm_bilist_get(&list->lst, position);
    CM_ASSERT(node != NULL);
    entity = BILIST_NODE_OF(pl_entity_t, node, lru_link);

    CTSQL_SAVE_STACK(stmt);
    do {
        vw_plarea_save_assist(entity, &assist);
        row_init(&row, (char *)cursor->row, CT_MAX_ROW_SIZE, SQLAREA_COLS);
        CT_BREAK_IF_ERROR(vw_sqlarea_row_put(session, &row, &assist));
        cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);
        status = CT_SUCCESS;
    } while (CT_FALSE);
    CTSQL_RESTORE_STACK(stmt);
    cm_unlatch(&list->latch, NULL);

    position++;
    cursor->rowid.vm_slot = (uint64)bucketid;
    cursor->rowid.vmid = (uint64)position;
    return status;
}

static inline status_t vm_sqlpool_row_put(sql_stmt_t *stmt, row_assist_t *row, sql_context_t *vm_ctx,
    memory_context_t *mctx, text_t *pagelist)
{
    int32 err_no;
    text_t hash_id;

    CT_RETURN_IFERR(sql_push(stmt, 24, (void **)&hash_id.str)); // 24 bytes
    // put hash id
    err_no = sprintf_s(hash_id.str, (CT_MAX_UINT32_STRLEN + 1), "%010u", vm_ctx->ctrl.hash_value);
    if (err_no == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (err_no));
        return CT_ERROR;
    }

    hash_id.len = (uint32)err_no;
    CT_RETURN_IFERR(row_put_text(row, &hash_id)); /* sql_id */

    // put ctrl info
    CT_RETURN_IFERR(row_put_int32(row, (int32)vm_ctx->type));
    CT_RETURN_IFERR(row_put_int32(row, (int32)vm_ctx->ctrl.uid));
    CT_RETURN_IFERR(row_put_int32(row, (int32)vm_ctx->ctrl.ref_count));
    CT_RETURN_IFERR(row_put_bool(row, (int32)vm_ctx->ctrl.valid));
    CT_RETURN_IFERR(row_put_bool(row, (int32)vm_ctx->ctrl.cleaned));
    CT_RETURN_IFERR(row_put_bool(row, (int32)vm_ctx->ctrl.is_free));

    // put pages infos
    CT_RETURN_IFERR(row_put_int32(row, (int32)mctx->pages.count));
    CT_RETURN_IFERR(row_put_int32(row, (int32)mctx->pages.first));
    CT_RETURN_IFERR(row_put_int32(row, (int32)mctx->pages.last));
    CT_RETURN_IFERR(row_put_int32(row, (int32)mctx->curr_page_id));
    CT_RETURN_IFERR(row_put_text(row, pagelist));

    // put large page id
    if (vm_ctx->large_page_id == CT_INVALID_ID32) {
        CT_RETURN_IFERR(row_put_null(row));
    } else {
        CT_RETURN_IFERR(row_put_int32(row, (int32)vm_ctx->large_page_id));
    }

    // put the first-executable optimization information
    CT_RETURN_IFERR(row_put_int32(row, (int32)vm_ctx->fexec_vars_cnt));
    CT_RETURN_IFERR(row_put_int32(row, (int32)vm_ctx->fexec_vars_bytes));

    // put active time
    CT_RETURN_IFERR(row_put_date(row, vm_ctx->stat.last_load_time));
    CT_RETURN_IFERR(row_put_date(row, vm_ctx->stat.last_active_time));

    return CT_SUCCESS;
}

static status_t inline vw_format_mctx_pages(const memory_context_t *mctx, text_buf_t *txtbuf)
{
    if (mctx->pages.count == 0) {
        return CT_SUCCESS;
    }

    uint32 next_page = mctx->pages.first;

    if (next_page >= mctx->pool->opt_count) {
        (void)cm_buf_append_str(txtbuf, "invalid page");
        return CT_SUCCESS;
    }
    (void)cm_buf_append_fmt(txtbuf, "%u", next_page);

    for (uint32 i = 1; i < mctx->pages.count; i++) {
        // get the next page
        next_page = mctx->pool->maps[next_page];
        if (next_page >= mctx->pool->opt_count) {
            CT_RETURN_IFERR(cm_concat_string((text_t *)txtbuf, txtbuf->max_size, "->invalid page"));
            return CT_SUCCESS;
        }
        if (!cm_buf_append_fmt(txtbuf, "->%u", next_page)) {
            // the memory can not overflow, 20 bytes are reserved for situation
            CT_RETURN_IFERR(cm_concat_string((text_t *)txtbuf, txtbuf->max_size, "-> ..."));
            return CT_SUCCESS;
        }
    }

    return CT_SUCCESS;
}

static status_t vw_sqlpool_fetch_core(knl_handle_t session, knl_cursor_t *cursor)
{
    row_assist_t row;
    memory_context_t mctx;
    context_ctrl_t *ctrl = NULL;
    sql_context_t vm_ctx;
    sql_stmt_t *stmt = ((session_t *)session)->current_stmt;
    uint64 id = cursor->rowid.vmid;
    text_buf_t pagelist;
    dc_user_t *user = NULL;

    CTSQL_SAVE_STACK(stmt);

    CT_RETURN_IFERR(sql_push_textbuf(stmt, CT_MAX_COLUMN_SIZE, &pagelist));
    pagelist.max_size -= 20; // reserved 20 bytes for putting ending text

    while (id < (sql_pool)->map->hwm) {
        if (ctx_get(g_instance->sql.pool, (uint32)id) == NULL) {
            ++id;
            continue;
        }
        cm_spin_lock(&sql_pool->lock, NULL);
        ctrl = ctx_get(sql_pool, (uint32)id);
        if (ctrl != NULL) { // prefetching
            // Copy, avoid unstable ptr
            vm_ctx = *((sql_context_t *)ctrl);
            mctx = *vm_ctx.ctrl.memory;

            // to print the page list of mctx, the lock of memory pool is needed
            cm_spin_lock(&mctx.pool->lock, NULL);
            (void)vw_format_mctx_pages(&mctx, &pagelist);
            cm_spin_unlock(&mctx.pool->lock);

            cm_spin_unlock(&sql_pool->lock);
            break;
        }
        cm_spin_unlock(&sql_pool->lock);
        id++;
    }

    if (id >= (sql_pool)->map->hwm) {
        cursor->eof = CT_TRUE;
        CTSQL_RESTORE_STACK(stmt);
        return CT_SUCCESS;
    }

    row_init(&row, (char *)cursor->row, CT_MAX_ROW_SIZE, SQLPOOL_COLS);
    if (vm_sqlpool_row_put(stmt, &row, &vm_ctx, &mctx, (text_t *)&pagelist) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }
    CURSOR_SET_TENANT_ID_BY_USER(dc_open_user_by_id(&stmt->session->knl_session, vm_ctx.ctrl.uid, &user), cursor, user);
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);

    cursor->rowid.vmid = (++id);
    CTSQL_RESTORE_STACK(stmt);
    return CT_SUCCESS;
}

static status_t vw_sqlpool_fetch(knl_handle_t session, knl_cursor_t *cursor)
{
    return vw_fetch_for_tenant(vw_sqlpool_fetch_core, session, cursor);
}

static inline void vw_sql_plan_ctx_switch(knl_cursor_t *cursor, bool32 is_subctx)
{
    if (is_subctx) {
        cursor->rowid.vm_slot++;
    } else {
        cursor->rowid.vmid++;
        cursor->rowid.vm_slot = 0;
    }
}

static inline uint32 vw_sql_plan_ctx_id(knl_cursor_t *cursor, bool32 is_subctx)
{
    if (is_subctx) {
        return (uint32)cursor->rowid.vm_slot;
    }
    return (uint32)cursor->rowid.vmid;
}

VW_DECL dv_sga = { "SYS", "DV_GMA", SGA_COLS, g_sga_columns, vw_common_open, vw_sga_fetch };
VW_DECL dv_system = { "SYS", "DV_SYSTEM", SYSTEM_COLS, g_system_columns, vw_common_open, vw_system_fetch };
VW_DECL dv_temp_pool = {
    "SYS", "DV_TEMP_POOLS", TEMP_POOL_COLS, g_temp_pool_columns, vw_common_open, vw_temp_pool_fetch
};
VW_DECL dv_vm_func_stack = { "SYS",          "DV_VM_FUNC_STACK",    VM_FUNC_STACK_COLS, g_vm_func_stack_columns,
                             vw_common_open, vw_vm_func_stack_fetch };
VW_DECL dv_sqlarea = { "SYS", "DV_SQLS", SQLAREA_COLS, g_sqlarea_columns, vw_common_open, vw_sqlarea_fetch };
VW_DECL dv_anonymous = { "SYS", "DV_ANONYMOUS", SQLAREA_COLS, g_sqlarea_columns, vw_common_open, vw_plarea_fetch };
VW_DECL dv_sgastat = { "SYS", "DV_GMA_STATS", SGA_STAT_COLS, g_sga_stat_columns, vw_common_open, vw_sga_stat_fetch };
VW_DECL dv_sqlpool = { "SYS", "DV_SQL_POOL", SQLPOOL_COLS, g_sqlpool_columns, vw_common_open, vw_sqlpool_fetch };

dynview_desc_t *vw_describe_sga(uint32 id)
{
    switch ((dynview_id_t)id) {
        case DYN_VIEW_SGA:
            return &dv_sga;

        case DYN_VIEW_SYSTEM:
            return &dv_system;

        case DYN_VIEW_TEMP_POOL:
            return &dv_temp_pool;

        case DYN_VIEW_SQLAREA:
            return &dv_sqlarea;

        case DYN_VIEW_SGASTAT:
            return &dv_sgastat;

        case DYN_VIEW_VM_FUNC_STACK:
            return &dv_vm_func_stack;

        case DYN_VIEW_SQLPOOL:
            return &dv_sqlpool;

        case DYN_VIEW_PLAREA:
            return &dv_anonymous;

        default:
            return NULL;
    }
}

