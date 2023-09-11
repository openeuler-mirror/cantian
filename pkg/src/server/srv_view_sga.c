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
 * srv_view_sga.c
 *
 *
 * IDENTIFICATION
 * src/server/srv_view_sga.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_log.h"
#include "knl_context.h"
#include "srv_view_sga.h"
#include "srv_instance.h"
#include "srv_param.h"
#include "srv_query.h"
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
    { 0, "NAME", 0, 0, GS_TYPE_CHAR, SGA_VALUE_BUFFER_NAME, 0, 0, GS_FALSE, 0, { 0 } },
    { 1, "VALUE", 0, 0, GS_TYPE_CHAR, SGA_VALUE_BUFFER_LEN, 0, 0, GS_FALSE, 0, { 0 } },
};

static knl_column_t g_system_columns[] = {
    { 0, "ID",           0, 0, GS_TYPE_INTEGER, sizeof(uint32),    0, 0, GS_FALSE, 0, { 0 } },
    { 1, "NAME",         0, 0, GS_TYPE_VARCHAR, GS_MAX_NAME_LEN,   0, 0, GS_FALSE, 0, { 0 } },
    { 2, "VALUE",        0, 0, GS_TYPE_VARCHAR, GS_MAX_NUMBER_LEN, 0, 0, GS_TRUE,  0, { 0 } },
    { 3, "COMMENTS",     0, 0, GS_TYPE_VARCHAR, GS_COMMENT_SIZE,   0, 0, GS_FALSE, 0, { 0 } },
    { 4, "ACCUMULATIVE", 0, 0, GS_TYPE_BOOLEAN, sizeof(bool32),    0, 0, GS_FALSE, 0, { 0 } },
};

static knl_column_t g_temp_pool_columns[] = {
    { 0,  "ID",              0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, { 0 } },
    { 1,  "TOTAL_VIRTUAL",   0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, { 0 } },
    { 2,  "FREE_VIRTUAL",    0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, { 0 } },
    { 3,  "PAGE_SIZE",       0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, { 0 } },
    { 4,  "TOTAL_PAGES",     0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, { 0 } },
    { 5,  "FREE_PAGES",      0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, { 0 } },
    { 6,  "PAGE_HWM",        0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, { 0 } },
    { 7,  "FREE_LIST",       0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, { 0 } },
    { 8,  "CLOSED_LIST",     0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, { 0 } },
    { 9,  "DISK_EXTENTS",    0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, { 0 } },
    { 10, "SWAP_COUNT",      0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, { 0 } },
    { 11, "FREE_EXTENTS",    0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, { 0 } },
    { 12, "MAX_SWAP_COUNT",  0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_FALSE, 0, { 0 } },
};

static knl_column_t g_vm_func_stack_columns[] = {
    { 0, "FUNC_STACK", 0, 0, GS_TYPE_VARCHAR, GS_VM_FUNC_STACK_SIZE, 0, 0, GS_TRUE, 0, { 0 } },
    { 1, "REF_COUNT", 0, 0, GS_TYPE_INTEGER, sizeof(uint32), 0, 0, GS_TRUE, 0, { 0 } },
};

static knl_column_t g_sga_stat_columns[] = {
    { 0, "AREA", 0, 0, GS_TYPE_VARCHAR, 32, 0, 0, GS_FALSE, 0, { 0 } },
    { 1, "POOL", 0, 0, GS_TYPE_VARCHAR, 32, 0, 0, GS_FALSE, 0, { 0 } },
    { 2, "NAME", 0, 0, GS_TYPE_VARCHAR, 32, 0, 0, GS_FALSE, 0, { 0 } },
    { 3, "VALUE", 0, 0, GS_TYPE_VARCHAR, 32, 0, 0, GS_FALSE, 0, { 0 } },
};

#define SGA_COLS (sizeof(g_sga_columns) / sizeof(knl_column_t))
#define SYSTEM_COLS (sizeof(g_system_columns) / sizeof(knl_column_t))
#define TEMP_POOL_COLS (sizeof(g_temp_pool_columns) / sizeof(knl_column_t))
#define DIS_SQLAREA_COLS (sizeof(g_dis_sqlarea_columns) / sizeof(knl_column_t))
#define SGA_STAT_COLS (sizeof(g_sga_stat_columns) / sizeof(knl_column_t))

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

static bool32 g_sga_ready = GS_FALSE;

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
            GS_THROW_ERROR(ERR_SYSTEM_CALL, (iret_snprintf));                                                      \
            return GS_ERROR;                                                                                       \
        }                                                                                                          \
        (idx)++;                                                                                                   \
    } while (0)

status_t vw_sga_fetch(knl_handle_t session, knl_cursor_t *cur)
{
    uint64 id = cur->rowid.vmid;
    row_assist_t ra;
    knl_attr_t *attr = &((knl_session_t *)session)->kernel->attr;
    uint32 idx = 0;

    if (id >= SGA_ROW_COUNT) {
        cur->eof = GS_TRUE;
        return GS_SUCCESS;
    }

    if (!g_sga_ready) {
        cm_spin_lock(&g_sga_lock, NULL);

        if (!g_sga_ready) {
            g_sga_ready = GS_TRUE;
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

    row_init(&ra, (char *)cur->row, GS_MAX_ROW_SIZE, SGA_COLS);
    GS_RETURN_IFERR(row_put_str(&ra, g_sga_rows[id].name));
    GS_RETURN_IFERR(row_put_str(&ra, g_sga_rows[id].value));

    cm_decode_row((char *)cur->row, cur->offsets, cur->lens, &cur->data_size);
    cur->rowid.vmid++;
    return GS_SUCCESS;
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
        return GS_FALSE;
    }
    if (access(THR_SIBLING_FILE, F_OK)) {
        return GS_FALSE;
    }
    if (access(CORE_SIBLING_FILE, F_OK)) {
        return GS_FALSE;
    }
    return GS_TRUE;
}

/*
 * check whether the SYS_CPU_PATH is accessable.one accessable path represented one logical cpu.
 */
static bool32 check_logical_cpu(uint32 cpu_num)
{
    char pathbuf[PROC_PATH_MAX] = "";
    int iret_snprintf;

    iret_snprintf = snprintf_s(pathbuf, PROC_PATH_MAX, PROC_PATH_MAX - 1, SYS_CPU_PATH, cpu_num);
    if (iret_snprintf == -1) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, iret_snprintf);
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
            g_instance->os_rinfo[NUM_CPUS].desc->got = GS_TRUE;
            /*
            parse the mapping files ThreadSiblingFile and CoreSiblingFile.
            if we failed open the file or read wrong data, we just ignore this field.
            */
            threadPerCore = parse_sibling_file(THR_SIBLING_FILE);
            if (threadPerCore > 0) {
                /* core numbers */
                g_instance->os_rinfo[NUM_CPU_CORES].int32_val = cpuNum / threadPerCore;
                g_instance->os_rinfo[NUM_CPU_CORES].desc->got = GS_TRUE;
            }
            threadPerSocket = parse_sibling_file(CORE_SIBLING_FILE);
            if (threadPerSocket > 0) {
                /* socket numbers */
                g_instance->os_rinfo[NUM_CPU_SOCKETS].int32_val = cpuNum / threadPerSocket;
                g_instance->os_rinfo[NUM_CPU_SOCKETS].desc->got = GS_TRUE;
            }
        }
    }
}

static void get_os_run_load(void)
{
    char *loadAvgPath = "/proc/loadavg";
    FILE *fd = NULL;
    size_t len = 0;
    g_instance->os_rinfo[RUNLOAD].desc->got = GS_FALSE;

    /* reset the member "got" of osStatDescArray to false */
    /* open the /proc/loadavg file. */
    fd = fopen(loadAvgPath, "r");
    if (fd != NULL) {
        char line[GS_PROC_LOAD_BUF_SIZE];
        /* get the first line of the file and read the first number of the line. */
        len = GS_PROC_LOAD_BUF_SIZE;
        if (fgets(line, len, fd) != NULL) {
            g_instance->os_rinfo[RUNLOAD].float8_val = strtod(line, NULL);
            g_instance->os_rinfo[RUNLOAD].desc->got = GS_TRUE;
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
        g_instance->os_rinfo[i].desc->got = GS_FALSE;
    }

    /* open /proc/stat file. */
    fd = fopen(statPath, "r");
    if (fd != NULL) {
        char line[GS_PROC_LOAD_BUF_SIZE];
        /* get the first line of the file and read the first number of the line. */
        len = GS_PROC_LOAD_BUF_SIZE;
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
                g_instance->os_rinfo[i].desc->got = GS_TRUE;
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
                    g_instance->os_rinfo[i].desc->got = GS_TRUE;
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
    g_instance->os_rinfo[VM_PAGE_IN_BYTES].desc->got = GS_FALSE;
    g_instance->os_rinfo[VM_PAGE_OUT_BYTES].desc->got = GS_FALSE;

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
                    g_instance->os_rinfo[VM_PAGE_IN_BYTES].desc->got = GS_TRUE;
                }
            }

            temp = strstr(buffer, "pswpout");
            if (temp != NULL) {
                temp += sizeof("pswpout");
                outPages = strtoul(temp, NULL, 10);
                if (outPages < ULONG_MAX / pageSize) {
                    g_instance->os_rinfo[VM_PAGE_OUT_BYTES].int64_val = outPages * pageSize;
                    g_instance->os_rinfo[VM_PAGE_OUT_BYTES].desc->got = GS_TRUE;
                }
            }
        }
        ret = close(fd);
        if (ret != 0) {
            GS_LOG_RUN_ERR("failed to close file with handle %d, error code %d", fd, errno);
        }
    }
}

/*
 * This function is to get the total physical memory size of the system. We read /proc/meminfo
 * file for this infomation. If we failed to get this field, we just ignore it when we report. And if
 * if we got this field, we will not read the file when we call this function next time.
 */
void get_total_memory(void)
{
    char *memInfoPath = "/proc/meminfo";
    FILE *fd = NULL;
    char line[GS_PROC_LOAD_BUF_SIZE + 1];
    char *temp = NULL;
    uint64 ret = 0;
    size_t len = GS_PROC_LOAD_BUF_SIZE;

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
                g_instance->os_rinfo[PHYSICAL_MEMORY_BYTES].desc->got = GS_TRUE;
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
        cursor->eof = GS_TRUE;
        return GS_SUCCESS;
    }
    if (id == 0) {
#ifndef WIN32
        get_cpu_nums();
        get_cpu_times();
        get_vm_stat();
        get_total_memory();
        get_os_run_load();
#else
        // WE NEED TO FETCH IN WINDOWS
#endif
    }
    row_init(&ra, (char *)cursor->row, GS_MAX_ROW_SIZE, SYSTEM_COLS);
    GS_RETURN_IFERR(row_put_int32(&ra, (int32)id));
    GS_RETURN_IFERR(row_put_str(&ra, g_instance->os_rinfo[id].desc->name));

    if (g_instance->os_rinfo[id].desc->got == GS_TRUE) {
        char value[GS_MAX_NUMBER_LEN];

        switch (id) {
            case NUM_CPUS:
            case NUM_CPU_CORES:
            case NUM_CPU_SOCKETS:

                PRTS_RETURN_IFERR(sprintf_s(value, GS_MAX_NUMBER_LEN, "%u", g_instance->os_rinfo[id].int32_val));
                GS_RETURN_IFERR(row_put_str(&ra, value));
                break;

            case RUNLOAD:
                PRTS_RETURN_IFERR(sprintf_s(value, GS_MAX_NUMBER_LEN, "%lf", g_instance->os_rinfo[id].float8_val));
                GS_RETURN_IFERR(row_put_str(&ra, value));
                break;
            default:
                PRTS_RETURN_IFERR(sprintf_s(value, GS_MAX_NUMBER_LEN, "%llu", g_instance->os_rinfo[id].int64_val));
                GS_RETURN_IFERR(row_put_str(&ra, value));
                break;
        }
    } else {
        GS_RETURN_IFERR(row_put_null(&ra));
    }

    GS_RETURN_IFERR(row_put_str(&ra, g_instance->os_rinfo[id].desc->comments));
    GS_RETURN_IFERR(row_put_int32(&ra, (int32)g_instance->os_rinfo[id].desc->comulative));
    cm_decode_row((char *)cursor->row, cursor->offsets, cursor->lens, &cursor->data_size);

    cursor->rowid.vmid++;
    return GS_SUCCESS;
}

static status_t vw_temp_pool_fetch(knl_handle_t se, knl_cursor_t *cur)
{
    uint64 id;
    uint32 count;
    row_assist_t ra;
    vm_pool_t *pool = NULL;
    knl_session_t *session = (knl_session_t *)se;

    id = cur->rowid.vmid;

    if (id >= session->kernel->temp_ctx_count) {
        cur->eof = GS_TRUE;
        return GS_SUCCESS;
    }

    pool = &session->kernel->temp_pool[id];

    row_init(&ra, (char *)cur->row, GS_MAX_ROW_SIZE, TEMP_POOL_COLS);
    GS_RETURN_IFERR(row_put_int32(&ra, (int32)id));
    GS_RETURN_IFERR(row_put_int32(&ra, (int32)(pool->map_count * VM_CTRLS_PER_PAGE)));

    count = pool->free_ctrls.count;
    count += pool->map_count * VM_CTRLS_PER_PAGE - pool->ctrl_hwm;
    GS_RETURN_IFERR(row_put_int32(&ra, (int32)count));
    GS_RETURN_IFERR(row_put_int32(&ra, GS_VMEM_PAGE_SIZE));
    GS_RETURN_IFERR(row_put_int32(&ra, (int32)pool->page_count));

    count = pool->free_pages.count + pool->page_count - pool->page_hwm;
    GS_RETURN_IFERR(row_put_int32(&ra, (int32)count));
    GS_RETURN_IFERR(row_put_int32(&ra, (int32)pool->page_hwm));
    GS_RETURN_IFERR(row_put_int32(&ra, (int32)pool->free_pages.count));
    GS_RETURN_IFERR(row_put_int32(&ra, (int32)vm_close_page_cnt(pool)));
    GS_RETURN_IFERR(row_put_int32(&ra, (int32)pool->get_swap_extents));
    GS_RETURN_IFERR(row_put_int32(&ra, (int32)pool->swap_count));
    GS_RETURN_IFERR(
        row_put_int32(&ra, (int32)((SPACE_GET(session, dtc_my_ctrl(session)->swap_space))->head->free_extents.count)));
    GS_RETURN_IFERR(row_put_int32(&ra, (int32)pool->max_swap_count));

    cm_decode_row((char *)cur->row, cur->offsets, cur->lens, &cur->data_size);
    cur->rowid.vmid++;
    return GS_SUCCESS;
}

static status_t vw_vm_func_stack_fetch(knl_handle_t session, knl_cursor_t *cur)
{
    row_assist_t ra;
    vm_func_stack_t *func_stack = NULL;
    vm_pool_t *pool = NULL;

    if (g_vm_max_stack_count == 0) {
        cur->eof = GS_TRUE;
        return GS_SUCCESS;
    }

    for (; cur->rowid.vmid < g_vm_max_stack_count; cur->rowid.vmid++) {
        pool = &((knl_session_t *)session)->kernel->temp_pool[cur->rowid.vm_slot];
        if (pool->func_stacks == NULL) {
            continue;
        }
        cm_spin_lock(&pool->lock, NULL);
        func_stack = pool->func_stacks[cur->rowid.vmid];
        if (func_stack == NULL || (func_stack->stack[0] == '\0' && func_stack->ref_count == 0)) {
            cm_spin_unlock(&pool->lock);
            continue;
        }

        row_init(&ra, (char *)cur->row, GS_MAX_ROW_SIZE, VM_FUNC_STACK_COLS);
        if (row_put_str(&ra, func_stack->stack) != GS_SUCCESS) {
            cm_spin_unlock(&pool->lock);
            return GS_ERROR;
        }
        if (row_put_int32(&ra, (int32)func_stack->ref_count) != GS_SUCCESS) {
            cm_spin_unlock(&pool->lock);
            return GS_ERROR;
        }

        cm_spin_unlock(&pool->lock);

        cm_decode_row((char *)cur->row, cur->offsets, cur->lens, &cur->data_size);
        cur->rowid.vmid++;
        cm_spin_unlock(&pool->lock);
        return GS_SUCCESS;
    }

    cur->eof = GS_TRUE;
    return GS_SUCCESS;
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

static status_t vw_sga_stat_prepare_area(memory_area_t *mem_area, uint32 *id)
{
    PRTS_RETURN_IFERR(
        snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u", mem_area->page_count));
    ++(*id);

    PRTS_RETURN_IFERR(
        snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u", mem_area->page_size));
    ++(*id);

    PRTS_RETURN_IFERR(
        snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u", mem_area->page_hwm));
    ++(*id);

    PRTS_RETURN_IFERR(snprintf_s(g_sga_stat_rows[*id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u",
                                 mem_area->free_pages.count));
    ++(*id);
    return GS_SUCCESS;
}

static status_t vm_sga_stat_prep_pool(memory_pool_t *pool, uint32 *id)
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
    return GS_SUCCESS;
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
    return GS_SUCCESS;
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
    return GS_SUCCESS;
}

static status_t vw_sga_stat_prep(void)
{
    uint32 id = 0;

    // shared area
    GS_RETURN_IFERR(vw_sga_stat_prepare_area(&g_instance->sga.shared_area, &id));
    // sql pool
    context_pool_t *sql_pool_val = sql_pool;
    GS_RETURN_IFERR(vm_sga_stat_prep_pool(sql_pool_val->memory, &id));

    PRTS_RETURN_IFERR(snprintf_s(g_sga_stat_rows[id].value, SGA_VALUE_BUFFER_LEN, SGA_VALUE_BUFFER_LEN - 1, "%u",
        ctx_pool_get_lru_cnt(sql_pool_val)));
    ++id;

    // dc pool
    GS_RETURN_IFERR(vm_sga_stat_prep_pool(&g_instance->kernel.dc_ctx.pool, &id));
    // lock pool
    GS_RETURN_IFERR(vw_sga_lock_pool_stat(&g_instance->kernel.lock_ctx, &id));
    // lob pool
    GS_RETURN_IFERR(vw_sga_lob_pool_stat(&g_instance->kernel.lob_ctx, &id));
    // large pool statistic
    GS_RETURN_IFERR(vm_sga_stat_prep_pool(&g_instance->sga.large_pool, &id));
    // small vma
    GS_RETURN_IFERR(vw_sga_stat_prepare_area(&g_instance->sga.vma.marea, &id));
    // large vma
    GS_RETURN_IFERR(vw_sga_stat_prepare_area(&g_instance->sga.vma.large_marea, &id));
    // private area
    GS_RETURN_IFERR(vw_sga_stat_prepare_area(&g_instance->sga.pma.marea, &id));
    CM_ASSERT(id == SGA_STAT_ROW_COUNT);
    return GS_SUCCESS;
}

static status_t vw_sga_stat_fetch(knl_handle_t session, knl_cursor_t *cur)
{
    uint64 id;
    row_assist_t ra;

    id = cur->rowid.vmid;
    if (id >= SGA_STAT_ROW_COUNT) {
        cur->eof = GS_TRUE;
        return GS_SUCCESS;
    }

    if (id == 0) {
        cm_spin_lock(&g_sga_lock, NULL);
        if (vw_sga_stat_prep() != GS_SUCCESS) {
            cm_spin_unlock(&g_sga_lock);
            return GS_ERROR;
        }
        cm_spin_unlock(&g_sga_lock);
    }

    row_init(&ra, (char *)cur->row, GS_MAX_ROW_SIZE, SGA_STAT_COLS);
    GS_RETURN_IFERR(row_put_str(&ra, g_sga_stat_rows[id].area));
    GS_RETURN_IFERR(row_put_str(&ra, g_sga_stat_rows[id].pool));
    GS_RETURN_IFERR(row_put_str(&ra, g_sga_stat_rows[id].name));
    GS_RETURN_IFERR(row_put_str(&ra, g_sga_stat_rows[id].value));

    cm_decode_row((char *)cur->row, cur->offsets, cur->lens, &cur->data_size);
    cur->rowid.vmid++;
    return GS_SUCCESS;
}


VW_DECL dv_sga = { "SYS", "DV_GMA", SGA_COLS, g_sga_columns, vw_common_open, vw_sga_fetch };
VW_DECL dv_system = { "SYS", "DV_SYSTEM", SYSTEM_COLS, g_system_columns, vw_common_open, vw_system_fetch };
VW_DECL dv_temp_pool = {
    "SYS", "DV_TEMP_POOLS", TEMP_POOL_COLS, g_temp_pool_columns, vw_common_open, vw_temp_pool_fetch
};
VW_DECL dv_vm_func_stack = { "SYS",          "DV_VM_FUNC_STACK",    VM_FUNC_STACK_COLS, g_vm_func_stack_columns,
                             vw_common_open, vw_vm_func_stack_fetch };
VW_DECL dv_sgastat = { "SYS", "DV_GMA_STATS", SGA_STAT_COLS, g_sga_stat_columns, vw_common_open, vw_sga_stat_fetch };

dynview_desc_t *vw_describe_sga(uint32 id)
{
    switch ((dynview_id_t)id) {
        case DYN_VIEW_SGA:
            return &dv_sga;

        case DYN_VIEW_SYSTEM:
            return &dv_system;

        case DYN_VIEW_TEMP_POOL:
            return &dv_temp_pool;

        case DYN_VIEW_SGASTAT:
            return &dv_sgastat;

        case DYN_VIEW_VM_FUNC_STACK:
            return &dv_vm_func_stack;

        default:
            return NULL;
    }
}
