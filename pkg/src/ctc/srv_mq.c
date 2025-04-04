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
 * srv_mq.c
 *
 *
 * IDENTIFICATION
 * src/ctc/srv_mq.c
 *
 * -------------------------------------------------------------------------
 */

#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/time.h>
#include <pthread.h>
#include <cm_log.h>
#include <semaphore.h>
#include <dirent.h>
#include <string.h>
#include "ctc_module.h"
#include "srv_mq.h"
#include "srv_mq_msg.h"
#include "message_queue/dsw_shm_pri.h"
#include "ctc_ddl.h"
#include "cse_stats.h"
#include "ctc_inst.h"
#include "mes_func.h"
#include "srv_instance.h"
#include "ctc_srv_util.h"

#define MEM_CLASS_NUM 27
#define SHM_MSG_TIMEOUT_SEC 1
#define MQ_RESERVED_THD_NUM (10)
#define SHM_MEMORY_REDUCE 8

struct shm_seg_s* g_shm_segs[SHM_SEG_MAX_NUM + 1] = {NULL};
struct shm_seg_s *g_upstream_shm_seg = NULL;
static spinlock_t g_client_id_list_lock;

typedef struct tag_mem_class_cfg_s {
    uint32_t size; // align to 8 bytes
    uint32_t num;
} mem_class_cfg_t;

uint32 g_shm_file_num;

int g_upstream_msg_cnt[MAX_SHM_PROC];

int* mq_get_upstream_msg_client_cnt(int client_id)
{
    if (client_id >= MYSQL_PROC_START && client_id < MAX_SHM_PROC) {
        return &g_upstream_msg_cnt[client_id];
    }

    CT_LOG_RUN_ERR("[mq] invalid client_id(%d)", client_id);
    return NULL;
}

int mq_is_client_upstream_empty(int client_id)
{
    int *cnt = mq_get_upstream_msg_client_cnt(client_id);
    if (cnt == NULL) {
        CT_LOG_RUN_ERR("[mq] add ddl msg cnt failed, client_id(%d)", client_id);
        return 1;
    }
    return *cnt == 0;
}

void mq_add_client_upstream_msg_cnt(int client_id)
{
    int *cnt = mq_get_upstream_msg_client_cnt(client_id);
    if (cnt == NULL) {
        CT_LOG_RUN_ERR("[mq] add ddl msg cnt failed, client_id(%d)", client_id);
        return;
    }
    __sync_add_and_fetch(cnt, 1);
}

void mq_sub_client_upstream_msg_cnt(int client_id)
{
    int *cnt = mq_get_upstream_msg_client_cnt(client_id);
    if (cnt == NULL) {
        CT_LOG_RUN_ERR("[mq] sub ddl msg cnt failed, client_id(%d)", client_id);
        return;
    }
    __sync_sub_and_fetch(cnt, 1);
}

mq_cfg_s g_mq_cfg = {0};
mem_class_cfg_t g_mem_class_cfg[MEM_CLASS_NUM] = {
    {8,       16000},
    {16,      16000},
    {32,      16000},
    {40,      16000},
    {48,      16000},
    {56,      16000},
    {64,      16000},
    {128,     16000},
    {256,     16000},
    {384,     8000},
    {512,     400},
    {1024,    400},
    {2048,    400},
    {4096,    400},
    {8192,    400},
    {12288,   1600},
    {16384,   1200},
    {40960,   4000},
    {65536,   14000},
    {66632,   20000},
    {82224,   1000},
    {102400,  800},
    {204800,  800},
    {491520,  800},
    {1048576, 40},
    {2097152, 100},
    {4194304, 200},
};

uint32_t g_support_ctc_client[] = {
    0x0301   // Cantian 3.0 版本号
};

EXTER_ATTACK static int check_ctc_client_version(uint32_t number)
{
    int n_size = sizeof(g_support_ctc_client) / sizeof(g_support_ctc_client[0]);
    for (int i = 0; i < n_size; i++) {
        if (g_support_ctc_client[i] == number) {
            return CT_SUCCESS;
        }
    }
    return CT_ERROR;
}

mq_cfg_s *get_global_mq_cfg(void)
{
    return &g_mq_cfg;
}


uint32_t get_mq_queue_num(void)
{
    return g_shm_file_num;
}

void set_mq_queue_num(uint32_t shm_memory_reduction_ratio)
{
    /*
     * The shm_memory_reduction_ratio indicates different memory specifications for a tenant:
     * a value of 1 represents physical memory, 2 represents 256 GB, 3 represents 128 GB, and 4 represents 64 GB.
    */
    g_shm_file_num = shm_memory_reduction_ratio != 0 ?
                      SHM_MEMORY_REDUCE / shm_memory_reduction_ratio : 0;
}


int clear_mmap(void)
{
    DIR *dir = opendir(MQ_SHM_MMAP_DIR);
    struct dirent *next_file;
    char filepath[CT_FILE_NAME_BUFFER_SIZE];
    while ((next_file = readdir(dir)) != NULL) {
        if (sprintf_s(filepath, sizeof(filepath), "%s/%s", MQ_SHM_MMAP_DIR, next_file->d_name) == -1) {
            CT_LOG_RUN_ERR("delete old mmap file failed: %s", next_file->d_name);
            closedir(dir);
            return -1;
        }
        CT_LOG_DEBUG_INF("delete old mmap file: %s", filepath);
        remove(filepath);
    }
    CT_LOG_RUN_INF("[SHM] deleted all old mmap file, last file %s.", filepath);
    closedir(dir);
    return 0;
}

int is_file(const char *path)
{
    struct stat path_stat;
    if (stat(path, &path_stat) != 0) {
        return 0;
    }
    return S_ISREG(path_stat.st_mode) || S_ISSOCK(path_stat.st_mode);
}

int chown_mmap(mq_cfg_s *mq_cfg)
{
    DIR *dir = opendir(MQ_SHM_MMAP_DIR);
    struct dirent *next_file;
    char filepath[CT_FILE_NAME_BUFFER_SIZE];
    while ((next_file = readdir(dir)) != NULL) {
        if (sprintf_s(filepath, sizeof(filepath), "%s/%s", MQ_SHM_MMAP_DIR, next_file->d_name) == -1) {
            CT_LOG_RUN_ERR("chown mmap file failed: %s", next_file->d_name);
            closedir(dir);
            return -1;
        }
        if (is_file(filepath)) {
            CT_LOG_RUN_INF("chown old mmap file: %s", filepath);
            if (chown(filepath, -1, mq_cfg->mysql_deploy_group_id) != 0) {
                CT_LOG_RUN_ERR("chown failed, errno = %d", errno);
            }
        }
    }
    CT_LOG_RUN_INF("[SHM] chown all mmap file, last file %s.", filepath);
    closedir(dir);
    return 0;
}

int mq_srv_start(struct shm_seg_s *seg, cpu_set_t *mask);

char ctc_cpu_info_str[CPU_INFO_STR_SIZE];
char mysql_cpu_info_str[CPU_INFO_STR_SIZE];

int ctc_cpu_info[SHM_SEG_MAX_NUM][SMALL_RECORD_SIZE];
int g_cpu_group_num = 0;
int mysql_cpu_info[MAX_SHM_PROC][SHM_SEG_MAX_NUM][SMALL_RECORD_SIZE];
int mysql_cpu_group_num[MAX_SHM_PROC];
cpu_set_t g_masks[SHM_SEG_MAX_NUM];

int get_cpu_group_num(void)
{
    return g_cpu_group_num;
}

cpu_set_t* get_cpu_masks(void)
{
    return g_masks;
}

static int init_cpu_mask(char *cpu_info_str, int *cpu_group_num, int cpu_info[SHM_SEG_MAX_NUM][SMALL_RECORD_SIZE])
{
    errno_t errcode;
    if (cpu_info_str[0] == '0' && strlen(cpu_info_str) == 1) {
        return CT_SUCCESS;
    }
    char *p = NULL;
    char *str = strtok_r(cpu_info_str, " ", &p);
    char cpu_group_str[SHM_SEG_MAX_NUM][SMALL_RECORD_SIZE];
    while (str != NULL) {
        errcode = strcpy_s(cpu_group_str[(*cpu_group_num)++], SMALL_RECORD_SIZE, str);
        MEMS_RETURN_IFERR(errcode);
        str = strtok_r(NULL, " ", &p);
    }
    for (int i = 0; i < *cpu_group_num; i++) {
        char *cpu_p = NULL;
        char cpu_group_str_cp[SMALL_RECORD_SIZE];
        errcode = strcpy_s(cpu_group_str_cp, SMALL_RECORD_SIZE, cpu_group_str[i]);
        MEMS_RETURN_IFERR(errcode);
        char *cpu_str = strtok_r(cpu_group_str_cp, ",", &cpu_p);
        int count = 0;
        while (cpu_str != NULL) {
            int s = 0, e = 0;
            int num = sscanf_s(cpu_str, "%d-%d", &s, &e);
            if (num == 1) {
                e = s;
            } else if (num != 2) {
                CT_LOG_RUN_ERR("cpu configuration error, num = %d, s = %d, e = %d, should be like \"0-3\" or \"0\", but \"%s\"",
                               num, s, e, cpu_str);
                return CT_ERROR;
            }
            for (int j = s; j <= e; j++) {
                cpu_info[i][count++] = j;
            }
            cpu_str = strtok_r(NULL, ",", &cpu_p);
        }
        cpu_info[i][count] = -1;
    }
    return CT_SUCCESS;
}

static void set_cpu_mask(void)
{
    for (int i = 0; i < g_cpu_group_num; i++) {
        cpu_set_t mask;
        CPU_ZERO(&mask);
        for (int j = 0; j < SMALL_RECORD_SIZE; j++) {
            if (ctc_cpu_info[i][j] >= 0) {
                CPU_SET(ctc_cpu_info[i][j], &mask);
            } else {
                break;
            }
        }
        g_masks[i] = mask;
    }
}

static void init_mysql_cpu_info(void)
{
    errno_t errcode;
    char *p = NULL;
    int instance_num = 0;
    char mysql_cpu_info_str_arr[MAX_SHM_PROC][CPU_INFO_STR_SIZE];
    char *str = strtok_r(mysql_cpu_info_str, ";", &p);
    while (str != NULL) {
        errcode = strcpy_s(mysql_cpu_info_str_arr[instance_num++], SMALL_RECORD_SIZE, str);
        MEMS_RETVOID_IFERR(errcode);
        str = strtok_r(NULL, ";", &p);
    }
    int ret;
    for (int i = 0; i < instance_num; i++) {
        ret = init_cpu_mask(mysql_cpu_info_str_arr[i], &(mysql_cpu_group_num[i + MYSQL_PROC_START]),
        mysql_cpu_info[i + MYSQL_PROC_START]);
        if (ret != 0) {
            mysql_cpu_group_num[i + MYSQL_PROC_START] = 0;
        }
    }
}

char *get_global_mq_cpu_info(void)
{
    return ctc_cpu_info_str;
}

char *get_global_mq_mysql_cpu_info(void)
{
    return mysql_cpu_info_str;
}

static void free_mem_in_seg_by_proc_id(struct shm_seg_sysv_s *seg, int mem_class_idx, int blk_idx, mem_blk_hdr_t *hdr,
    uint64_t arg)
{
    if (hdr->proc_id == (int32_t)arg) {
        shm_free(seg->_seg, (char *)hdr + sizeof(mem_blk_hdr_t));
    }
}

static void free_mem(int proc_id)
{
    uint32_t mq_num = get_mq_queue_num();
    for (int k = 0; k < mq_num + 1; k++) {
        struct shm_seg_sysv_s *seg = (struct shm_seg_sysv_s *)g_shm_segs[k]->priv;
        shm_walk_all_block(seg, free_mem_in_seg_by_proc_id, (uint64_t)proc_id);
    }
}

static bool is_proc_cleanable(int client_id, int* client_status)
{
    for (int i = 0; i < MAX_SHM_SEG_NUM; i++) {
        int *clean_up_flag = get_clean_up_flag(i, client_id);
        if (*clean_up_flag) {
            CT_LOG_RUN_ERR("[CTC_CLEAN_UP]: Client is not cleanable, seg_id(%d), "
                           "client_id(%d), msg_left(%d), client_status(%d)",
                           i, client_id, *clean_up_flag, *client_status);
            return false;
        }
    }
    if (!mq_is_client_upstream_empty(client_id)) {
        CT_LOG_RUN_WAR_LIMIT(LOG_PRINT_INTERVAL_SECOND_20, "[CTC_CLEAN_UP] ddl broadcast ongoing. client_id(%d)",
                             client_id);
        return false;
    }
    return true;
}

int pre_clean_up_for_bad_mysql_proc(int client_id, int *client_status)
{
    uint32_t inst_id = 0;
    if (ctc_get_inst_id(client_id, &inst_id) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC_CLEAN_UP]: Failed to get inst_id by client_id=%d", client_id);
        return CT_ERROR;
    }
    
    unlock_instance_for_bad_mysql(inst_id);
    
    while (!is_proc_cleanable(client_id, client_status)) {
        sleep(1);
    }
    return CT_SUCCESS;
}

int clean_up_for_bad_mysql_proc(int client_id, int* client_status)
{
    uint32_t inst_id = 0;
    if (ctc_get_inst_id(client_id, &inst_id) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC_CLEAN_UP]: Failed to get inst_id by client_id=%d", client_id);
        return CT_ERROR;
    }
    
    ctc_handler_t tch = {0};
    tch.inst_id = inst_id;
    tch.sess_addr = INVALID_VALUE64;
    tch.is_broadcast = true;
    /* thd_id为0时，关闭实例id为inst_id的实例所建立的所有mysql连接 */
    int ret = ctc_close_mysql_connection(&tch);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC_CLEAN_UP]: close mysql connection failed, ret:%d, ctc_inst_id:%u",
            ret, inst_id);
    }
    ret = clean_up_for_bad_mysql(inst_id);
    free_mem(client_id);
    if (ctc_release_inst_id(inst_id) == CT_ERROR) {
        CT_LOG_RUN_INF("[CTC_CLEAN_UP]: inst_id has been release before clean up, inst_id:%u",
            inst_id);
    }
    return ret;
}

static void shm_log_err(char *log_text, int length)
{
    CT_LOG_RUN_ERR(log_text);
}

static void shm_log_info(char *log_text, int length)
{
    CT_LOG_RUN_INF_LIMIT(LOG_PRINT_INTERVAL_SECOND_60, log_text);
}

static int client_connected_cb(int *inst_id)
{
    if (ctc_alloc_inst_id((uint32_t *)inst_id) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("ctc_alloc_inst_id failed, client_id(%d).", *inst_id);
        return -1;
    }
    CT_LOG_DEBUG_INF("instance connected, inst_id(%d)", *inst_id);
    return 0;
}

int create_mq_shm_file(void)
{
    uint32_t mq_num = get_mq_queue_num();
    for (int i = 0; i < mq_num + 1; ++i) {
        if (g_shm_segs[i] != NULL) {
            CT_LOG_RUN_ERR("shm seg %d have existed", i);
            continue;
        }
        shm_key_t shm_key;
        shm_key.type = SHM_KEY_MMAP;
        (void)sprintf_s(shm_key.shm_name, NAME_MAX, "%s", MQ_SHM_MMAP_NAME);
        int ret = sprintf_s(shm_key.mmap_name, NAME_MAX, "%s.%d", MQ_SHM_MMAP_NAME, i);
        if (ret == -1) {
            CT_LOG_RUN_ERR("shm_key.mmap_name sprintf_s failed");
            return -1;
        }
        shm_key.seg_id = i;

        shm_mem_class_t shm_class[MEM_CLASS_NUM];
        for (int j = 0; j < MEM_CLASS_NUM; j++) {
            shm_class[j].num = (uint32_t)g_mem_class_cfg[j].num;
            shm_class[j].size = (uint32_t)g_mem_class_cfg[j].size;
        }
        g_shm_segs[i] = shm_master_init(&shm_key, shm_class, MEM_CLASS_NUM, i == mq_num ? 1 : 0);
        if (g_shm_segs[i] == NULL) {
            CT_LOG_RUN_ERR("shm init failed, shm_seg is null");
            return -1;
        }
        if (i == mq_num) {
            // the last seg is for upstream, served by mysqld
            g_upstream_shm_seg = g_shm_segs[i];
            continue;
        }

        if (mq_srv_start(g_shm_segs[i], (g_cpu_group_num == 0) ? NULL : &g_masks[i % g_cpu_group_num]) != 0) {
            return -1;
        }
    }
    return 0;
}

int init_cpu_info(void)
{
    if (init_cpu_mask(ctc_cpu_info_str, &g_cpu_group_num, ctc_cpu_info) != 0 || g_cpu_group_num == 0) {
        CT_LOG_RUN_ERR("g_cpu_group_num init error, g_cpu_group_num is %d", g_cpu_group_num);
        return CT_ERROR;
    }
    init_mysql_cpu_info();
    set_cpu_mask();
    return CT_SUCCESS;
}

int mq_srv_init(void)
{
    if (clear_mmap() != 0) {
        CT_LOG_RUN_ERR("clear mmap dir failed.");
        return -1;
    }
    uint32_t mq_num = get_mq_queue_num();
    mq_cfg_s *cfg = get_global_mq_cfg();

    shm_set_info_log_writer(shm_log_info);
    shm_set_error_log_writer(shm_log_err);

    CT_LOG_RUN_INF("shm start init %u queue...\n", mq_num);
    uint32_t max_thd_num = 0;
    uint32_t min_mq_thd = mq_num * (cfg->num_msg_recv_thd + REG_RECV_THD_NUM);
    ctc_get_max_sessions_per_node(&max_thd_num);
    if (max_thd_num == 0) {
        CT_LOG_RUN_ERR("get max session num failed");
        return -1;
    }
    max_thd_num = max_thd_num > min_mq_thd ? max_thd_num : min_mq_thd;
    max_thd_num += MQ_RESERVED_THD_NUM;
    if (shm_tpool_init((int)max_thd_num) != 0) {
        CT_LOG_RUN_ERR("shm tpool init failed");
        return -1;
    }

    set_shm_master_pre_clean_up(pre_clean_up_for_bad_mysql_proc);
    set_shm_master_clean_up(clean_up_for_bad_mysql_proc);
    shm_set_proc_connected_callback(client_connected_cb);

    if (create_mq_shm_file() != 0) {
        return -1;
    }

    if (chown_mmap(cfg) != 0) {
        CT_LOG_RUN_ERR("chown mmap dir failed.");
        return -1;
    }
    CT_LOG_RUN_INF("[SHM] shm start finished. max_thd_num %u, min_thd_num %u.", max_thd_num, min_mq_thd);
    return 0;
}

int ctc_check_req_key_num(uint16_t key_num)
{
    if (key_num > MAX_KEY_COLUMNS) {
        CT_LOG_RUN_ERR("The number of keys exceeds the maximum, key_num:(%u)", key_num);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static int ctc_check_cursor_num(int32_t cursor_num)
{
    if (cursor_num > SESSION_CURSOR_NUM) {
        CT_LOG_RUN_ERR("cursor_num exceeds the max number of cursor, curNum:(%u)", cursor_num);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static int ctc_check_req_pos_length(uint16_t pos_length)
{
    if (pos_length > SMALL_RECORD_SIZE) {
        CT_LOG_RUN_ERR("pos_length exceeds the maximum of destination buffer, pos_length:(%u)", pos_length);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static int ctc_check_req_lob_buffer_size(uint32_t buf_size)
{
    if (buf_size > LOB_DATA_SIZE_8M) {
        CT_LOG_RUN_ERR("The lob buffer size exceeds the maximum, buf_size:(%u)", buf_size);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static int ctc_check_mq_client_id(int client_id)
{
    if (client_id < MIN_SHM_PROC || client_id >= MAX_SHM_PROC) {
        CT_LOG_RUN_ERR("client_id is not valid, client_id:(%d)", client_id);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static int ctc_check_message_seg_num(uint16_t seg_num)
{
    if (seg_num > DSW_MESSAGE_SEGMENT_NUM_MAX) {
        CT_LOG_RUN_ERR("The number of message segment exceeds the maximum, seg_num:(%u)", seg_num);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static int ctc_check_ddl_msg_len(uint32_t message_len)
{
    if (message_len > DSW_MESSAGE_SEGMENT_NUM_MAX * CTC_MQ_MESSAGE_SLICE_LEN) {
        CT_LOG_RUN_ERR("message length exceeds the maximum, message_len:(%u)", message_len);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static int ctc_check_bulk_insert_num(uint64_t bulk_num)
{
    if (bulk_num > UINT_MAX) {
        CT_LOG_RUN_ERR("the number of bulk insert records exceeds the maximum, bulk_num:(%u)", bulk_num);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_mq_set_batch_data(dsw_message_block_t *message_block, uint8_t *data_buf, uint32_t data_len)
{
    CT_RETURN_IFERR(ctc_check_message_seg_num(message_block->head.seg_num));
    uint32_t use_buf_len = 0;
    for (uint16_t i = 0; i < message_block->head.seg_num; ++i) {
        if (use_buf_len + message_block->head.seg_desc[i].length > data_len) {
            CT_LOG_RUN_ERR("data len error, data_len:%u, use_buf_len:%u.", data_len, use_buf_len);
            return CT_ERROR;
        }

        if (message_block->seg_buf[i] == NULL) {
            CT_LOG_RUN_ERR("buf_data error, seg_buf[%u] is null.", i);
            return CT_ERROR;
        }

        errno_t ret = memcpy_s(message_block->seg_buf[i], message_block->head.seg_desc[i].length,
                               data_buf + use_buf_len, message_block->head.seg_desc[i].length);
        MEMS_RETURN_IFERR(ret);
        use_buf_len += message_block->head.seg_desc[i].length;
    }
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_mq_get_batch_data(dsw_message_block_t *message_block, uint8_t *buf_data, uint32_t buf_len)
{
    CT_RETURN_IFERR(ctc_check_message_seg_num(message_block->head.seg_num));
    uint32_t use_buf_len = 0;
    for (uint16_t i = 0; i < message_block->head.seg_num; ++i) {
        if (message_block->head.seg_desc[i].length > CTC_MQ_MESSAGE_SLICE_LEN) {
            CT_LOG_RUN_ERR("seg_data length error, seg_len:%u.", message_block->head.seg_desc[i].length);
            return CT_ERROR;
        }

        if (use_buf_len + message_block->head.seg_desc[i].length > buf_len) {
            CT_LOG_RUN_ERR("buf len error, buf_len:%u, use_buf_len:%u.", buf_len, use_buf_len);
            return CT_ERROR;
        }

        if (message_block->seg_buf[i] == NULL) {
            CT_LOG_RUN_ERR("buf_data error, seg_buf[%u] is null.", i);
            return CT_ERROR;
        }

        errno_t ret = memcpy_s(buf_data + use_buf_len, message_block->head.seg_desc[i].length,
                               message_block->seg_buf[i], message_block->head.seg_desc[i].length);
        MEMS_RETURN_IFERR(ret);
        use_buf_len += message_block->head.seg_desc[i].length;
    }
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_mq_open_table(dsw_message_block_t *message_block)
{
    struct open_table_request *req = message_block->seg_buf[0];
    req->result = ctc_open_table(&req->tch, req->table_name, req->user_name);
    return req->result;
}

EXTER_ATTACK int ctc_mq_close_table(dsw_message_block_t *message_block)
{
    struct close_table_request *req = message_block->seg_buf[0];
    req->result = ctc_close_table(&req->tch);
    return req->result;
}

EXTER_ATTACK int ctc_mq_close_session(dsw_message_block_t *message_block)
{
    struct close_session_request *req = message_block->seg_buf[0];
    req->result = ctc_close_session(&req->tch);
    return req->result;
}

EXTER_ATTACK int ctc_mq_kill_session(dsw_message_block_t *message_block)
{
    struct close_session_request *req = message_block->seg_buf[0];
    ctc_kill_session(&req->tch);
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_mq_write_row(dsw_message_block_t *message_block)
{
    struct write_row_request *req = message_block->seg_buf[0];
    record_info_t record_info = {req->record, req->record_len};
    CT_RETVALUE_IFTRUE((req->flag.auto_inc_step == 0), CT_ERROR);
    req->result = ctc_write_row(&req->tch, &record_info, req->serial_column_offset,
                                &req->last_insert_id, req->flag);
    return req->result;
}

EXTER_ATTACK int ctc_mq_update_job(dsw_message_block_t *message_block)
{
    struct update_job_request *req = message_block->seg_buf[0];
    req->result = ctc_update_job(req->info);
    return req->result;
}

EXTER_ATTACK int ctc_mq_bulk_write(dsw_message_block_t *message_block)
{
    struct bulk_write_request *req = message_block->seg_buf[0];
    record_info_t record_info = {req->record, req->record_len};
    CT_RETURN_IFERR(ctc_check_bulk_insert_num(req->record_num));
    req->result = ctc_bulk_write(&req->tch, &record_info, req->record_num, &req->err_pos, req->flag, req->part_ids);
    return req->result;
}

EXTER_ATTACK int ctc_mq_update_row(dsw_message_block_t *message_block)
{
    struct update_row_request *req = message_block->seg_buf[0];
    database_t *db = &g_instance->kernel.db;
    req->result = ctc_update_row(&req->tch, req->new_record_len, req->new_record,
        req->upd_cols, req->col_num, req->flag);
    return req->result;
}

EXTER_ATTACK int ctc_mq_delete_row(dsw_message_block_t *message_block)
{
    struct delete_row_request *req = message_block->seg_buf[0];
    req->result = ctc_delete_row(&req->tch, req->record_len, req->flag);
    return req->result;
}

EXTER_ATTACK int ctc_mq_rnd_init(dsw_message_block_t *message_block)
{
    struct rnd_init_request *req = message_block->seg_buf[0];
    req->result = ctc_rnd_init(&req->tch, req->action, req->mode, req->cond);
    return req->result;
}

EXTER_ATTACK int ctc_mq_rnd_end(dsw_message_block_t *message_block)
{
    struct rnd_end_request *req = message_block->seg_buf[0];
    req->result = ctc_rnd_end(&req->tch);
    return req->result;
}

EXTER_ATTACK int ctc_mq_rnd_next(dsw_message_block_t *message_block)
{
    int result;
    struct rnd_next_request *req = message_block->seg_buf[0];
    record_info_t record_info = { req->record, 0 };
    result = ctc_rnd_next(&req->tch, &record_info);
    if (result == CT_SUCCESS) {
        req->record_len = record_info.record_len;
    }
    req->result = result;
    return req->result;
}

EXTER_ATTACK int ctc_mq_scan_records(dsw_message_block_t *message_block)
{
    struct scan_records_request *req = message_block->seg_buf[0];
    req->result = ctc_scan_records(&req->tch, &req->num_rows, req->index_name);
    return req->result;
}

EXTER_ATTACK int ctc_mq_rnd_prefetch(dsw_message_block_t *message_block)
{
    struct rnd_prefetch_request *req = message_block->seg_buf[0];
    req->result = ctc_rnd_prefetch(&req->tch, req->records, req->record_lens,
                                   req->recNum, req->rowids, req->max_row_size);
    return req->result;
}

EXTER_ATTACK int ctc_mq_trx_commit(dsw_message_block_t *message_block)
{
    struct trx_commit_request *req = message_block->seg_buf[0];
    CT_RETURN_IFERR(ctc_check_cursor_num(req->csize));
    req->result = ctc_trx_commit(&req->tch, req->cursors, req->csize, &req->is_ddl_commit, req->sql, req->enable_stat);
    return req->result;
}

EXTER_ATTACK int ctc_mq_statistic_commit(dsw_message_block_t *message_block)
{
    struct trx_commit_request *req = message_block->seg_buf[0];
    CT_RETURN_IFERR(ctc_check_cursor_num(req->csize));
    req->result = ctc_statistic_commit(&req->tch, req->sql, req->enable_stat);
    return req->result;
}

EXTER_ATTACK int ctc_mq_trx_rollback(dsw_message_block_t *message_block)
{
    struct trx_rollback_request *req = message_block->seg_buf[0];
    CT_RETURN_IFERR(ctc_check_cursor_num(req->csize));
    req->result = ctc_trx_rollback(&req->tch, req->cursors, req->csize);
    return req->result;
}

EXTER_ATTACK int ctc_mq_trx_begin(dsw_message_block_t *message_block)
{
    struct trx_begin_request *req = message_block->seg_buf[0];
    req->result = ctc_trx_begin(&req->tch, req->trx_context, req->is_mysql_local, req->begin_time, req->enable_stat);
    return req->result;
}

EXTER_ATTACK int ctc_mq_statistic_begin(dsw_message_block_t *message_block)
{
    struct trx_begin_request *req = message_block->seg_buf[0];
    req->result = ctc_statistic_begin(&req->tch, req->begin_time, req->enable_stat);
    return req->result;
}

EXTER_ATTACK int ctc_mq_pre_create_db(dsw_message_block_t *message_block)
{
    struct pre_create_db_request *req = message_block->seg_buf[0];
    ctc_db_infos_t db_infos = { 0 };
    db_infos.name = req->db_name;
    db_infos.datafile_size = req->ctc_db_datafile_size;
    db_infos.datafile_autoextend = req->ctc_db_datafile_autoextend;
    db_infos.datafile_extend_size = req->ctc_db_datafile_extend_size;
    req->result = ctc_pre_create_db(&(req->tch), req->sql_str, &db_infos, &(req->error_code), req->error_message);
    return req->result;
}

EXTER_ATTACK int ctc_mq_drop_tablespace_and_user(dsw_message_block_t *message_block)
{
    struct drop_tablespace_and_user_request *req = message_block->seg_buf[0];
    req->result = ctc_drop_tablespace_and_user(&(req->tch), req->db_name,
        req->sql_str, req->user_name, req->user_ip, &(req->error_code), req->error_message);
    return req->result;
}

EXTER_ATTACK int ctc_mq_drop_db_pre_check(dsw_message_block_t *message_block)
{
    struct drop_db_pre_check_request *req = message_block->seg_buf[0];
    req->result = ctc_drop_db_pre_check(&(req->tch), req->db_name, &(req->error_code), req->error_message);
    return req->result;
}

EXTER_ATTACK int ctc_mq_lock_table(dsw_message_block_t *message_block)
{
    struct lock_table_request *req = message_block->seg_buf[0];
    req->result = ctc_lock_table(&(req->tch), req->db_name, &(req->lock_info), &(req->error_code));
    return req->result;
}

EXTER_ATTACK int ctc_mq_unlock_table(dsw_message_block_t *message_block)
{
    struct ctc_unlock_tables_request *req = message_block->seg_buf[0];
    req->result = ctc_unlock_table(&(req->tch), req->mysql_inst_id, &(req->lock_info));
    return req->result;
}

EXTER_ATTACK int ctc_mq_index_end(dsw_message_block_t *message_block)
{
    struct index_end_request *req = message_block->seg_buf[0];
    req->result = ctc_index_end(&req->tch);
    return req->result;
}

EXTER_ATTACK int ctc_mq_srv_set_savepoint(dsw_message_block_t *message_block)
{
    struct srv_set_savepoint_request *req = message_block->seg_buf[0];
    req->result = ctc_srv_set_savepoint(&req->tch, req->name);
    return req->result;
}

EXTER_ATTACK int ctc_mq_srv_rollback_savepoint(dsw_message_block_t *message_block)
{
    struct srv_rollback_savepoint_request *req = message_block->seg_buf[0];
    CT_RETURN_IFERR(ctc_check_cursor_num(req->csize));
    req->result = ctc_srv_rollback_savepoint(&req->tch, req->cursors, req->csize, req->name);
    return req->result;
}

EXTER_ATTACK int ctc_mq_srv_release_savepoint(dsw_message_block_t *message_block)
{
    struct srv_release_savepoint_request *req = message_block->seg_buf[0];
    req->result = ctc_srv_release_savepoint(&req->tch, req->name);
    return req->result;
}

EXTER_ATTACK int ctc_mq_general_fetch(dsw_message_block_t *message_block)
{
    int result;
    struct general_fetch_request *req = message_block->seg_buf[0];
    record_info_t record_info = { req->record, 0 };
    result = ctc_general_fetch(&req->tch, &record_info);
    if (result == CT_SUCCESS) {
        req->record_len = record_info.record_len;
    }
    req->result = result;
    return req->result;
}

EXTER_ATTACK int ctc_mq_general_prefetch(dsw_message_block_t *message_block)
{
    struct general_prefetch_request *req = message_block->seg_buf[0];
    req->result = ctc_general_prefetch(&req->tch, req->records, req->record_lens,
                                       req->recNum, req->rowids, req->max_row_size);
    return req->result;
}

EXTER_ATTACK int ctc_mq_get_index_name(dsw_message_block_t *message_block)
{
    struct get_index_slot_request *req = message_block->seg_buf[0];
    req->result = ctc_get_index_name(&req->tch, req->index_name);
    return req->result;
}

EXTER_ATTACK int ctc_mq_free_session_cursors(dsw_message_block_t *message_block)
{
    struct free_session_cursors_request *req = message_block->seg_buf[0];
    CT_RETURN_IFERR(ctc_check_cursor_num(req->csize));
    req->result = ctc_free_session_cursors(&req->tch, req->cursors, req->csize);
    return req->result;
}

EXTER_ATTACK int ctc_mq_index_read(dsw_message_block_t *message_block)
{
    int result;
    struct index_read_request *req = message_block->seg_buf[0];

    index_key_info_t index_key_info;
    result = memset_s(&index_key_info, sizeof(index_key_info_t), 0, sizeof(index_key_info_t));
    MEMS_RETURN_IFERR(result);
    index_key_info.find_flag = req->find_flag;
    index_key_info.action = req->action;
    database_t *db = &g_instance->kernel.db;
    index_key_info.sorted = req->sorted;
    index_key_info.need_init = req->need_init;
    index_key_info.key_num = req->key_num;
    index_key_info.active_index = MAX_INDEXES;
    index_key_info.index_skip_scan = req->index_skip_scan;
    errno_t ret = memcpy_s(index_key_info.index_name, CTC_MAX_KEY_NAME_LENGTH + 1, req->index_name,
                           strlen(req->index_name));
    MEMS_RETURN_IFERR(ret);

    if (req->key_num >= MAX_KEY_COLUMNS) {
        CT_LOG_RUN_ERR("req->key_num is invalid, req->key_num(%d)", req->key_num);
        return CT_ERROR;
    }

    for (uint32 i = 0; i < MAX_KEY_COLUMNS; ++i) {
        index_key_info.key_info[i].is_key_null = req->is_key_null[i];
    }

    for (uint16_t i = 0; i < req->key_num; ++i) {
        if (req->left_key_info.key_lens[i] != 0) {
            index_key_info.key_info[i].left_key = &req->left_key_record[0] + req->left_key_info.key_offsets[i];
            index_key_info.key_info[i].left_key_len = req->left_key_info.key_lens[i];
        }

        if (req->right_key_info.key_lens[i] != 0) {
            index_key_info.key_info[i].right_key = &req->right_key_record[0] + req->right_key_info.key_offsets[i];
            index_key_info.key_info[i].right_key_len = req->right_key_info.key_lens[i];
        }
    }

    record_info_t record_info = { req->record, 0 };
    result = ctc_index_read(&req->tch, &record_info, &index_key_info, req->mode, req->cond, req->is_replace);
    if (result == CT_SUCCESS) {
        req->record_len = record_info.record_len;
    }
    req->result = result;
    req->need_init = index_key_info.need_init;
    return req->result;
}

EXTER_ATTACK int ctc_mq_rnd_pos(dsw_message_block_t *message_block)
{
    int result;
    struct rnd_pos_request *req = message_block->seg_buf[0];
    record_info_t record_info = { req->record, 0 };
    result = ctc_rnd_pos(&req->tch, req->pos_length, req->position, &record_info);
    if (result == CT_SUCCESS) {
        req->record_len = record_info.record_len;
    }
    req->result = result;
    return req->result;
}

EXTER_ATTACK int ctc_mq_position(dsw_message_block_t *message_block)
{
    struct position_request *req = message_block->seg_buf[0];
    CT_RETURN_IFERR(ctc_check_req_pos_length(req->pos_length));
    req->result = ctc_position(&req->tch, req->position, req->pos_length);
    return req->result;
}

EXTER_ATTACK int ctc_mq_delete_all_rows(dsw_message_block_t *message_block)
{
    struct delete_all_rows_request *req = message_block->seg_buf[0];
    req->result = ctc_delete_all_rows(&req->tch, req->flag);
    return req->result;
}

EXTER_ATTACK int ctc_mq_analyze_table(dsw_message_block_t *message_block)
{
    struct analyze_table_request *req = message_block->seg_buf[0];
    req->result = ctc_analyze_table(&req->tch, req->user_name, req->table_name, req->ratio);
    return req->result;
}

EXTER_ATTACK int ctc_mq_get_cbo_stats(dsw_message_block_t *message_block)
{
    struct get_cbo_stats_request *req = message_block->seg_buf[0];
    req->result = ctc_get_cbo_stats(&req->tch, req->stats, req->ctc_cbo_stats_table, req->first_partid, req->num_part_fetch);
    return req->result;
}

EXTER_ATTACK int ctc_mq_write_lob(dsw_message_block_t *message_block)
{
    int result = CT_ERROR;
    struct knl_write_lob_request *request = message_block->seg_buf[0];
    CT_RETURN_IFERR(ctc_check_req_lob_buffer_size(request->data_len));
    int reqSize = sizeof(struct knl_write_lob_request) + request->data_len;
    uint8_t* reqBuf = (uint8_t *)malloc(reqSize);
    if (reqBuf == NULL) {
        CT_LOG_RUN_ERR("ctc_mq_write_lob apply for reqBuf failed.");
        return result;
    }
    int ret = ctc_mq_get_batch_data(message_block, reqBuf, reqSize);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("ctc_mq_get_batch_data failed in ctc_mq_write_lob.");
        CM_FREE_PTR(reqBuf);
        return result;
    }
    struct knl_write_lob_request *req = (struct knl_write_lob_request*)reqBuf;
    result = ctc_knl_write_lob(&req->tch, req->locator, 0, req->column_id, req->data, req->data_len, req->force_outline);
    req->result = result;
    result = ctc_mq_set_batch_data(message_block, reqBuf, reqSize);
    CM_FREE_PTR(reqBuf);
    return result;
}

EXTER_ATTACK int ctc_mq_read_lob(dsw_message_block_t *message_block)
{
    int result = CT_ERROR;
    struct knl_read_lob_request *request = message_block->seg_buf[0];
    CT_RETURN_IFERR(ctc_check_req_lob_buffer_size(request->size));
    int reqSize = sizeof(struct knl_read_lob_request) + request->size;
    uint8_t* reqBuf = (uint8_t *)malloc(reqSize);
    if (reqBuf == NULL) {
        CT_LOG_RUN_ERR("ctc_mq_write_lob apply for reqBuf failed.");
        return result;
    }
    int ret = ctc_mq_get_batch_data(message_block, reqBuf, reqSize);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("ctc_mq_get_batch_data failed in ctc_mq_read_lob.");
        CM_FREE_PTR(reqBuf);
        return result;
    }
    struct knl_read_lob_request *req = (struct knl_read_lob_request*)reqBuf;
    uint32_t read_size = 0;
    result = ctc_knl_read_lob(&req->tch, req->locator, req->offset, req->buf, req->size, &read_size);
    req->result = result;
    if (result == CT_SUCCESS) {
        req->read_size = read_size;
        result = ctc_mq_set_batch_data(message_block, reqBuf, reqSize);
    }
    CM_FREE_PTR(reqBuf);
    return result;
}

EXTER_ATTACK int ctc_mq_create_table(dsw_message_block_t *message_block)
{
    int result = CT_ERROR;
    void *req = message_block->seg_buf[0];
    ddl_ctrl_t *ddl_ctrl = (ddl_ctrl_t *) req;
    CT_RETURN_IFERR(ctc_check_ddl_msg_len(ddl_ctrl->msg_len));
    uint8_t* reqBuf = (uint8_t *)malloc(ddl_ctrl->msg_len);
    if (reqBuf == NULL) {
        CT_LOG_RUN_ERR("ctc_mq_create_table apply for reqBuf failed,size:%u", ddl_ctrl->msg_len);
        return result;
    }
    int ret = ctc_mq_get_batch_data(message_block, reqBuf, ddl_ctrl->msg_len);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("ctc_mq_get_batch_data failed in ctc_mq_create_table,size:%u", ddl_ctrl->msg_len);
        CM_FREE_PTR(reqBuf);
        return result;
    }
    result = ctc_create_table(reqBuf, ddl_ctrl);
    ddl_ctrl->error_code = result;
    errno_t err_code = memcpy_s(reqBuf, ddl_ctrl->msg_len, ddl_ctrl, sizeof(ddl_ctrl_t));
    if (err_code != EOK) {
        CT_LOG_RUN_ERR("Failed(%d) to copy the object item.", err_code);
        CM_FREE_PTR(reqBuf);
        return CT_ERROR;
    }
    result = ctc_mq_set_batch_data(message_block, reqBuf, ddl_ctrl->msg_len);
    CM_FREE_PTR(reqBuf);
    return result;
}

EXTER_ATTACK int ctc_mq_truncate_table(dsw_message_block_t *message_block)
{
    int result;
    void *req = message_block->seg_buf[0];
    ddl_ctrl_t *ddl_ctrl = (ddl_ctrl_t *) req;
    result = ctc_truncate_table((char *) req + sizeof(ddl_ctrl_t), ddl_ctrl);
    ddl_ctrl->error_code = result;
    return result;
}

EXTER_ATTACK int ctc_mq_truncate_partition(dsw_message_block_t *message_block)
{
    int result = CT_ERROR;
    void *req = message_block->seg_buf[0];
    ddl_ctrl_t *ddl_ctrl = (ddl_ctrl_t *) req;
    CT_RETURN_IFERR(ctc_check_ddl_msg_len(ddl_ctrl->msg_len));
    uint8_t* reqBuf = (uint8_t *)malloc(ddl_ctrl->msg_len);
    if (reqBuf == NULL) {
        CT_LOG_RUN_ERR("ctc_mq_truncate_partition apply for reqBuf failed,size:%u", ddl_ctrl->msg_len);
        return result;
    }
    int ret = ctc_mq_get_batch_data(message_block, reqBuf, ddl_ctrl->msg_len);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("ctc_mq_get_batch_data failed in ctc_mq_truncate_partition,size:%u", ddl_ctrl->msg_len);
        CM_FREE_PTR(reqBuf);
        return result;
    }
    result = ctc_truncate_partition(reqBuf, ddl_ctrl);
    ddl_ctrl->error_code = result;
    errno_t err_code = memcpy_s(reqBuf, ddl_ctrl->msg_len, ddl_ctrl, sizeof(ddl_ctrl_t));
    if (err_code != EOK) {
        CT_LOG_RUN_ERR("Failed(%d) to copy the object item.", err_code);
        CM_FREE_PTR(reqBuf);
        return CT_ERROR;
    }
    result = ctc_mq_set_batch_data(message_block, reqBuf, ddl_ctrl->msg_len);
    CM_FREE_PTR(reqBuf);
    return result;
}

EXTER_ATTACK int ctc_mq_rename_table(dsw_message_block_t *message_block)
{
    int result;
    void *req = message_block->seg_buf[0];
    ddl_ctrl_t *ddl_ctrl = (ddl_ctrl_t *) req;
    result = ctc_rename_table((char *) req + sizeof(ddl_ctrl_t), ddl_ctrl);
    ddl_ctrl->error_code = result;
    return result;
}

EXTER_ATTACK int ctc_mq_alter_table(dsw_message_block_t *message_block)
{
    int result = CT_ERROR;
    void *req = message_block->seg_buf[0];
    ddl_ctrl_t *ddl_ctrl = (ddl_ctrl_t *) req;
    CT_RETURN_IFERR(ctc_check_ddl_msg_len(ddl_ctrl->msg_len));
    uint8_t* reqBuf = (uint8_t *)malloc(ddl_ctrl->msg_len);
    if (reqBuf == NULL) {
        CT_LOG_RUN_ERR("ctc_mq_alter_table apply for reqBuf failed,size:%u", ddl_ctrl->msg_len);
        return result;
    }
    int ret = ctc_mq_get_batch_data(message_block, reqBuf, ddl_ctrl->msg_len);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("ctc_mq_get_batch_data failed in ctc_mq_alter_table,size:%u", ddl_ctrl->msg_len);
        CM_FREE_PTR(reqBuf);
        return result;
    }
    result = ctc_alter_table(reqBuf, ddl_ctrl);
    ddl_ctrl->error_code = result;
    errno_t err_code = memcpy_s(reqBuf, ddl_ctrl->msg_len, ddl_ctrl, sizeof(ddl_ctrl_t));
    if (err_code != EOK) {
        CT_LOG_RUN_ERR("Failed(%d) to copy the object item.", err_code);
        CM_FREE_PTR(reqBuf);
        return CT_ERROR;
    }
    result = ctc_mq_set_batch_data(message_block, reqBuf, ddl_ctrl->msg_len);
    CM_FREE_PTR(reqBuf);
    return result;
}

EXTER_ATTACK int ctc_mq_get_serial_value(dsw_message_block_t *message_block)
{
    int result;
    struct get_serial_val_request *req = message_block->seg_buf[0];
    CT_RETVALUE_IFTRUE((req->flag.auto_inc_step == 0), CT_ERROR);
    uint64_t value;
    result = ctc_get_serial_value(&req->tch, &value, req->flag);
    if (result == CT_SUCCESS) {
        req->value = value;
    }
    req->result = result;
    return req->result;
}

EXTER_ATTACK int ctc_mq_drop_table(dsw_message_block_t *message_block)
{
    int result;
    void *req = message_block->seg_buf[0];
    ddl_ctrl_t *ddl_ctrl = (ddl_ctrl_t *) req;
    result = ctc_drop_table((char *) req + sizeof(ddl_ctrl_t), ddl_ctrl);
    ddl_ctrl->error_code = result;
    return result;
}

EXTER_ATTACK int ctc_mq_execute_mysql_ddl_sql(dsw_message_block_t *message_block)
{
    int result;
    struct execute_mysql_ddl_sql_request *req = message_block->seg_buf[0];
    result = ctc_execute_mysql_ddl_sql(&req->tch, &req->broadcast_req, req->allow_fail);
    req->result = result;
    return req->result;
}

EXTER_ATTACK int ctc_mq_set_opt(dsw_message_block_t *message_block)
{
    int result;
    struct execute_set_opt_request *req = message_block->seg_buf[0];
    result = ctc_execute_set_opt(&req->tch, &req->broadcast_req, req->allow_fail);
    req->result = result;
    return req->result;
}

EXTER_ATTACK int ctc_mq_invalidate_mysql_dd_cache(dsw_message_block_t *message_block)
{
    int result;
    struct invalidate_mysql_dd_request *req = message_block->seg_buf[0];
    result = ctc_broadcast_mysql_dd_invalidate(&req->tch, &req->broadcast_req);
    req->result = result;
    return req->result;
}

EXTER_ATTACK int ctc_mq_broadcast_rewrite_sql(dsw_message_block_t *message_block)
{
    int result;
    struct execute_mysql_ddl_sql_request *req = message_block->seg_buf[0];
    result = ctc_broadcast_rewrite_sql(&req->tch, &req->broadcast_req, req->allow_fail);
    req->result = result;
    return req->result;
}

EXTER_ATTACK int ctc_mq_create_tablespace(dsw_message_block_t *message_block)
{
    int result;
    void *req = message_block->seg_buf[0];
    ddl_ctrl_t *ddl_ctrl = (ddl_ctrl_t *)req;
    result = ctc_create_tablespace((char *)req + sizeof(ddl_ctrl_t), ddl_ctrl);
    ddl_ctrl->error_code = result;
    return result;
}

EXTER_ATTACK int ctc_mq_alter_tablespace(dsw_message_block_t *message_block)
{
    int result;
    void *req = message_block->seg_buf[0];
    ddl_ctrl_t *ddl_ctrl = (ddl_ctrl_t *)req;
    result = ctc_alter_tablespace((char *)req + sizeof(ddl_ctrl_t), ddl_ctrl);
    ddl_ctrl->error_code = result;
    return result;
}

EXTER_ATTACK int ctc_mq_drop_tablespace(dsw_message_block_t *message_block)
{
    int result;
    void *req = message_block->seg_buf[0];
    ddl_ctrl_t *ddl_ctrl = (ddl_ctrl_t *)req;
    result = ctc_drop_tablespace((char *)req + sizeof(ddl_ctrl_t), ddl_ctrl);
    ddl_ctrl->error_code = result;
    return result;
}

EXTER_ATTACK int ctc_mq_get_max_sessions(dsw_message_block_t *message_block)
{
    struct get_max_session_request *req = message_block->seg_buf[0];
    uint32_t max_session_per_node = 0;
    uint32_t *max_inst_num = get_ctc_max_inst_num();
    ctc_get_max_sessions_per_node(&max_session_per_node);
    CT_RETVALUE_IFTRUE((*max_inst_num == 0), CT_ERROR);
    req->max_sessions = max_session_per_node / *max_inst_num;
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_mq_lock_instance(dsw_message_block_t *message_block)
{
    struct lock_instance_request *req = message_block->seg_buf[0];
    req->result = ctc_lock_instance(&req->is_mysqld_starting, req->lock_type, &req->tch);
    return req->result;
}

EXTER_ATTACK int ctc_mq_record_sql_for_cantian(dsw_message_block_t *message_block)
{
    int result;
    struct execute_mysql_ddl_sql_request *req = message_block->seg_buf[0];
    result = ctc_record_sql_for_cantian(&req->tch, &req->broadcast_req, req->allow_fail);
    req->result = result;
    return req->result;
}

EXTER_ATTACK int ctc_mq_get_paral_schedule(dsw_message_block_t *message_block)
{
    struct get_paral_schedule_request *req = message_block->seg_buf[0];

    req->result = ctc_get_paral_schedule(&req->tch, &req->query_scn, &req->ssn, &req->worker_count, req->paral_range);

    return req->result;
}

EXTER_ATTACK int ctc_mq_get_index_paral_schedule(dsw_message_block_t *message_block)
{
    struct get_index_paral_schedule_request *req = message_block->seg_buf[0];

    req->result = ctc_get_index_paral_schedule(&req->tch, &req->query_scn,
        &req->worker_count, req->index_name, req->reverse, req->is_index_full, req->scan_range, req->index_paral_range);
    return req->result;
}

EXTER_ATTACK int ctc_mq_pq_index_read(dsw_message_block_t *message_block)
{
    int result;
    struct pq_index_read_request *req = message_block->seg_buf[0];

    index_key_info_t index_key_info;
    result = memset_s(&index_key_info, sizeof(index_key_info_t), 0, sizeof(index_key_info_t));
    MEMS_RETURN_IFERR(result);
    index_key_info.find_flag = req->find_flag;
    index_key_info.action = req->action;
    database_t *db = &g_instance->kernel.db;
    index_key_info.sorted = req->sorted;
    index_key_info.need_init = req->need_init;
    index_key_info.key_num = req->key_num;
    index_key_info.active_index = MAX_INDEXES;
    index_key_info.index_skip_scan = req->index_skip_scan;
    errno_t ret = memcpy_s(index_key_info.index_name, CTC_MAX_KEY_NAME_LENGTH + 1, req->index_name,
                           strlen(req->index_name) + 1);
    MEMS_RETURN_IFERR(ret);

    if (req->key_num >= MAX_KEY_COLUMNS) {
        CT_LOG_RUN_ERR("req->key_num is invalid, req->key_num(%d)", req->key_num);
        return CT_ERROR;
    }

    record_info_t record_info = { req->record, 0 };
    result = ctc_pq_index_read(&req->tch, &record_info, &index_key_info, req->scan_range, req->mode,
        req->cond, req->is_replace, req->query_scn);
    if (result == CT_SUCCESS) {
        req->record_len = record_info.record_len;
    }
    req->result = result;
    req->need_init = index_key_info.need_init;
    return req->result;
}

EXTER_ATTACK int ctc_mq_set_cursor_range(dsw_message_block_t *message_block)
{
    struct set_cursor_range_requst *req = message_block->seg_buf[0];
    req->result = ctc_pq_set_cursor_range(&req->tch, req->l_page, req->r_page, req->query_scn, req->ssn);
    return req->result;
}

EXTER_ATTACK int ctc_mq_unlock_instance(dsw_message_block_t *message_block)
{
    struct unlock_instance_request *req = message_block->seg_buf[0];
    req->result = ctc_unlock_instance(&req->is_mysqld_starting, &req->tch);
    return req->result;
}

EXTER_ATTACK int ctc_mq_check_db_table_exists(dsw_message_block_t *message_block)
{
    struct check_table_exists_request *req = message_block->seg_buf[0];
    req->result = ctc_check_db_table_exists(req->db, req->name, &req->is_exists);
    return req->result;
}

EXTER_ATTACK int ctc_mq_search_metadata_switch(dsw_message_block_t *message_block)
{
    struct search_metadata_status_request *req = message_block->seg_buf[0];
    req->result = ctc_search_metadata_status(&req->metadata_switch, &req->cluster_ready);
    return req->result;
}

EXTER_ATTACK int ctc_mq_query_cluster_role(dsw_message_block_t *message_block)
{
    struct query_cluster_role_request *req = message_block->seg_buf[0];
    req->result = ctc_query_cluster_role(&req->is_slave, &req->cluster_ready);
    return req->result;
}

EXTER_ATTACK int ctc_mq_query_shm_file_num(dsw_message_block_t *message_block)
{
    struct query_shm_file_num_request *req = message_block->seg_buf[0];
    req->result = ctc_query_shm_file_num(&req->shm_file_num);
    return req->result;
}

EXTER_ATTACK int ctc_mq_query_shm_usage(dsw_message_block_t *message_block)
{
    struct query_shm_usage_request *req = message_block->seg_buf[0];
    req->result = ctc_query_shm_usage(req->shm_usage);
    return req->result;
}

EXTER_ATTACK int ctc_mq_wait_instance_startuped(dsw_message_block_t *message_block)
{
    return srv_wait_instance_startuped();
}

EXTER_ATTACK int ctc_mq_register_instance(dsw_message_block_t *message_block)
{
    struct register_instance_request *req = message_block->seg_buf[0];

    if (check_ctc_client_version(req->ctc_version) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Got an unsupport ctc client(version:%u).", req->ctc_version);
        req->result = REG_MISMATCH_CTC_VERSION;
        return CT_ERROR;
    }

    int client_id = message_block->head.src_nid;
    CT_RETURN_IFERR(ctc_check_mq_client_id(client_id));
    req->group_num = mysql_cpu_group_num[client_id];
    for (int i = 0; i < mysql_cpu_group_num[client_id]; i++) {
        for (int j = 0; j < SMALL_RECORD_SIZE; j++) {
            req->cpu_info[i][j] = mysql_cpu_info[client_id][i][j];
            if (req->cpu_info[i][j] < 0) {
                break;
            }
        }
    }

    set_client_status(client_id, SHM_CLIENT_STATUS_WORKING);
    req->result = CT_SUCCESS;
    CT_LOG_RUN_INF("[CTC_REGISTER]: register instance success for client(%d), version(Hex):%x", client_id, req->ctc_version);
    return CT_SUCCESS;
}

EXTER_ATTACK int ctc_mq_update_sample_size(dsw_message_block_t *message_block)
{
    struct update_sample_size_request *req = message_block->seg_buf[0];
    return ctc_update_sample_size(req->sample_size, req->need_persist);
}

EXTER_ATTACK int ctc_mq_get_sample_size(dsw_message_block_t *message_block)
{
    uint32_t *req = message_block->seg_buf[0];
    return ctc_get_sample_size(req);
}

EXTER_ATTACK int ctc_mq_query_sql_statistic_stat(dsw_message_block_t *message_block)
{
    struct update_sql_statistic_stat *req = message_block->seg_buf[0];
    req->result = ctc_query_sql_statistic_stat(&req->enable_stat);
    return req->result;
}

struct mq_recv_msg_node {
    enum CTC_FUNC_TYPE func_type;
    int (*deal_msg)(dsw_message_block_t *message_block);
};

static struct mq_recv_msg_node g_mq_recv_msg[] = {
    {CTC_FUNC_TYPE_OPEN_TABLE,                    ctc_mq_open_table},
    {CTC_FUNC_TYPE_CLOSE_TABLE,                   ctc_mq_close_table},
    {CTC_FUNC_TYPE_CLOSE_SESSION,                 ctc_mq_close_session},
    {CTC_FUNC_TYPE_WRITE_ROW,                     ctc_mq_write_row},
    {CTC_FUNC_TYPE_UPDATE_JOB,                    ctc_mq_update_job},
    {CTC_FUNC_TYPE_UPDATE_ROW,                    ctc_mq_update_row},
    {CTC_FUNC_TYPE_DELETE_ROW,                    ctc_mq_delete_row},
    {CTC_FUNC_TYPE_UPDATE_SAMPLE_SIZE,            ctc_mq_update_sample_size},
    {CTC_FUNC_TYPE_GET_SAMPLE_SIZE,               ctc_mq_get_sample_size},
    {CTC_FUNC_TYPE_RND_INIT,                      ctc_mq_rnd_init},
    {CTC_FUNC_TYPE_RND_END,                       ctc_mq_rnd_end},
    {CTC_FUNC_TYPE_RND_NEXT,                      ctc_mq_rnd_next},
    {CTC_FUNC_TYPE_RND_PREFETCH,                  ctc_mq_rnd_prefetch},
    {CTC_FUNC_TYPE_SCAN_RECORDS,                  ctc_mq_scan_records},
    {CTC_FUNC_TYPE_TRX_COMMIT,                    ctc_mq_trx_commit},
    {CTC_FUNC_TYPE_TRX_ROLLBACK,                  ctc_mq_trx_rollback},
    {CTC_FUNC_TYPE_STATISTIC_BEGIN,               ctc_mq_statistic_begin},
    {CTC_FUNC_TYPE_STATISTIC_COMMIT,              ctc_mq_statistic_commit},
    {CTC_FUNC_TYPE_TRX_BEGIN,                     ctc_mq_trx_begin},
    {CTC_FUNC_TYPE_LOCK_TABLE,                    ctc_mq_lock_table},
    {CTC_FUNC_TYPE_UNLOCK_TABLE,                  ctc_mq_unlock_table},
    {CTC_FUNC_TYPE_INDEX_END,                     ctc_mq_index_end},
    {CTC_FUNC_TYPE_SRV_SET_SAVEPOINT,             ctc_mq_srv_set_savepoint},
    {CTC_FUNC_TYPE_SRV_ROLLBACK_SAVEPOINT,        ctc_mq_srv_rollback_savepoint},
    {CTC_FUNC_TYPE_SRV_RELEASE_SAVEPOINT,         ctc_mq_srv_release_savepoint},
    {CTC_FUNC_TYPE_GENERAL_FETCH,                 ctc_mq_general_fetch},
    {CTC_FUNC_TYPE_GENERAL_PREFETCH,              ctc_mq_general_prefetch},
    {CTC_FUNC_TYPE_FREE_CURSORS,                  ctc_mq_free_session_cursors},
    {CTC_FUNC_TYPE_GET_INDEX_NAME,                ctc_mq_get_index_name},
    {CTC_FUNC_TYPE_INDEX_READ,                    ctc_mq_index_read},
    {CTC_FUNC_TYPE_RND_POS,                       ctc_mq_rnd_pos},
    {CTC_FUNC_TYPE_POSITION,                      ctc_mq_position},
    {CTC_FUNC_TYPE_DELETE_ALL_ROWS,               ctc_mq_delete_all_rows},
    {CTC_FUNC_TYPE_GET_CBO_STATS,                 ctc_mq_get_cbo_stats},
    {CTC_FUNC_TYPE_WRITE_LOB,                     ctc_mq_write_lob},
    {CTC_FUNC_TYPE_READ_LOB,                      ctc_mq_read_lob},
    {CTC_FUNC_TYPE_CREATE_TABLE,                  ctc_mq_create_table},
    {CTC_FUNC_TYPE_TRUNCATE_TABLE,                ctc_mq_truncate_table},
    {CTC_FUNC_TYPE_TRUNCATE_PARTITION,            ctc_mq_truncate_partition},
    {CTC_FUNC_TYPE_RENAME_TABLE,                  ctc_mq_rename_table},
    {CTC_FUNC_TYPE_ALTER_TABLE,                   ctc_mq_alter_table},
    {CTC_FUNC_TYPE_GET_SERIAL_VALUE,              ctc_mq_get_serial_value},
    {CTC_FUNC_TYPE_DROP_TABLE,                    ctc_mq_drop_table},
    {CTC_FUNC_TYPE_EXCUTE_MYSQL_DDL_SQL,          ctc_mq_execute_mysql_ddl_sql},
    {CTC_FUNC_TYPE_SET_OPT,                       ctc_mq_set_opt},
    {CTC_FUNC_TYPE_BROADCAST_REWRITE_SQL,         ctc_mq_broadcast_rewrite_sql},
    {CTC_FUNC_TYPE_CREATE_TABLESPACE,             ctc_mq_create_tablespace},
    {CTC_FUNC_TYPE_ALTER_TABLESPACE,              ctc_mq_alter_tablespace},
    {CTC_FUNC_TYPE_DROP_TABLESPACE,               ctc_mq_drop_tablespace},
    {CTC_FUNC_TYPE_BULK_INSERT,                   ctc_mq_bulk_write},
    {CTC_FUNC_TYPE_ANALYZE,                       ctc_mq_analyze_table},
    {CTC_FUNC_TYPE_GET_MAX_SESSIONS,              ctc_mq_get_max_sessions},
    {CTC_FUNC_LOCK_INSTANCE,                      ctc_mq_lock_instance},
    {CTC_FUNC_UNLOCK_INSTANCE,                    ctc_mq_unlock_instance},
    {CTC_FUNC_CHECK_TABLE_EXIST,                  ctc_mq_check_db_table_exists},
    {CTC_FUNC_SEARCH_METADATA_SWITCH,             ctc_mq_search_metadata_switch},
    {CTC_FUNC_QUERY_SHM_USAGE,                    ctc_mq_query_shm_usage},
    {CTC_FUNC_QUERY_CLUSTER_ROLE,                 ctc_mq_query_cluster_role},
    {CTC_FUNC_SET_CLUSTER_ROLE_BY_CANTIAN,        ctc_set_cluster_role_by_cantian_intf},
    {CTC_FUNC_PRE_CREATE_DB,                      ctc_mq_pre_create_db},
    {CTC_FUNC_TYPE_DROP_TABLESPACE_AND_USER,      ctc_mq_drop_tablespace_and_user},
    {CTC_FUNC_DROP_DB_PRE_CHECK,                  ctc_mq_drop_db_pre_check},
    {CTC_FUNC_KILL_CONNECTION,                    ctc_mq_kill_session},
    {CTC_FUNC_TYPE_INVALIDATE_OBJECT,             ctc_mq_invalidate_mysql_dd_cache},
    {CTC_FUNC_TYPE_RECORD_SQL,                    ctc_mq_record_sql_for_cantian},
    {CTC_FUNC_TYPE_GET_PARAL_SCHEDULE,            ctc_mq_get_paral_schedule},
    {CTC_FUNC_TYPE_GET_INDEX_PARAL_SCHEDULE,      ctc_mq_get_index_paral_schedule},
    {CTC_FUNC_TYPE_PQ_INDEX_READ,                 ctc_mq_pq_index_read},
    {CTC_FUNC_TYPE_PQ_SET_CURSOR_RANGE,           ctc_mq_set_cursor_range},
    {CTC_FUNC_QUERY_SQL_STATISTIC_STAT,           ctc_mq_query_sql_statistic_stat},
    /* for instance registration, should be the last */
    {CTC_FUNC_TYPE_REGISTER_INSTANCE,             ctc_mq_register_instance},
    {CTC_FUNC_QUERY_SHM_FILE_NUM,                 ctc_mq_query_shm_file_num},
    {CTC_FUNC_TYPE_WAIT_CONNETOR_STARTUPED,       ctc_mq_wait_instance_startuped},
};

EXTER_ATTACK int mq_recv_msg(struct shm_seg_s *shm_seg, dsw_message_block_t *message_block)
{
    if (message_block == NULL || message_block->seg_buf[0] == NULL) {
        CT_LOG_RUN_ERR("shm message_block is invalid, null message_block ptr");
        return CT_ERROR;
    }

    int *client_id_list = get_client_id_list();
    int client_id = message_block->head.src_nid;

    if (ctc_check_mq_client_id(client_id) != CT_SUCCESS) {
        sem_post(&message_block->head.sem);
        return CT_ERROR;
    }

    if (client_id >= MYSQL_PROC_START && client_id_list[client_id] != SHM_CLIENT_STATUS_WORKING) {
        CT_LOG_RUN_ERR("inst is not available, client_id(%d), status(%d)", client_id, client_id_list[client_id]);
        sem_post(&message_block->head.sem);
        return CT_ERROR;
    }

    int result = CT_SUCCESS;
    uint32_t cmd_type = message_block->head.cmd_type;
    if (cmd_type >= CTC_FUNC_TYPE_REGISTER_INSTANCE || g_mq_recv_msg[cmd_type].deal_msg == NULL) {
        CT_LOG_RUN_ERR("cmd is invalid, client_id(%d), cmd_type(%d)", client_id, message_block->head.cmd_type);
        sem_post(&message_block->head.sem);
        return result;
    }

    result = g_mq_recv_msg[cmd_type].deal_msg(message_block);
    
    sem_post(&message_block->head.sem);
    return result;
}

EXTER_ATTACK int mq_recv_reg_msg(struct shm_seg_s *shm_seg, dsw_message_block_t *message_block)
{
    if (message_block == NULL || message_block->seg_buf[0] == NULL) {
        CT_LOG_RUN_ERR("shm message_block is invalid, null message_block ptr");
        return CT_ERROR;
    }

    int *client_id_list = get_client_id_list();
    int client_id = message_block->head.src_nid;
    if (ctc_check_mq_client_id(client_id) != CT_SUCCESS) {
        sem_post(&message_block->head.sem);
        return CT_ERROR;
    }

    if (client_id >= MYSQL_PROC_START && client_id_list[client_id] != SHM_CLIENT_STATUS_CONNECTING) {
        CT_LOG_RUN_ERR("inst is not available for register, client_id(%d), status(%d)",
                       client_id, client_id_list[client_id]);
        sem_post(&message_block->head.sem);
        return CT_ERROR;
    }

    int result = CT_SUCCESS;
    if (message_block->head.cmd_type >= CTC_FUNC_TYPE_REGISTER_INSTANCE &&
        message_block->head.cmd_type < CTC_FUNC_TYPE_MYSQL_EXECUTE_UPDATE &&
        g_mq_recv_msg[message_block->head.cmd_type].deal_msg != NULL) {
        result = g_mq_recv_msg[message_block->head.cmd_type].deal_msg(message_block);
    } else {
        CT_LOG_RUN_ERR("cmd is invalid, client_id(%d), cmd_type(%d)", client_id, message_block->head.cmd_type);
    }
    
    sem_post(&message_block->head.sem);
    return result;
}

int mq_srv_start(struct shm_seg_s *seg, cpu_set_t *mask)
{
    mq_cfg_s *cfg = get_global_mq_cfg();
    CT_LOG_DEBUG_INF("start mq srv, reg_thd:%u, msg_thd:%u", REG_RECV_THD_NUM, cfg->num_msg_recv_thd);
    int ret = shm_proc_start(seg, SERVER_REGISTER_PROC_ID, REG_RECV_THD_NUM, mask, 0, mq_recv_reg_msg);
    if (ret != 0) {
        CT_LOG_RUN_ERR("[SHM] start recv_reg_msg thds %d failed.", REG_RECV_THD_NUM);
        return ret;
    }
    ret = shm_proc_start(seg, SERVER_PROC_ID, (int)cfg->num_msg_recv_thd, mask, 1, mq_recv_msg);
    if (ret != 0) {
        CT_LOG_RUN_ERR("[SHM] start recv_msg thds %d failed.", (int)cfg->num_msg_recv_thd);
    }
    return ret;
}

int mq_srv_destory(void)
{
    uint32_t mq_num = get_mq_queue_num();
    for (int i = 0; i < mq_num + 1; ++i) {
        if (g_shm_segs[i] == NULL) {
            continue;
        }

        shm_master_exit(g_shm_segs[i]);
    }
    return 0;
}

static void ctc_mq_mysql_execute_update_callback(int proc_id, void *rsp, bool *is_continue_broadcast)
{
    *is_continue_broadcast = true;
    if (rsp == NULL) {
        CT_LOG_RUN_ERR("[CTC_DDL]:rsp is null.");
        return;
    }
    
    struct execute_ddl_mysql_sql_request *tmp_rsp = (struct execute_ddl_mysql_sql_request *)rsp;
    if (tmp_rsp->result != CT_SUCCESS) {
        if (tmp_rsp->allow_fail == true) {
            *is_continue_broadcast = false;
            CT_LOG_RUN_ERR("[CTC_DDL_REWRITE]:Fail at begining. result:%d, proc_id:%d, sql:%s,"
                "user_name:%s, sql_command:%u, err_code:%d, err_msg:%s, allow_fail:%d", tmp_rsp->result, proc_id,
                sql_without_plaintext_password((tmp_rsp->broadcast_req.options & CTC_CURRENT_SQL_CONTAIN_PLAINTEXT_PASSWORD),
                tmp_rsp->broadcast_req.sql_str, sizeof(tmp_rsp->broadcast_req.sql_str)), tmp_rsp->broadcast_req.user_name,
                tmp_rsp->broadcast_req.sql_command, tmp_rsp->broadcast_req.err_code, tmp_rsp->broadcast_req.err_msg,
                tmp_rsp->allow_fail);
            return;
        }
        CT_LOG_RUN_ERR("[CTC_DDL]:remove client, proc_id:%d, sql:%s, user_name:%s, sql_command:%u, err_code:%d,"
            "allow_fail:%d", proc_id, sql_without_plaintext_password((tmp_rsp->broadcast_req.options & CTC_CURRENT_SQL_CONTAIN_PLAINTEXT_PASSWORD),
            tmp_rsp->broadcast_req.sql_str, sizeof(tmp_rsp->broadcast_req.sql_str)), tmp_rsp->broadcast_req.user_name,
            tmp_rsp->broadcast_req.sql_command, tmp_rsp->broadcast_req.err_code, tmp_rsp->allow_fail);
        remove_bad_client(proc_id);
        tmp_rsp->result = CT_SUCCESS;
    }
}

static void ctc_mq_mysql_execute_set_opt_callback(int proc_id, void *rsp, bool *is_continue_broadcast)
{
    *is_continue_broadcast = true;
    if (rsp == NULL) {
        CT_LOG_RUN_ERR("[CTC_SET_OPT]:rsp is null.");
        return;
    }
    
    struct execute_mysql_set_opt_request *tmp_rsp = (struct execute_mysql_set_opt_request *)rsp;
    if (tmp_rsp->result != CT_SUCCESS) {
        if (tmp_rsp->allow_fail == true) {
            *is_continue_broadcast = false;
            CT_LOG_RUN_ERR("[CTC_SET_OPT]:Fail at begining. result:%d, proc_id:%d, "
                "err_code:%d, err_msg:%s, allow_fail:%d", tmp_rsp->result, proc_id,
                tmp_rsp->broadcast_req.err_code, tmp_rsp->broadcast_req.err_msg,
                tmp_rsp->allow_fail);
            return;
        }
        CT_LOG_RUN_ERR("[CTC_SET_OPT]:remove client, proc_id:%d, err_code:%d,"
            "allow_fail:%d", proc_id, tmp_rsp->broadcast_req.err_code, tmp_rsp->allow_fail);
        remove_bad_client(proc_id);
        tmp_rsp->result = CT_SUCCESS;
    }
}

void ctc_mq_rewrite_open_conn_callback(int proc_id, void *rsp, bool *is_continue_broadcast)
{
    *is_continue_broadcast = true;
    if (rsp == NULL) {
        CT_LOG_RUN_ERR("[CTC_REWRITE_CONN]:rsp is null.");
        return;
    }
    
    struct execute_ddl_mysql_sql_request *tmp_rsp = (struct execute_ddl_mysql_sql_request *)rsp;
    if (tmp_rsp->result != CT_SUCCESS) {
        // 有一个节点开连接失败，停止流程, 返错
        *is_continue_broadcast = false;
        CT_LOG_RUN_ERR("[CTC_REWRITE_CONN]:open connection failed, proc_id:%d, sql:%s, user_name:%s,"
            "sql_command:%u, err_code:%d,", proc_id,
            sql_without_plaintext_password((tmp_rsp->broadcast_req.options & CTC_CURRENT_SQL_CONTAIN_PLAINTEXT_PASSWORD),
            tmp_rsp->broadcast_req.sql_str, sizeof(tmp_rsp->broadcast_req.sql_str)), tmp_rsp->broadcast_req.user_name,
            tmp_rsp->broadcast_req.sql_command,
            tmp_rsp->broadcast_req.err_code);
    }
}

static void ctc_mq_unlock_tables_callback(int proc_id, void *rsp, bool *is_continue_broadcast)
{
    *is_continue_broadcast = true;
    if (rsp == NULL) {
        CT_LOG_RUN_ERR("[CTC_UNLOCK_TABLE]:rsp is null.");
        return;
    }

    struct ctc_unlock_tables_request *tmp_rsp = (struct ctc_unlock_tables_request *)rsp;
    if (tmp_rsp->result != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC_UNLOCK_TABLE]:remove client, proc_id = %d", proc_id);
        remove_bad_client(proc_id);
        tmp_rsp->result = CT_SUCCESS;
    }
}

static void ctc_mq_lock_tables_callback(int proc_id, void *rsp, bool *is_continue_broadcast)
{
    *is_continue_broadcast = true;
    if (rsp == NULL) {
        CT_LOG_RUN_ERR("[CTC_LOCK_TABLE]:rsp is null.");
        return;
    }
    
    struct ctc_lock_tables_request *tmp_rsp = (struct ctc_lock_tables_request *)rsp;
    if (tmp_rsp->result != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC_LOCK_TABLE]:lock table failed, proc_id:%d, db:%s, table:%s", proc_id,
            tmp_rsp->lock_info.db_name, tmp_rsp->lock_info.table_name);
        *is_continue_broadcast = false;
    }
}

struct mq_send_msg_callback_map {
    enum CTC_FUNC_TYPE func_type;
    void (*send_msg_callback)(int proc_id, void *rsp, bool *is_continue_broadcast);
};

static struct mq_send_msg_callback_map g_mq_send_msg_callback[] = {
    {CTC_FUNC_TYPE_MYSQL_EXECUTE_UPDATE,         ctc_mq_mysql_execute_update_callback},
    {CTC_FUNC_TYPE_UNLOCK_TABLES,                ctc_mq_unlock_tables_callback},
    {CTC_FUNC_TYPE_LOCK_TABLES,                  ctc_mq_lock_tables_callback},
    {CTC_FUNC_TYPE_EXECUTE_REWRITE_OPEN_CONN,    ctc_mq_rewrite_open_conn_callback},
    {CTC_FUNC_TYPE_MYSQL_EXECUTE_SET_OPT,        ctc_mq_mysql_execute_set_opt_callback},
};

void mq_send_msg_callback(enum CTC_FUNC_TYPE func_type, int proc_id, void *rsp, bool *is_continue_broadcast)
{
    for (int i = 0; i < sizeof(g_mq_send_msg_callback) / sizeof(g_mq_send_msg_callback[0]); i++) {
        if (g_mq_send_msg_callback[i].func_type == func_type) {
            g_mq_send_msg_callback[i].send_msg_callback(proc_id, rsp, is_continue_broadcast);
            break;
        }
    }
}

static int ctc_send_msg_to_one_client(void *shm_inst, enum CTC_FUNC_TYPE func_type,
                                      dsw_message_block_t *msg, int client_id, bool *is_continue_broadcast)
{
    int *client_id_list = get_client_id_list();
    // This flag is to make sure the msg has been successfully received by a client.
    int is_succeed = CT_ERROR;
    if (client_id_list[client_id] == SHM_CLIENT_STATUS_WORKING) {
        int ret = shm_send_msg(shm_inst, client_id, msg);
        if (ret != CT_SUCCESS) {
            CT_LOG_RUN_ERR("faild to send msg, ret(%d)", ret);
            return ret;
        }
        mq_add_client_upstream_msg_cnt(client_id);

        while (client_id_list[client_id] == SHM_CLIENT_STATUS_WORKING) {
            struct timespec ts;
            if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
                CT_LOG_RUN_ERR("faild to get current time, errno(%d)", errno);
                mq_sub_client_upstream_msg_cnt(client_id);
                return CT_ERROR;
            }
            ts.tv_sec += SHM_MSG_TIMEOUT_SEC;
            if (sem_timedwait(&msg->head.sem, &ts) == 0) {
                break;
            }
            if (errno == ETIMEDOUT || errno == EINTR) {
                CT_LOG_RUN_WAR_LIMIT(LOG_PRINT_INTERVAL_SECOND_60, "wait sem again, client_id:(%d), client_status:(%d), errno(%d), msg_type(%d)",
                               client_id, client_id_list[client_id], errno, func_type);
                continue;
            } else {
                CT_LOG_RUN_ERR("faild to wait sem, errno(%d)", errno);
                mq_sub_client_upstream_msg_cnt(client_id);
                return CT_ERROR;
            }
        }
        mq_sub_client_upstream_msg_cnt(client_id);
        mq_send_msg_callback(func_type, client_id, msg->seg_buf[0], is_continue_broadcast);
        is_succeed = CT_SUCCESS;
    }
    if (client_id_list[client_id] != SHM_CLIENT_STATUS_WORKING && client_id_list[client_id] != SHM_CLIENT_STATUS_DOWN) {
        CT_LOG_RUN_WAR("skip client, inst_id(%d), client_stat(%d)", client_id, client_id_list[client_id]);
        if (client_id_list[client_id] == SHM_CLIENT_STATUS_CONNECTING) {
            CT_LOG_RUN_WAR("remove connecting timeout client, inst_id(%d), client_stat(%d)",
                client_id, client_id_list[client_id]);
            remove_bad_client(client_id);
        }
    }
    database_t *db = &g_instance->kernel.db;
    if (!DB_IS_PRIMARY(db)) {
        return is_succeed;
    }
    return 0;
}

int ctc_mq_deal_func(void *shm_inst, enum CTC_FUNC_TYPE func_type, void *request)
{
    dsw_message_block_t *msg = (dsw_message_block_t *)shm_alloc(shm_inst, sizeof(dsw_message_block_t));
    database_t *db = &g_instance->kernel.db;
    bool is_slave_cluster = !DB_IS_PRIMARY(db);
    if (msg == NULL) {
        CT_LOG_RUN_ERR("[CTC_SHM]:msg init failed, msg_type(%d)", func_type);
        return -1;
    }
    int ret = sem_init(&msg->head.sem, 1, 0);
    if (ret != 0) {
        CT_LOG_RUN_ERR("[CTC_SHM]:sem init failed, msg_type(%d), ret(%d)", func_type, ret);
        return ret;
    }
    msg->head.src_nid = SERVER_PROC_ID;
    msg->head.dst_nid = 2; // 2仅作为标记使用，表示发送给某个节点的nid，真正起作用的for循环的变量i
    msg->head.seg_num = 1;
    msg->head.seg_desc[0].type = 0;
    msg->head.seg_desc[0].length = REQUEST_SIZE;
    msg->head.cmd_type = (uint32_t) func_type;
    msg->seg_buf[0] = request;

    bool is_continue_broadcast = true;
    int at_least_one_succeed = CT_ERROR;
    for (int i = MYSQL_PROC_START; i < MAX_SHM_PROC; i++) {
        int send_ret = ctc_send_msg_to_one_client(shm_inst, func_type, msg, i, &is_continue_broadcast);
        if (!is_slave_cluster && send_ret != 0) {
            CT_LOG_RUN_ERR("[CTC_SHM]:failed to sent msg to a client, client_id(%d), msg_type(%d)", i, func_type);
        }
        if (send_ret == CT_SUCCESS) {
            at_least_one_succeed = CT_SUCCESS;
        }
        if (!is_continue_broadcast) {
            break;
        }
    }

    ret = sem_destroy(&msg->head.sem);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[CTC_SHM]:sem destory failed, ret:%d, func_type:%d.", ret, func_type);
    }
    shm_free(shm_inst, msg);
    if (is_slave_cluster) {
        // At least one mysql should execute succeed in slave cluster.
        if (at_least_one_succeed == CT_SUCCESS) {
            return ret;
        } else {
            CT_LOG_RUN_ERR("[CTC_SHM]:slave cluster failed to send msg at least one mysql, ret:%d", ret);
            return CT_ERROR;
        }
    } else {
        return ret;
    }
}

void *get_upstream_shm_inst(void)
{
    return g_upstream_shm_seg;
}

void *alloc_share_mem(void* shm_inst, uint32_t mem_size)
{
    return shm_alloc((struct shm_seg_s *) shm_inst, mem_size);
}

void free_share_mem(void* shm_inst, void *shm_mem)
{
    shm_free((struct shm_seg_s *) shm_inst, shm_mem);
}

int ctc_query_shm_usage(uint32_t *shm_usage)
{
    uint32_t idx = 0;
    uint32_t shm_file_num = get_mq_queue_num();
    for (int i = 0; i < shm_file_num + 1; i++) {
        struct shm_seg_sysv_s *seg = (struct shm_seg_sysv_s *)g_shm_segs[i]->priv;
        shm_area_t *all_shm = seg->all_seg_shm;
        for (int j = 0; j < all_shm->head.nr_mem_class; j++) {
            shm_mem_list_t mem_list = all_shm->mem_list[j];
            shm_free_list_t free_list = mem_list.free_list;
            mem_blk_hdr_t *hdr = NULL;
            uint32_t free_size = 0;
            for (uint32_t node = free_list.head; node != SHM_NULL; node = hdr->next) {
                hdr = (mem_blk_hdr_t *)shm2ptr((char *)(all_shm), node);
                free_size++;
            }
            shm_usage[idx++] = all_shm->mem_list[j].total - free_size;
        }
    }

    return CT_SUCCESS;
}