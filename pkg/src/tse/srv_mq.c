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
 * src/tse/srv_mq.c
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
#include "tse_module.h"
#include "srv_mq.h"
#include "srv_mq_msg.h"
#include "message_queue/dsw_shm_pri.h"
#include "tse_ddl.h"
#include "cse_stats.h"
#include "tse_inst.h"
#include "mes_func.h"
#include "srv_instance.h"
#include "tse_srv_util.h"

#define MEM_CLASS_NUM 27
#define SHM_MSG_TIMEOUT_SEC 1
#define MQ_RESERVED_THD_NUM (10)

struct shm_seg_s* g_shm_segs[SHM_SEG_MAX_NUM + 1] = {NULL};
struct shm_seg_s *g_upstream_shm_seg = NULL;
static spinlock_t g_client_id_list_lock;


typedef struct tag_mem_class_cfg_s {
    uint32_t size; // align to 8 bytes
    uint32_t num;
} mem_class_cfg_t;

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
    {4,      960},
    {8,      780},
    {24,     500},
    {40,     8000},
    {48,     9700},
    {56,     10000},
    {64,     20000},
    {128,    8192},
    {256,    20000},
    {296,    400},
    {312,    400},
    {512,    400},
    {1024,   400},
    {2048,   400},
    {4096,   400},
    {8192,   400},
    {40960,  8192},
    {41008,  400},
    {41144,  400},
    {49200,  400},
    {65536,  15000},
    {65544,  10000},
    {82224,  400},
    {102400, 2000},
    {204800, 1000},
    {491520, 1000},
    {52428800, 20},
};

uint32_t g_support_ctc_client[] = {
    0x0300   // Cantian 3.0 版本号
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
    return g_mq_cfg.num_msg_queue;
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

char tse_cpu_info_str[CPU_INFO_STR_SIZE];
char mysql_cpu_info_str[CPU_INFO_STR_SIZE];

int tse_cpu_info[SHM_SEG_MAX_NUM][SMALL_RECORD_SIZE];
int tse_cpu_group_num = 0;
int mysql_cpu_info[MAX_SHM_PROC][SHM_SEG_MAX_NUM][SMALL_RECORD_SIZE];
int mysql_cpu_group_num[MAX_SHM_PROC];

cpu_set_t g_masks[SHM_SEG_MAX_NUM];

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
            int s, e;
            int num = sscanf_s(cpu_str, "%d-%d", &s, &e);
            if (num < 0) {
                CT_LOG_RUN_ERR("cpu configuration error, should be like \"0-3\": %s", cpu_str);
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
    for (int i = 0; i < tse_cpu_group_num; i++) {
        cpu_set_t mask;
        CPU_ZERO(&mask);
        for (int j = 0; j < SMALL_RECORD_SIZE; j++) {
            if (tse_cpu_info[i][j] >= 0) {
                CPU_SET(tse_cpu_info[i][j], &mask);
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
    return tse_cpu_info_str;
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
    if (tse_get_inst_id(client_id, &inst_id) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[TSE_CLEAN_UP]: Failed to get inst_id by client_id=%d", client_id);
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
    if (tse_get_inst_id(client_id, &inst_id) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[TSE_CLEAN_UP]: Failed to get inst_id by client_id=%d", client_id);
        return CT_ERROR;
    }
    
    tianchi_handler_t tch = {0};
    tch.inst_id = inst_id;
    tch.sess_addr = INVALID_VALUE64;
    tch.is_broadcast = true;
    /* thd_id为0时，关闭实例id为inst_id的实例所建立的所有mysql连接 */
    int ret = tse_close_mysql_connection(&tch);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[TSE_CLEAN_UP]:close mysql connection failed, ret:%d, tse_inst_id:%u",
            ret, inst_id);
    }
    ret = clean_up_for_bad_mysql(inst_id);
    free_mem(client_id);
    if (tse_release_inst_id(inst_id) == CT_ERROR) {
        CT_LOG_RUN_INF("[TSE_CLEAN_UP]:inst_id has been release before clean up, inst_id:%u",
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
    CT_LOG_RUN_INF(log_text);
}

static int client_connected_cb(int *inst_id)
{
    if (tse_alloc_inst_id((uint32_t *)inst_id) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("tse_alloc_inst_id failed, client_id(%d).", *inst_id);
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

        if (mq_srv_start(g_shm_segs[i], (tse_cpu_group_num == 0) ? NULL : &g_masks[i % tse_cpu_group_num]) != 0) {
            return -1;
        }
    }
    return 0;
}

int mq_srv_init(void)
{
    if (init_cpu_mask(tse_cpu_info_str, &tse_cpu_group_num, tse_cpu_info) != 0) {
        tse_cpu_group_num = 0;
        CT_LOG_RUN_ERR("cpu group init error!");
    }
    init_mysql_cpu_info();
    set_cpu_mask();
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
    tse_get_max_sessions_per_node(&max_thd_num);
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

int tse_check_req_key_num(uint16_t key_num)
{
    if (key_num > MAX_KEY_COLUMNS) {
        CT_LOG_RUN_ERR("The number of keys exceeds the maximum, key_num:(%u)", key_num);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static int tse_check_cursor_num(int32_t cursor_num)
{
    if (cursor_num > SESSION_CURSOR_NUM) {
        CT_LOG_RUN_ERR("cursor_num exceeds the max number of cursor, curNum:(%u)", cursor_num);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static int tse_check_req_pos_length(uint16_t pos_length)
{
    if (pos_length > SMALL_RECORD_SIZE) {
        CT_LOG_RUN_ERR("pos_length exceeds the maximum of destination buffer, pos_length:(%u)", pos_length);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static int tse_check_req_lob_buffer_size(uint32_t buf_size)
{
    if (buf_size > LOB_DATA_SIZE_8M) {
        CT_LOG_RUN_ERR("The lob buffer size exceeds the maximum, buf_size:(%u)", buf_size);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static int tse_check_mq_client_id(int client_id)
{
    if (client_id < MIN_SHM_PROC || client_id >= MAX_SHM_PROC) {
        CT_LOG_RUN_ERR("client_id is not valid, client_id:(%d)", client_id);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static int tse_check_message_seg_num(uint16_t seg_num)
{
    if (seg_num > DSW_MESSAGE_SEGMENT_NUM_MAX) {
        CT_LOG_RUN_ERR("The number of message segment exceeds the maximum, seg_num:(%u)", seg_num);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static int tse_check_ddl_msg_len(uint32_t message_len)
{
    if (message_len > DSW_MESSAGE_SEGMENT_NUM_MAX * TSE_MQ_MESSAGE_SLICE_LEN) {
        CT_LOG_RUN_ERR("message length exceeds the maximum, message_len:(%u)", message_len);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static int tse_check_bulk_insert_num(uint64_t bulk_num)
{
    if (bulk_num > UINT_MAX) {
        CT_LOG_RUN_ERR("the number of bulk insert records exceeds the maximum, bulk_num:(%u)", bulk_num);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

EXTER_ATTACK int tse_mq_set_batch_data(dsw_message_block_t *message_block, uint8_t *data_buf, uint32_t data_len)
{
    CT_RETURN_IFERR(tse_check_message_seg_num(message_block->head.seg_num));
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

EXTER_ATTACK int tse_mq_get_batch_data(dsw_message_block_t *message_block, uint8_t *buf_data, uint32_t buf_len)
{
    CT_RETURN_IFERR(tse_check_message_seg_num(message_block->head.seg_num));
    uint32_t use_buf_len = 0;
    for (uint16_t i = 0; i < message_block->head.seg_num; ++i) {
        if (message_block->head.seg_desc[i].length > TSE_MQ_MESSAGE_SLICE_LEN) {
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

EXTER_ATTACK int tse_mq_open_table(dsw_message_block_t *message_block)
{
    struct open_table_request *req = message_block->seg_buf[0];
    req->result = tse_open_table(&req->tch, req->table_name, req->user_name);
    return req->result;
}

EXTER_ATTACK int tse_mq_close_table(dsw_message_block_t *message_block)
{
    struct close_table_request *req = message_block->seg_buf[0];
    req->result = tse_close_table(&req->tch);
    return req->result;
}

EXTER_ATTACK int tse_mq_close_session(dsw_message_block_t *message_block)
{
    struct close_session_request *req = message_block->seg_buf[0];
    req->result = tse_close_session(&req->tch);
    return req->result;
}

EXTER_ATTACK int tse_mq_kill_session(dsw_message_block_t *message_block)
{
    struct close_session_request *req = message_block->seg_buf[0];
    tse_kill_session(&req->tch);
    return CT_SUCCESS;
}

EXTER_ATTACK int tse_mq_write_row(dsw_message_block_t *message_block)
{
    struct write_row_request *req = message_block->seg_buf[0];
    record_info_t record_info = {req->record, req->record_len};
    CT_RETVALUE_IFTRUE((req->flag.auto_inc_step == 0), CT_ERROR);
    req->result = tse_write_row(&req->tch, &record_info, req->serial_column_offset,
                                &req->last_insert_id, req->flag);
    return req->result;
}

EXTER_ATTACK int tse_mq_write_through_row(dsw_message_block_t *message_block)
{
    struct write_row_request *req = message_block->seg_buf[0];
    if (!req->flag.write_through) {
        CT_LOG_RUN_ERR("The write_through_row detect a not write_through flag.");
        return CT_ERROR;
    }
    record_info_t record_info = {req->record, req->record_len};
    tianchi_handler_t *tch = &req->tch;
    session_t *session = tse_get_session_by_addr(tch->sess_addr);
    TSE_LOG_RET_VAL_IF_NUL(session, ERR_INVALID_SESSION_ID, "session lookup failed");
    tse_set_no_use_other_sess4thd(session);
 
    if (knl_begin_auton_rm(session) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("ERR to begin transaction for write_through_row.");
        return CT_ERROR;
    }
    req->result = tse_write_row(&req->tch, &record_info, req->serial_column_offset,
                                &req->last_insert_id, req->flag);
    knl_end_auton_rm(session, req->result);
    return req->result;
}

EXTER_ATTACK int tse_mq_bulk_write(dsw_message_block_t *message_block)
{
    struct bulk_write_request *req = message_block->seg_buf[0];
    record_info_t record_info = {req->record, req->record_len};
    CT_RETURN_IFERR(tse_check_bulk_insert_num(req->record_num));
    req->result = tse_bulk_write(&req->tch, &record_info, req->record_num, &req->err_pos, req->flag, req->part_ids);
    return req->result;
}

EXTER_ATTACK int tse_mq_update_row(dsw_message_block_t *message_block)
{
    struct update_row_request *req = message_block->seg_buf[0];
    database_t *db = &g_instance->kernel.db;
    req->result = tse_update_row(&req->tch, req->new_record_len, req->new_record,
        req->upd_cols, req->col_num, req->flag);
    return req->result;
}

EXTER_ATTACK int tse_mq_delete_row(dsw_message_block_t *message_block)
{
    struct delete_row_request *req = message_block->seg_buf[0];
    req->result = tse_delete_row(&req->tch, req->record_len, req->flag);
    return req->result;
}

EXTER_ATTACK int tse_mq_rnd_init(dsw_message_block_t *message_block)
{
    struct rnd_init_request *req = message_block->seg_buf[0];
    req->result = tse_rnd_init(&req->tch, req->action, req->mode, req->cond);
    return req->result;
}

EXTER_ATTACK int tse_mq_rnd_end(dsw_message_block_t *message_block)
{
    struct rnd_end_request *req = message_block->seg_buf[0];
    req->result = tse_rnd_end(&req->tch);
    return req->result;
}

EXTER_ATTACK int tse_mq_rnd_next(dsw_message_block_t *message_block)
{
    int result;
    struct rnd_next_request *req = message_block->seg_buf[0];
    record_info_t record_info = { req->record, 0 };
    result = tse_rnd_next(&req->tch, &record_info);
    if (result == CT_SUCCESS) {
        req->record_len = record_info.record_len;
    }
    req->result = result;
    return req->result;
}

EXTER_ATTACK int tse_mq_scan_records(dsw_message_block_t *message_block)
{
    struct scan_records_request *req = message_block->seg_buf[0];
    req->result = tse_scan_records(&req->tch, &req->num_rows, req->index_name);
    return req->result;
}

EXTER_ATTACK int tse_mq_rnd_prefetch(dsw_message_block_t *message_block)
{
    struct rnd_prefetch_request *req = message_block->seg_buf[0];
    req->result = tse_rnd_prefetch(&req->tch, req->records, req->record_lens,
                                   req->recNum, req->rowids, req->max_row_size);
    return req->result;
}

EXTER_ATTACK int tse_mq_trx_commit(dsw_message_block_t *message_block)
{
    struct trx_commit_request *req = message_block->seg_buf[0];
    CT_RETURN_IFERR(tse_check_cursor_num(req->csize));
    req->result = tse_trx_commit(&req->tch, req->cursors, req->csize, &req->is_ddl_commit);
    return req->result;
}

EXTER_ATTACK int tse_mq_trx_rollback(dsw_message_block_t *message_block)
{
    struct trx_rollback_request *req = message_block->seg_buf[0];
    CT_RETURN_IFERR(tse_check_cursor_num(req->csize));
    req->result = tse_trx_rollback(&req->tch, req->cursors, req->csize);
    return req->result;
}

EXTER_ATTACK int tse_mq_trx_begin(dsw_message_block_t *message_block)
{
    struct trx_begin_request *req = message_block->seg_buf[0];
    req->result = tse_trx_begin(&req->tch, req->trx_context, req->is_mysql_local);
    return req->result;
}

EXTER_ATTACK int tse_mq_pre_create_db(dsw_message_block_t *message_block)
{
    struct pre_create_db_request *req = message_block->seg_buf[0];
    tse_db_infos_t db_infos = { 0 };
    db_infos.name = req->db_name;
    db_infos.datafile_size = req->tse_db_datafile_size;
    db_infos.datafile_autoextend = req->tse_db_datafile_autoextend;
    db_infos.datafile_extend_size = req->tse_db_datafile_extend_size;
    req->result = tse_pre_create_db(&(req->tch), req->sql_str, &db_infos, &(req->error_code), req->error_message);
    return req->result;
}

EXTER_ATTACK int tse_mq_drop_tablespace_and_user(dsw_message_block_t *message_block)
{
    struct drop_tablespace_and_user_request *req = message_block->seg_buf[0];
    req->result = tse_drop_tablespace_and_user(&(req->tch), req->db_name,
        req->sql_str, req->user_name, req->user_ip, &(req->error_code), req->error_message);
    return req->result;
}

EXTER_ATTACK int tse_mq_drop_db_pre_check(dsw_message_block_t *message_block)
{
    struct drop_db_pre_check_request *req = message_block->seg_buf[0];
    req->result = tse_drop_db_pre_check(&(req->tch), req->db_name, &(req->error_code), req->error_message);
    return req->result;
}

EXTER_ATTACK int tse_mq_lock_table(dsw_message_block_t *message_block)
{
    struct lock_table_request *req = message_block->seg_buf[0];
    req->result = tse_lock_table(&(req->tch), req->db_name, &(req->lock_info), &(req->error_code));
    return req->result;
}

EXTER_ATTACK int tse_mq_unlock_table(dsw_message_block_t *message_block)
{
    struct tse_unlock_tables_request *req = message_block->seg_buf[0];
    req->result = tse_unlock_table(&(req->tch), req->mysql_inst_id, &(req->lock_info));
    return req->result;
}

EXTER_ATTACK int tse_mq_index_end(dsw_message_block_t *message_block)
{
    struct index_end_request *req = message_block->seg_buf[0];
    req->result = tse_index_end(&req->tch);
    return req->result;
}

EXTER_ATTACK int tse_mq_srv_set_savepoint(dsw_message_block_t *message_block)
{
    struct srv_set_savepoint_request *req = message_block->seg_buf[0];
    req->result = tse_srv_set_savepoint(&req->tch, req->name);
    return req->result;
}

EXTER_ATTACK int tse_mq_srv_rollback_savepoint(dsw_message_block_t *message_block)
{
    struct srv_rollback_savepoint_request *req = message_block->seg_buf[0];
    CT_RETURN_IFERR(tse_check_cursor_num(req->csize));
    req->result = tse_srv_rollback_savepoint(&req->tch, req->cursors, req->csize, req->name);
    return req->result;
}

EXTER_ATTACK int tse_mq_srv_release_savepoint(dsw_message_block_t *message_block)
{
    struct srv_release_savepoint_request *req = message_block->seg_buf[0];
    req->result = tse_srv_release_savepoint(&req->tch, req->name);
    return req->result;
}

EXTER_ATTACK int tse_mq_general_fetch(dsw_message_block_t *message_block)
{
    int result;
    struct general_fetch_request *req = message_block->seg_buf[0];
    record_info_t record_info = { req->record, 0 };
    result = tse_general_fetch(&req->tch, &record_info);
    if (result == CT_SUCCESS) {
        req->record_len = record_info.record_len;
    }
    req->result = result;
    return req->result;
}

EXTER_ATTACK int tse_mq_general_prefetch(dsw_message_block_t *message_block)
{
    struct general_prefetch_request *req = message_block->seg_buf[0];
    req->result = tse_general_prefetch(&req->tch, req->records, req->record_lens,
                                       req->recNum, req->rowids, req->max_row_size);
    return req->result;
}

EXTER_ATTACK int tse_mq_get_index_name(dsw_message_block_t *message_block)
{
    struct get_index_slot_request *req = message_block->seg_buf[0];
    req->result = tse_get_index_name(&req->tch, req->index_name);
    return req->result;
}

EXTER_ATTACK int tse_mq_free_session_cursors(dsw_message_block_t *message_block)
{
    struct free_session_cursors_request *req = message_block->seg_buf[0];
    CT_RETURN_IFERR(tse_check_cursor_num(req->csize));
    req->result = tse_free_session_cursors(&req->tch, req->cursors, req->csize);
    return req->result;
}

EXTER_ATTACK int tse_mq_index_read(dsw_message_block_t *message_block)
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
    errno_t ret = memcpy_s(index_key_info.index_name, TSE_MAX_KEY_NAME_LENGTH + 1, req->index_name,
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
    result = tse_index_read(&req->tch, &record_info, &index_key_info, req->mode, req->cond, req->is_replace);
    if (result == CT_SUCCESS) {
        req->record_len = record_info.record_len;
    }
    req->result = result;
    req->need_init = index_key_info.need_init;
    return req->result;
}

EXTER_ATTACK int tse_mq_rnd_pos(dsw_message_block_t *message_block)
{
    int result;
    struct rnd_pos_request *req = message_block->seg_buf[0];
    record_info_t record_info = { req->record, 0 };
    result = tse_rnd_pos(&req->tch, req->pos_length, req->position, &record_info);
    if (result == CT_SUCCESS) {
        req->record_len = record_info.record_len;
    }
    req->result = result;
    return req->result;
}

EXTER_ATTACK int tse_mq_position(dsw_message_block_t *message_block)
{
    struct position_request *req = message_block->seg_buf[0];
    CT_RETURN_IFERR(tse_check_req_pos_length(req->pos_length));
    req->result = tse_position(&req->tch, req->position, req->pos_length);
    return req->result;
}

EXTER_ATTACK int tse_mq_delete_all_rows(dsw_message_block_t *message_block)
{
    struct delete_all_rows_request *req = message_block->seg_buf[0];
    req->result = tse_delete_all_rows(&req->tch, req->flag);
    return req->result;
}

EXTER_ATTACK int tse_mq_analyze_table(dsw_message_block_t *message_block)
{
    struct analyze_table_request *req = message_block->seg_buf[0];
    req->result = tse_analyze_table(&req->tch, req->user_name, req->table_name, req->ratio);
    return req->result;
}

EXTER_ATTACK int tse_mq_get_cbo_stats(dsw_message_block_t *message_block)
{
    struct get_cbo_stats_request *req = message_block->seg_buf[0];
    req->result = tse_get_cbo_stats(&req->tch, req->stats);
    return req->result;
}

EXTER_ATTACK int tse_mq_write_lob(dsw_message_block_t *message_block)
{
    int result = CT_ERROR;
    struct knl_write_lob_request *request = message_block->seg_buf[0];
    CT_RETURN_IFERR(tse_check_req_lob_buffer_size(request->data_len));
    int reqSize = sizeof(struct knl_write_lob_request) + request->data_len;
    uint8_t* reqBuf = (uint8_t *)malloc(reqSize);
    if (reqBuf == NULL) {
        CT_LOG_RUN_ERR("tse_mq_write_lob apply for reqBuf failed.");
        return result;
    }
    int ret = tse_mq_get_batch_data(message_block, reqBuf, reqSize);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("tse_mq_get_batch_data failed in tse_mq_write_lob.");
        CM_FREE_PTR(reqBuf);
        return result;
    }
    struct knl_write_lob_request *req = (struct knl_write_lob_request*)reqBuf;
    result = tse_knl_write_lob(&req->tch, req->locator, 0, req->column_id, req->data, req->data_len, req->force_outline);
    req->result = result;
    result = tse_mq_set_batch_data(message_block, reqBuf, reqSize);
    CM_FREE_PTR(reqBuf);
    return result;
}

EXTER_ATTACK int tse_mq_read_lob(dsw_message_block_t *message_block)
{
    int result = CT_ERROR;
    struct knl_read_lob_request *request = message_block->seg_buf[0];
    CT_RETURN_IFERR(tse_check_req_lob_buffer_size(request->size));
    int reqSize = sizeof(struct knl_read_lob_request) + request->size;
    uint8_t* reqBuf = (uint8_t *)malloc(reqSize);
    if (reqBuf == NULL) {
        CT_LOG_RUN_ERR("tse_mq_write_lob apply for reqBuf failed.");
        return result;
    }
    int ret = tse_mq_get_batch_data(message_block, reqBuf, reqSize);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("tse_mq_get_batch_data failed in tse_mq_read_lob.");
        CM_FREE_PTR(reqBuf);
        return result;
    }
    struct knl_read_lob_request *req = (struct knl_read_lob_request*)reqBuf;
    uint32_t read_size = 0;
    result = tse_knl_read_lob(&req->tch, req->locator, req->offset, req->buf, req->size, &read_size);
    req->result = result;
    if (result == CT_SUCCESS) {
        req->read_size = read_size;
        result = tse_mq_set_batch_data(message_block, reqBuf, reqSize);
    }
    CM_FREE_PTR(reqBuf);
    return result;
}

EXTER_ATTACK int tse_mq_create_table(dsw_message_block_t *message_block)
{
    int result = CT_ERROR;
    void *req = message_block->seg_buf[0];
    ddl_ctrl_t *ddl_ctrl = (ddl_ctrl_t *) req;
    CT_RETURN_IFERR(tse_check_ddl_msg_len(ddl_ctrl->msg_len));
    uint8_t* reqBuf = (uint8_t *)malloc(ddl_ctrl->msg_len);
    if (reqBuf == NULL) {
        CT_LOG_RUN_ERR("tse_mq_create_table apply for reqBuf failed,size:%u", ddl_ctrl->msg_len);
        return result;
    }
    int ret = tse_mq_get_batch_data(message_block, reqBuf, ddl_ctrl->msg_len);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("tse_mq_get_batch_data failed in tse_mq_create_table,size:%u", ddl_ctrl->msg_len);
        CM_FREE_PTR(reqBuf);
        return result;
    }
    result = tse_create_table(reqBuf, ddl_ctrl);
    ddl_ctrl->error_code = result;
    errno_t err_code = memcpy_s(reqBuf, ddl_ctrl->msg_len, ddl_ctrl, sizeof(ddl_ctrl_t));
    if (err_code != EOK) {
        CT_LOG_RUN_ERR("Failed(%d) to copy the object item.", err_code);
        CM_FREE_PTR(reqBuf);
        return CT_ERROR;
    }
    result = tse_mq_set_batch_data(message_block, reqBuf, ddl_ctrl->msg_len);
    CM_FREE_PTR(reqBuf);
    return result;
}

EXTER_ATTACK int tse_mq_truncate_table(dsw_message_block_t *message_block)
{
    int result;
    void *req = message_block->seg_buf[0];
    ddl_ctrl_t *ddl_ctrl = (ddl_ctrl_t *) req;
    result = tse_truncate_table((char *) req + sizeof(ddl_ctrl_t), ddl_ctrl);
    ddl_ctrl->error_code = result;
    return result;
}

EXTER_ATTACK int tse_mq_truncate_partition(dsw_message_block_t *message_block)
{
    int result = CT_ERROR;
    void *req = message_block->seg_buf[0];
    ddl_ctrl_t *ddl_ctrl = (ddl_ctrl_t *) req;
    CT_RETURN_IFERR(tse_check_ddl_msg_len(ddl_ctrl->msg_len));
    uint8_t* reqBuf = (uint8_t *)malloc(ddl_ctrl->msg_len);
    if (reqBuf == NULL) {
        CT_LOG_RUN_ERR("tse_mq_truncate_partition apply for reqBuf failed,size:%u", ddl_ctrl->msg_len);
        return result;
    }
    int ret = tse_mq_get_batch_data(message_block, reqBuf, ddl_ctrl->msg_len);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("tse_mq_get_batch_data failed in tse_mq_truncate_partition,size:%u", ddl_ctrl->msg_len);
        CM_FREE_PTR(reqBuf);
        return result;
    }
    result = tse_truncate_partition(reqBuf, ddl_ctrl);
    ddl_ctrl->error_code = result;
    errno_t err_code = memcpy_s(reqBuf, ddl_ctrl->msg_len, ddl_ctrl, sizeof(ddl_ctrl_t));
    if (err_code != EOK) {
        CT_LOG_RUN_ERR("Failed(%d) to copy the object item.", err_code);
        CM_FREE_PTR(reqBuf);
        return CT_ERROR;
    }
    result = tse_mq_set_batch_data(message_block, reqBuf, ddl_ctrl->msg_len);
    CM_FREE_PTR(reqBuf);
    return result;
}

EXTER_ATTACK int tse_mq_rename_table(dsw_message_block_t *message_block)
{
    int result;
    void *req = message_block->seg_buf[0];
    ddl_ctrl_t *ddl_ctrl = (ddl_ctrl_t *) req;
    result = tse_rename_table((char *) req + sizeof(ddl_ctrl_t), ddl_ctrl);
    ddl_ctrl->error_code = result;
    return result;
}

EXTER_ATTACK int tse_mq_alter_table(dsw_message_block_t *message_block)
{
    int result = CT_ERROR;
    void *req = message_block->seg_buf[0];
    ddl_ctrl_t *ddl_ctrl = (ddl_ctrl_t *) req;
    CT_RETURN_IFERR(tse_check_ddl_msg_len(ddl_ctrl->msg_len));
    uint8_t* reqBuf = (uint8_t *)malloc(ddl_ctrl->msg_len);
    if (reqBuf == NULL) {
        CT_LOG_RUN_ERR("tse_mq_alter_table apply for reqBuf failed,size:%u", ddl_ctrl->msg_len);
        return result;
    }
    int ret = tse_mq_get_batch_data(message_block, reqBuf, ddl_ctrl->msg_len);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("tse_mq_get_batch_data failed in tse_mq_alter_table,size:%u", ddl_ctrl->msg_len);
        CM_FREE_PTR(reqBuf);
        return result;
    }
    result = tse_alter_table(reqBuf, ddl_ctrl);
    ddl_ctrl->error_code = result;
    errno_t err_code = memcpy_s(reqBuf, ddl_ctrl->msg_len, ddl_ctrl, sizeof(ddl_ctrl_t));
    if (err_code != EOK) {
        CT_LOG_RUN_ERR("Failed(%d) to copy the object item.", err_code);
        CM_FREE_PTR(reqBuf);
        return CT_ERROR;
    }
    result = tse_mq_set_batch_data(message_block, reqBuf, ddl_ctrl->msg_len);
    CM_FREE_PTR(reqBuf);
    return result;
}

EXTER_ATTACK int tse_mq_get_serial_value(dsw_message_block_t *message_block)
{
    int result;
    struct get_serial_val_request *req = message_block->seg_buf[0];
    CT_RETVALUE_IFTRUE((req->flag.auto_inc_step == 0), CT_ERROR);
    uint64_t value;
    result = tse_get_serial_value(&req->tch, &value, req->flag);
    if (result == CT_SUCCESS) {
        req->value = value;
    }
    req->result = result;
    return req->result;
}

EXTER_ATTACK int tse_mq_drop_table(dsw_message_block_t *message_block)
{
    int result;
    void *req = message_block->seg_buf[0];
    ddl_ctrl_t *ddl_ctrl = (ddl_ctrl_t *) req;
    result = tse_drop_table((char *) req + sizeof(ddl_ctrl_t), ddl_ctrl);
    ddl_ctrl->error_code = result;
    return result;
}

EXTER_ATTACK int tse_mq_execute_mysql_ddl_sql(dsw_message_block_t *message_block)
{
    int result;
    struct execute_mysql_ddl_sql_request *req = message_block->seg_buf[0];
    result = tse_execute_mysql_ddl_sql(&req->tch, &req->broadcast_req, req->allow_fail);
    req->result = result;
    return req->result;
}

EXTER_ATTACK int tse_mq_invalidate_mysql_dd_cache(dsw_message_block_t *message_block)
{
    int result;
    struct invalidate_mysql_dd_request *req = message_block->seg_buf[0];
    result = tse_broadcast_mysql_dd_invalidate(&req->tch, &req->broadcast_req);
    req->result = result;
    return req->result;
}

EXTER_ATTACK int tse_mq_broadcast_rewrite_sql(dsw_message_block_t *message_block)
{
    int result;
    struct execute_mysql_ddl_sql_request *req = message_block->seg_buf[0];
    result = tse_broadcast_rewrite_sql(&req->tch, &req->broadcast_req, req->allow_fail);
    req->result = result;
    return req->result;
}

EXTER_ATTACK int tse_mq_create_tablespace(dsw_message_block_t *message_block)
{
    int result;
    void *req = message_block->seg_buf[0];
    ddl_ctrl_t *ddl_ctrl = (ddl_ctrl_t *)req;
    result = tse_create_tablespace((char *)req + sizeof(ddl_ctrl_t), ddl_ctrl);
    ddl_ctrl->error_code = result;
    return result;
}

EXTER_ATTACK int tse_mq_alter_tablespace(dsw_message_block_t *message_block)
{
    int result;
    void *req = message_block->seg_buf[0];
    ddl_ctrl_t *ddl_ctrl = (ddl_ctrl_t *)req;
    result = tse_alter_tablespace((char *)req + sizeof(ddl_ctrl_t), ddl_ctrl);
    ddl_ctrl->error_code = result;
    return result;
}

EXTER_ATTACK int tse_mq_drop_tablespace(dsw_message_block_t *message_block)
{
    int result;
    void *req = message_block->seg_buf[0];
    ddl_ctrl_t *ddl_ctrl = (ddl_ctrl_t *)req;
    result = tse_drop_tablespace((char *)req + sizeof(ddl_ctrl_t), ddl_ctrl);
    ddl_ctrl->error_code = result;
    return result;
}

EXTER_ATTACK int tse_mq_get_max_sessions(dsw_message_block_t *message_block)
{
    struct get_max_session_request *req = message_block->seg_buf[0];
    uint32_t max_session_per_node = 0;
    uint32_t *max_inst_num = get_ctc_max_inst_num();
    tse_get_max_sessions_per_node(&max_session_per_node);
    CT_RETVALUE_IFTRUE((*max_inst_num == 0), CT_ERROR);
    req->max_sessions = max_session_per_node / *max_inst_num;
    return CT_SUCCESS;
}

EXTER_ATTACK int tse_mq_lock_instance(dsw_message_block_t *message_block)
{
    struct lock_instance_request *req = message_block->seg_buf[0];
    req->result = tse_lock_instance(&req->is_mysqld_starting, req->lock_type, &req->tch);
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

EXTER_ATTACK int tse_mq_unlock_instance(dsw_message_block_t *message_block)
{
    struct unlock_instance_request *req = message_block->seg_buf[0];
    req->result = tse_unlock_instance(&req->is_mysqld_starting, &req->tch);
    return req->result;
}

EXTER_ATTACK int tse_mq_check_db_table_exists(dsw_message_block_t *message_block)
{
    struct check_table_exists_request *req = message_block->seg_buf[0];
    req->result = tse_check_db_table_exists(req->db, req->name, &req->is_exists);
    return req->result;
}
 
EXTER_ATTACK int tse_mq_search_metadata_switch(dsw_message_block_t *message_block)
{
    struct search_metadata_status_request *req = message_block->seg_buf[0];
    req->result = tse_search_metadata_status(&req->metadata_switch, &req->cluster_ready);
    return req->result;
}

EXTER_ATTACK int tse_mq_query_cluster_role(dsw_message_block_t *message_block)
{
    struct query_cluster_role_request *req = message_block->seg_buf[0];
    req->result = tse_query_cluster_role(&req->is_slave, &req->cluster_ready);
    return req->result;
}

EXTER_ATTACK int tse_mq_wait_instance_startuped(dsw_message_block_t *message_block)
{
    return srv_wait_instance_startuped();
}

EXTER_ATTACK int tse_mq_register_instance(dsw_message_block_t *message_block)
{
    struct register_instance_request *req = message_block->seg_buf[0];
    if (check_ctc_client_version(req->ctc_version) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Got an unsupport ctc client(version:%u).", req->ctc_version);
        req->result = REG_MISMATCH_CTC_VERSION;
        return CT_ERROR;
    }

    int client_id = message_block->head.src_nid;
    CT_RETURN_IFERR(tse_check_mq_client_id(client_id));
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

struct mq_recv_msg_node {
    enum TSE_FUNC_TYPE func_type;
    int (*deal_msg)(dsw_message_block_t *message_block);
};

static struct mq_recv_msg_node g_mq_recv_msg[] = {
    {TSE_FUNC_TYPE_OPEN_TABLE,                    tse_mq_open_table},
    {TSE_FUNC_TYPE_CLOSE_TABLE,                   tse_mq_close_table},
    {TSE_FUNC_TYPE_CLOSE_SESSION,                 tse_mq_close_session},
    {TSE_FUNC_TYPE_WRITE_ROW,                     tse_mq_write_row},
    {TSE_FUNC_TYPE_WRITE_THROUGH_ROW,             tse_mq_write_through_row},
    {TSE_FUNC_TYPE_UPDATE_ROW,                    tse_mq_update_row},
    {TSE_FUNC_TYPE_DELETE_ROW,                    tse_mq_delete_row},
    {TSE_FUNC_TYPE_RND_INIT,                      tse_mq_rnd_init},
    {TSE_FUNC_TYPE_RND_END,                       tse_mq_rnd_end},
    {TSE_FUNC_TYPE_RND_NEXT,                      tse_mq_rnd_next},
    {TSE_FUNC_TYPE_RND_PREFETCH,                  tse_mq_rnd_prefetch},
    {TSE_FUNC_TYPE_SCAN_RECORDS,                  tse_mq_scan_records},
    {TSE_FUNC_TYPE_TRX_COMMIT,                    tse_mq_trx_commit},
    {TSE_FUNC_TYPE_TRX_ROLLBACK,                  tse_mq_trx_rollback},
    {TSE_FUNC_TYPE_TRX_BEGIN,                     tse_mq_trx_begin},
    {TSE_FUNC_TYPE_LOCK_TABLE,                    tse_mq_lock_table},
    {TSE_FUNC_TYPE_UNLOCK_TABLE,                  tse_mq_unlock_table},
    {TSE_FUNC_TYPE_INDEX_END,                     tse_mq_index_end},
    {TSE_FUNC_TYPE_SRV_SET_SAVEPOINT,             tse_mq_srv_set_savepoint},
    {TSE_FUNC_TYPE_SRV_ROLLBACK_SAVEPOINT,        tse_mq_srv_rollback_savepoint},
    {TSE_FUNC_TYPE_SRV_RELEASE_SAVEPOINT,         tse_mq_srv_release_savepoint},
    {TSE_FUNC_TYPE_GENERAL_FETCH,                 tse_mq_general_fetch},
    {TSE_FUNC_TYPE_GENERAL_PREFETCH,              tse_mq_general_prefetch},
    {TSE_FUNC_TYPE_FREE_CURSORS,                  tse_mq_free_session_cursors},
    {TSE_FUNC_TYPE_GET_INDEX_NAME,                tse_mq_get_index_name},
    {TSE_FUNC_TYPE_INDEX_READ,                    tse_mq_index_read},
    {TSE_FUNC_TYPE_RND_POS,                       tse_mq_rnd_pos},
    {TSE_FUNC_TYPE_POSITION,                      tse_mq_position},
    {TSE_FUNC_TYPE_DELETE_ALL_ROWS,               tse_mq_delete_all_rows},
    {TSE_FUNC_TYPE_GET_CBO_STATS,                 tse_mq_get_cbo_stats},
    {TSE_FUNC_TYPE_WRITE_LOB,                     tse_mq_write_lob},
    {TSE_FUNC_TYPE_READ_LOB,                      tse_mq_read_lob},
    {TSE_FUNC_TYPE_CREATE_TABLE,                  tse_mq_create_table},
    {TSE_FUNC_TYPE_TRUNCATE_TABLE,                tse_mq_truncate_table},
    {TSE_FUNC_TYPE_TRUNCATE_PARTITION,            tse_mq_truncate_partition},
    {TSE_FUNC_TYPE_RENAME_TABLE,                  tse_mq_rename_table},
    {TSE_FUNC_TYPE_ALTER_TABLE,                   tse_mq_alter_table},
    {TSE_FUNC_TYPE_GET_SERIAL_VALUE,              tse_mq_get_serial_value},
    {TSE_FUNC_TYPE_DROP_TABLE,                    tse_mq_drop_table},
    {TSE_FUNC_TYPE_EXCUTE_MYSQL_DDL_SQL,          tse_mq_execute_mysql_ddl_sql},
    {TSE_FUNC_TYPE_BROADCAST_REWRITE_SQL,         tse_mq_broadcast_rewrite_sql},
    {TSE_FUNC_TYPE_CREATE_TABLESPACE,             tse_mq_create_tablespace},
    {TSE_FUNC_TYPE_ALTER_TABLESPACE,              tse_mq_alter_tablespace},
    {TSE_FUNC_TYPE_DROP_TABLESPACE,               tse_mq_drop_tablespace},
    {TSE_FUNC_TYPE_BULK_INSERT,                   tse_mq_bulk_write},
    {TSE_FUNC_TYPE_ANALYZE,                       tse_mq_analyze_table},
    {TSE_FUNC_TYPE_GET_MAX_SESSIONS,              tse_mq_get_max_sessions},
    {TSE_FUNC_LOCK_INSTANCE,                      tse_mq_lock_instance},
    {TSE_FUNC_UNLOCK_INSTANCE,                    tse_mq_unlock_instance},
    {TSE_FUNC_CHECK_TABLE_EXIST,                  tse_mq_check_db_table_exists},
    {TSE_FUNC_SEARCH_METADATA_SWITCH,             tse_mq_search_metadata_switch},
    {TSE_FUNC_QUERY_CLUSTER_ROLE,                 tse_mq_query_cluster_role},
    {TSE_FUNC_SET_CLUSTER_ROLE_BY_CANTIAN,        tse_set_cluster_role_by_cantian},
    {TSE_FUNC_PRE_CREATE_DB,                      tse_mq_pre_create_db},
    {TSE_FUNC_TYPE_DROP_TABLESPACE_AND_USER,      tse_mq_drop_tablespace_and_user},
    {TSE_FUNC_DROP_DB_PRE_CHECK,                  tse_mq_drop_db_pre_check},
    {TSE_FUNC_KILL_CONNECTION,                    tse_mq_kill_session},
    {TSE_FUNC_TYPE_INVALIDATE_OBJECT,             tse_mq_invalidate_mysql_dd_cache},
    {TSE_FUNC_TYPE_RECORD_SQL,                    ctc_mq_record_sql_for_cantian},
    /* for instance registration, should be the last */
    {TSE_FUNC_TYPE_REGISTER_INSTANCE,             tse_mq_register_instance},
    {TSE_FUNC_TYPE_WAIT_CONNETOR_STARTUPED,       tse_mq_wait_instance_startuped},
};

EXTER_ATTACK int mq_recv_msg(struct shm_seg_s *shm_seg, dsw_message_block_t *message_block)
{
    if (message_block == NULL || message_block->seg_buf[0] == NULL) {
        CT_LOG_RUN_ERR("shm message_block is invalid, null message_block ptr");
        return CT_ERROR;
    }

    int *client_id_list = get_client_id_list();
    int client_id = message_block->head.src_nid;

    if (tse_check_mq_client_id(client_id) != CT_SUCCESS) {
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
    if (cmd_type >= TSE_FUNC_TYPE_REGISTER_INSTANCE || g_mq_recv_msg[cmd_type].deal_msg == NULL) {
        CT_LOG_RUN_ERR("cmd is invalid, client_id(%d), cmd_type(%d)", client_id, message_block->head.cmd_type);
        sem_post(&message_block->head.sem);
        return result;
    }

    timeval_t tv_begin;
    mysql_record_io_stat_begin(g_mq_recv_msg[cmd_type].func_type, &tv_begin);
    
    result = g_mq_recv_msg[cmd_type].deal_msg(message_block);
    
    mysql_record_io_stat_end(g_mq_recv_msg[cmd_type].func_type, &tv_begin, result);
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
    if (tse_check_mq_client_id(client_id) != CT_SUCCESS) {
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
    if (message_block->head.cmd_type >= TSE_FUNC_TYPE_REGISTER_INSTANCE &&
        message_block->head.cmd_type < TSE_FUNC_TYPE_MYSQL_EXECUTE_UPDATE &&
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

static void tse_mq_mysql_execute_update_callback(int proc_id, void *rsp, bool *is_continue_broadcast)
{
    *is_continue_broadcast = true;
    if (rsp == NULL) {
        CT_LOG_RUN_ERR("[TSE_DDL]:rsp is null.");
        return;
    }
    
    struct execute_ddl_mysql_sql_request *tmp_rsp = (struct execute_ddl_mysql_sql_request *)rsp;
    if (tmp_rsp->result != CT_SUCCESS) {
        if (tmp_rsp->allow_fail == true) {
            *is_continue_broadcast = false;
            CT_LOG_RUN_ERR("[TSE_DDL_REWRITE]:Fail at begining. result:%d, proc_id:%d, sql:%s,"
                "user_name:%s, sql_command:%u, err_code:%d, err_msg:%s, allow_fail:%d", tmp_rsp->result, proc_id,
                sql_without_plaintext_password((tmp_rsp->broadcast_req.options & TSE_CURRENT_SQL_CONTAIN_PLAINTEXT_PASSWORD),
                tmp_rsp->broadcast_req.sql_str, sizeof(tmp_rsp->broadcast_req.sql_str)), tmp_rsp->broadcast_req.user_name,
                tmp_rsp->broadcast_req.sql_command, tmp_rsp->broadcast_req.err_code, tmp_rsp->broadcast_req.err_msg,
                tmp_rsp->allow_fail);
            return;
        }
        CT_LOG_RUN_ERR("[TSE_DDL]:remove client, proc_id:%d, sql:%s, user_name:%s, sql_command:%u, err_code:%d,"
            "allow_fail:%d", proc_id, sql_without_plaintext_password((tmp_rsp->broadcast_req.options & TSE_CURRENT_SQL_CONTAIN_PLAINTEXT_PASSWORD),
            tmp_rsp->broadcast_req.sql_str, sizeof(tmp_rsp->broadcast_req.sql_str)), tmp_rsp->broadcast_req.user_name,
            tmp_rsp->broadcast_req.sql_command, tmp_rsp->broadcast_req.err_code, tmp_rsp->allow_fail);
        remove_bad_client(proc_id);
        tmp_rsp->result = CT_SUCCESS;
    }
}

void tse_mq_rewrite_open_conn_callback(int proc_id, void *rsp, bool *is_continue_broadcast)
{
    *is_continue_broadcast = true;
    if (rsp == NULL) {
        CT_LOG_RUN_ERR("[TSE_REWRITE_CONN]:rsp is null.");
        return;
    }
    
    struct execute_ddl_mysql_sql_request *tmp_rsp = (struct execute_ddl_mysql_sql_request *)rsp;
    if (tmp_rsp->result != CT_SUCCESS) {
        // 有一个节点开连接失败，停止流程, 返错
        *is_continue_broadcast = false;
        CT_LOG_RUN_ERR("[TSE_REWRITE_CONN]:open connection failed, proc_id:%d, sql:%s, user_name:%s,"
            "sql_command:%u, err_code:%d,", proc_id,
            sql_without_plaintext_password((tmp_rsp->broadcast_req.options & TSE_CURRENT_SQL_CONTAIN_PLAINTEXT_PASSWORD),
            tmp_rsp->broadcast_req.sql_str, sizeof(tmp_rsp->broadcast_req.sql_str)), tmp_rsp->broadcast_req.user_name,
            tmp_rsp->broadcast_req.sql_command,
            tmp_rsp->broadcast_req.err_code);
    }
}

static void tse_mq_unlock_tables_callback(int proc_id, void *rsp, bool *is_continue_broadcast)
{
    *is_continue_broadcast = true;
    if (rsp == NULL) {
        CT_LOG_RUN_ERR("[TSE_UNLOCK_TABLE]:rsp is null.");
        return;
    }

    struct tse_unlock_tables_request *tmp_rsp = (struct tse_unlock_tables_request *)rsp;
    if (tmp_rsp->result != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[TSE_UNLOCK_TABLE]:remove client, proc_id = %d", proc_id);
        remove_bad_client(proc_id);
        tmp_rsp->result = CT_SUCCESS;
    }
}

static void tse_mq_lock_tables_callback(int proc_id, void *rsp, bool *is_continue_broadcast)
{
    *is_continue_broadcast = true;
    if (rsp == NULL) {
        CT_LOG_RUN_ERR("[TSE_LOCK_TABLE]:rsp is null.");
        return;
    }
    
    struct tse_lock_tables_request *tmp_rsp = (struct tse_lock_tables_request *)rsp;
    if (tmp_rsp->result != CT_SUCCESS) {
        CT_LOG_RUN_ERR("[TSE_LOCK_TABLE]:lock table failed, proc_id:%d, db:%s, table:%s", proc_id,
            tmp_rsp->lock_info.db_name, tmp_rsp->lock_info.table_name);
        *is_continue_broadcast = false;
    }
}

struct mq_send_msg_callback_map {
    enum TSE_FUNC_TYPE func_type;
    void (*send_msg_callback)(int proc_id, void *rsp, bool *is_continue_broadcast);
};

static struct mq_send_msg_callback_map g_mq_send_msg_callback[] = {
    {TSE_FUNC_TYPE_MYSQL_EXECUTE_UPDATE,         tse_mq_mysql_execute_update_callback},
    {TSE_FUNC_TYPE_UNLOCK_TABLES,                tse_mq_unlock_tables_callback},
    {TSE_FUNC_TYPE_LOCK_TABLES,                  tse_mq_lock_tables_callback},
    {TSE_FUNC_TYPE_EXECUTE_REWRITE_OPEN_CONN,    tse_mq_rewrite_open_conn_callback},
};

void mq_send_msg_callback(enum TSE_FUNC_TYPE func_type, int proc_id, void *rsp, bool *is_continue_broadcast)
{
    for (int i = 0; i < sizeof(g_mq_send_msg_callback) / sizeof(g_mq_send_msg_callback[0]); i++) {
        if (g_mq_send_msg_callback[i].func_type == func_type) {
            g_mq_send_msg_callback[i].send_msg_callback(proc_id, rsp, is_continue_broadcast);
            break;
        }
    }
}

static int tse_send_msg_to_one_client(void *shm_inst, enum TSE_FUNC_TYPE func_type,
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
                CT_LOG_RUN_WAR("wait sem again, client_id:(%d), client_status:(%d), errno(%d)",
                               client_id, client_id_list[client_id], errno);
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

int tse_mq_deal_func(void *shm_inst, enum TSE_FUNC_TYPE func_type, void *request)
{
    dsw_message_block_t *msg = (dsw_message_block_t *)shm_alloc(shm_inst, sizeof(dsw_message_block_t));
    database_t *db = &g_instance->kernel.db;
    bool is_slave_cluster = !DB_IS_PRIMARY(db);
    if (msg == NULL) {
        CT_LOG_RUN_ERR("[TSE_SHM]:msg init failed, msg_type(%d)", func_type);
        return -1;
    }
    int ret = sem_init(&msg->head.sem, 1, 0);
    if (ret != 0) {
        CT_LOG_RUN_ERR("[TSE_SHM]:sem init failed, msg_type(%d), ret(%d)", func_type, ret);
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
        int send_ret = tse_send_msg_to_one_client(shm_inst, func_type, msg, i, &is_continue_broadcast);
        if (!is_slave_cluster && send_ret != 0) {
            CT_LOG_RUN_ERR("[TSE_SHM]:failed to sent msg to a client, client_id(%d), msg_type(%d)", i, func_type);
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
        CT_LOG_RUN_ERR("[TSE_SHM]:sem destory failed, ret:%d, func_type:%d.", ret, func_type);
    }
    shm_free(shm_inst, msg);
    if (is_slave_cluster) {
        // At least one mysql should execute succeed in slave cluster.
        if (at_least_one_succeed == CT_SUCCESS) {
            return ret;
        } else {
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
