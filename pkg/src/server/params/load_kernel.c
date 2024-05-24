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
 * load_kernel.c
 *
 *
 * IDENTIFICATION
 * src/server/params/load_kernel.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_module.h"
#include "srv_instance.h"
#include "srv_param_common.h"
#include "load_kernel.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RM_SESSION_RATIO 1.2
#define SGA_PAD(buf_size, page_size) ((buf_size) + CM_ALIGN8(((buf_size) / (page_size)) * sizeof(uint32)))

static status_t srv_get_page_size_param(knl_attr_t *attr)
{
    CT_RETURN_IFERR(srv_get_param_size_uint32("PAGE_SIZE", &attr->page_size));
    if (!(attr->page_size == 8192 || attr->page_size == 16384 || attr->page_size == 32768)) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "PAGE_SIZE");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}


/**
 * get the value for column count parameter
 */
static status_t srv_get_max_column_count_param(knl_attr_t *attr)
{
    CT_RETURN_IFERR(srv_get_param_uint32("MAX_COLUMN_COUNT", &attr->max_column_count));
    if (!(attr->max_column_count == 1024 || attr->max_column_count == 2048 || attr->max_column_count == 3072 ||
        attr->max_column_count == 4096)) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "COLUMN_COUNT");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t srv_get_ini_trans_param(knl_attr_t *attr)
{
    CT_RETURN_IFERR(srv_get_param_uint32("INI_TRANS", &attr->initrans));
    if (attr->initrans > CT_MAX_TRANS || attr->initrans <= 0) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "INI_TRANS", (int64)1, (int64)CT_MAX_TRANS);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t srv_get_cr_mode_param(knl_attr_t *attr)
{
    char *value;

    value = srv_get_param("CR_MODE");
    if (cm_str_equal_ins(value, "PAGE")) {
        attr->cr_mode = CR_PAGE;
    } else if (cm_str_equal_ins(value, "ROW")) {
        attr->cr_mode = CR_ROW;
    } else {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "CR_MODE");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t srv_get_row_format_param(knl_attr_t *attr)
{
    char *value;
    value = srv_get_param("ROW_FORMAT");
    if (cm_str_equal_ins(value, "CSF")) {
        attr->row_format = ROW_FORMAT_CSF;
    } else if (cm_str_equal_ins(value, "ASF")) {
        attr->row_format = ROW_FORMAT_ASF;
    } else {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "ROW_FORMAT");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t srv_get_undo_segments_param(knl_attr_t *attr)
{
    if (srv_get_param_uint32("_UNDO_SEGMENTS", &attr->undo_segments) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (attr->undo_segments < CT_MIN_UNDO_SEGMENT || attr->undo_segments > CT_MAX_UNDO_SEGMENT) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_UNDO_SEGMENTS");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t srv_get_undo_active_segments_param(knl_attr_t *attr)
{
    if (srv_get_param_uint32("_UNDO_ACTIVE_SEGMENTS", &attr->undo_active_segments) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (attr->undo_active_segments < CT_MIN_UNDO_ACTIVE_SEGMENT ||
        attr->undo_active_segments > CT_MAX_UNDO_ACTIVE_SEGMENT) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_UNDO_ACTIVE_SEGMENTS");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t srv_get_auton_trans_segments_param(knl_attr_t *attr)
{
    if (srv_get_param_uint32("_UNDO_AUTON_TRANS_SEGMENTS", &attr->undo_auton_trans_segments) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (attr->undo_auton_trans_segments < CT_MIN_AUTON_TRANS_SEGMENT ||
        attr->undo_auton_trans_segments >= CT_MAX_UNDO_SEGMENT) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_UNDO_AUTON_TRANS_SEGMENTS");
        return CT_ERROR;
    }

    if (attr->undo_auton_trans_segments >= attr->undo_segments) {
        attr->undo_auton_trans_segments = attr->undo_segments - 1;
    }

    return CT_SUCCESS;
}

static status_t srv_get_default_space_type_param(knl_attr_t *attr)
{
    char *value = srv_get_param("DEFAULT_TABLESPACE_TYPE");

    if (cm_str_equal_ins(value, "NORMAL")) {
        attr->default_space_type = SPACE_NORMAL;
    } else if (cm_str_equal_ins(value, "BITMAP")) {
        attr->default_space_type = SPACE_BITMAP;
    } else {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "DEFAULT_TABLESPACE_TYPE");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t srv_get_vma_params(knl_attr_t *attr)
{
    CT_RETURN_IFERR(srv_get_param_uint32("_VMP_CACHES_EACH_SESSION", &attr->vmp_cache_pages));

    CT_RETURN_IFERR(srv_get_param_size_uint64("VARIANT_MEMORY_AREA_SIZE", &attr->vma_size));
    if (attr->vma_size < CT_MIN_VMA_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "VARIANT_MEMORY_AREA_SIZE", CT_MIN_VMA_SIZE);
        return CT_ERROR;
    }
    if (attr->vma_size > CT_MAX_SGA_BUF_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "VARIANT_MEMORY_AREA_SIZE", CT_MAX_SGA_BUF_SIZE);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_size_uint64("LARGE_VARIANT_MEMORY_AREA_SIZE", &attr->large_vma_size));
    if (attr->large_vma_size < CT_MIN_LARGE_VMA_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "LARGE_VARIANT_MEMORY_AREA_SIZE", CT_MIN_LARGE_VMA_SIZE);
        return CT_ERROR;
    }
    if (attr->large_vma_size > CT_MAX_SGA_BUF_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "LARGE_VARIANT_MEMORY_AREA_SIZE", CT_MAX_SGA_BUF_SIZE);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("_VMP_CACHES_EACH_SESSION", &attr->vmp_cache_pages));
    CT_RETURN_IFERR(srv_get_param_bool32("_VMA_MEM_CHECK", &g_vma_mem_check));
    return CT_SUCCESS;
}

static status_t srv_get_pma_params(knl_attr_t *attr)
{
    uint64 hash_area_size;
    CT_RETURN_IFERR(srv_get_param_size_uint64("PMA_BUFFER_SIZE", &attr->pma_size));
    CT_RETURN_IFERR(srv_verf_param_uint64("PMA_BUFFER_SIZE", attr->pma_size, 0, PMA_MAX_SIZE));

    CT_RETURN_IFERR(srv_get_param_size_uint64("HASH_AREA_SIZE", &hash_area_size));
    CT_RETURN_IFERR(srv_verf_param_uint64("HASH_AREA_SIZE", hash_area_size, 0, PMA_MAX_SIZE));

    // adjust hash area size
    g_instance->sql.hash_area_size = CM_CALC_ALIGN(hash_area_size, PMA_PAGE_SIZE);

    // adjust private memory area size
    uint64 page_count = attr->pma_size / PMA_PAGE_SIZE;
    uint64 pool_size = page_count * sizeof(pm_pool_t);
    uint64 maps_size = page_count * sizeof(uint32) * VM_PAGES_PER_PPAGE;
    uint64 buf_size = page_count * (PMA_PAGE_SIZE + sizeof(uint32)) + pool_size + maps_size;
    attr->pma_size = CM_CALC_ALIGN(buf_size, CT_MAX_ALIGN_SIZE_4K);
    return CT_SUCCESS;
}

static status_t srv_get_pool_params(knl_attr_t *attr)
{
    // private pool buffer
    CT_RETURN_IFERR(srv_get_vma_params(attr));
    CT_RETURN_IFERR(srv_get_pma_params(attr));

    // shared pool buffer
    CT_RETURN_IFERR(srv_get_param_size_uint64("SHARED_POOL_SIZE", &attr->shared_area_size));
    if (attr->shared_area_size < CT_MIN_SHARED_POOL_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "SHARED_POOL_SIZE", CT_MIN_SHARED_POOL_SIZE);
        return CT_ERROR;
    }
    if (attr->shared_area_size > CT_MAX_SGA_BUF_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "SHARED_POOL_SIZE", CT_MAX_SGA_BUF_SIZE);
        return CT_ERROR;
    }

    attr->shared_area_size = SGA_PAD(attr->shared_area_size, CT_SHARED_PAGE_SIZE);

    CT_RETURN_IFERR(srv_get_param_double("_SQL_POOL_FACTOR", &attr->sql_pool_factor));
    if (attr->sql_pool_factor < CT_MIN_SQL_POOL_FACTOR || attr->sql_pool_factor > CT_MAX_SQL_POOL_FACTOR) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_SQL_POOL_FACTOR");
        return CT_ERROR;
    }

    // large pool buffer
    CT_RETURN_IFERR(srv_get_param_size_uint64("LARGE_POOL_SIZE", &attr->large_pool_size));
    if (attr->large_pool_size < CT_MIN_LARGE_POOL_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "LARGE_POOL_SIZE", CT_MIN_LARGE_POOL_SIZE);
        return CT_ERROR;
    }
    if (attr->large_pool_size > CT_MAX_SGA_BUF_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "LARGE_POOL_SIZE", CT_MAX_SGA_BUF_SIZE);
        return CT_ERROR;
    }
    attr->large_pool_size = SGA_PAD(attr->large_pool_size, CT_LARGE_PAGE_SIZE);

    // buddy pool buffer
    attr->buddy_init_size = BUDDY_INIT_BLOCK_SIZE;
    attr->buddy_max_size = BUDDY_MEM_POOL_INIT_SIZE;

    return CT_SUCCESS;
}

static status_t srv_get_log_buffer_param(knl_attr_t *attr)
{
    CT_RETURN_IFERR(srv_get_param_size_uint64("LOG_BUFFER_SIZE", &attr->log_buf_size));
    if (attr->log_buf_size < CT_MIN_LOG_BUFFER_SIZE || attr->log_buf_size > CT_MAX_LOG_BUFFER_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "LOG_BUFFER_SIZE", CT_MIN_LOG_BUFFER_SIZE, CT_MAX_LOG_BUFFER_SIZE);
        return CT_ERROR;
    }
    attr->lgwr_buf_size = attr->log_buf_size / 2;
    if (cm_get_cipher_len((uint32)attr->lgwr_buf_size, (uint32 *)&attr->lgwr_cipher_buf_size) != CT_SUCCESS) {
        return CT_ERROR;
    }
    knl_panic(attr->lgwr_cipher_buf_size >= attr->lgwr_buf_size);
    if (attr->lgwr_cipher_buf_size < attr->lgwr_buf_size) {
        CT_LOG_RUN_ERR("ERROR: wrong lgwr_cipher_buf_size");
        return CT_ERROR;
    }
    attr->lgwr_cipher_buf_size += sizeof(cipher_ctrl_t);
    attr->lgwr_cipher_buf_size = CM_CALC_ALIGN(attr->lgwr_cipher_buf_size, SIZE_K(4));
    attr->lgwr_buf_size = attr->lgwr_cipher_buf_size;

    CT_RETURN_IFERR(srv_get_param_uint32("LOG_BUFFER_COUNT", &attr->log_buf_count));
    if (!(attr->log_buf_count > 0 && attr->log_buf_count <= CT_MAX_LOG_BUFFERS)) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "LOG_BUFFER_COUNT");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t srv_get_ckpt_param(knl_attr_t *attr)
{
    CT_RETURN_IFERR(srv_get_param_bool32("_CHECKPOINT_MERGE_IO", &attr->ckpt_flush_neighbors));

    CT_RETURN_IFERR(srv_get_param_uint32("CHECKPOINT_PAGES", &attr->ckpt_interval));
    if (attr->ckpt_interval == 0) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "CHECKPOINT_PAGES", (int64)1);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("CHECKPOINT_PERIOD", &attr->ckpt_timeout));
    if (attr->ckpt_timeout == 0) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "CHECKPOINT_PERIOD", (int64)1);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("CHECKPOINT_GROUP_SIZE", &attr->ckpt_group_size));
    if (attr->ckpt_group_size == 0) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "CHECKPOINT_GROUP_SIZE", (int64)1);
        return CT_ERROR;
    }

    if (attr->ckpt_group_size > CT_MAX_CKPT_GROUP_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "CHECKPOINT_GROUP_SIZE", (int64)CT_MAX_CKPT_GROUP_SIZE);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("CHECKPOINT_IO_CAPACITY", &attr->ckpt_io_capacity));
    if (attr->ckpt_io_capacity == 0) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "CHECKPOINT_IO_CAPACITY", (int64)1);
        return CT_ERROR;
    }

    if (attr->ckpt_io_capacity > attr->ckpt_group_size) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "CHECKPOINT_IO_CAPACITY", (int64)attr->ckpt_group_size);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}
static status_t srv_get_temp_buffer_param(knl_attr_t *attr)
{
    CT_RETURN_IFERR(srv_get_param_size_uint64("TEMP_BUFFER_SIZE", &attr->temp_buf_size));

    if (attr->temp_buf_size < CT_MIN_TEMP_BUFFER_SIZE || attr->temp_buf_size > CT_MAX_TEMP_BUFFER_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "TEMP_BUFFER_SIZE", CT_MIN_TEMP_BUFFER_SIZE, CT_MAX_TEMP_BUFFER_SIZE);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("MAX_TEMP_TABLES", &attr->max_temp_tables));

    if (attr->max_temp_tables < CT_RESERVED_TEMP_TABLES) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "MAX_TEMP_TABLES", CT_RESERVED_TEMP_TABLES);
        return CT_ERROR;
    }

    if (attr->max_temp_tables > CT_MAX_TEMP_TABLES) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "MAX_TEMP_TABLES", (int64)CT_MAX_TEMP_TABLES);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("TEMP_POOL_NUM", &attr->temp_pool_num));
    if (attr->temp_pool_num > CT_MAX_TEMP_POOL_NUM || attr->temp_pool_num <= 0) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "TEMP_POOL_NUM", (int64)1, (int64)CT_MAX_TEMP_POOL_NUM);
        return CT_ERROR;
    }

    return srv_get_param_uint32("_MAX_VM_FUNC_STACK_COUNT", &g_vm_max_stack_count);
}

static status_t srv_get_qos_params(knl_attr_t *attr)
{
    CT_RETURN_IFERR(srv_get_param_bool32("_ENABLE_QOS", &attr->enable_qos));

    CT_RETURN_IFERR(srv_get_param_double("_QOS_CTRL_FACTOR", &attr->qos_factor));
    if (attr->qos_factor > CT_MAX_QOS_CTRL_FACTOR || attr->qos_factor <= CT_MIN_QOS_CTRL_FACTOR) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_QOS_CTRL_FACTOR");
        return CT_ERROR;
    }
    attr->qos_threshold = (uint32)(int32)(attr->cpu_count * attr->qos_factor);

    CT_RETURN_IFERR(srv_get_param_uint32("_QOS_SLEEP_TIME", &attr->qos_sleep_time));
    if (attr->qos_sleep_time <= 0) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_QOS_SLEEP_TIME");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("_QOS_RANDOM_RANGE", &attr->qos_random_range));
    if (attr->qos_random_range <= 0) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_QOS_RANDOM_RANGE");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t srv_get_thread_stack_size(knl_attr_t *attr)
{
    CT_RETURN_IFERR(srv_get_param_size_uint64("_THREAD_STACK_SIZE", &attr->thread_stack_size));

    long stack_rlimit = cm_get_os_thread_stack_rlimit();
    if (attr->thread_stack_size > (uint64)(stack_rlimit - CT_STACK_DEPTH_SLOP) ||
        attr->thread_stack_size < CT_MIN_THREAD_STACK_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "_THREAD_STACK_SIZE", (int64)CT_MIN_THREAD_STACK_SIZE,
            (int64)(stack_rlimit - CT_STACK_DEPTH_SLOP));
        return CT_ERROR;
    }

    attr->reactor_thread_stack_size = attr->thread_stack_size;
    return CT_SUCCESS;
}

static status_t srv_get_file_options_params(knl_attr_t *attr)
{
    const char *value = srv_get_param("FILE_OPTIONS");
    attr->enable_asynch = CT_FALSE;
    attr->enable_directIO = CT_FALSE;
    attr->enable_logdirectIO = CT_FALSE;
    attr->enable_dsync = CT_FALSE;
    attr->enable_fdatasync = CT_FALSE;
    attr->enable_OSYNC = CT_FALSE;

    if (cm_str_equal_ins(value, "NONE")) {
        attr->enable_OSYNC = CT_TRUE;
        return CT_SUCCESS;
    }

    if (cm_str_equal_ins(value, "DIRECTIO")) {
        attr->enable_logdirectIO = CT_TRUE;
        attr->enable_OSYNC = CT_TRUE;
        return CT_SUCCESS;
    }

    if (cm_str_equal_ins(value, "FULLDIRECTIO")) {
        attr->enable_directIO = CT_TRUE;
        attr->enable_logdirectIO = CT_TRUE;
        attr->enable_OSYNC = CT_TRUE;
        return CT_SUCCESS;
    }

    if (cm_str_equal_ins(value, "ASYNCH")) {
        attr->enable_asynch = CT_TRUE;
        attr->enable_directIO = CT_TRUE;
        attr->enable_logdirectIO = CT_TRUE;
        return CT_SUCCESS;
    }

    if (cm_str_equal_ins(value, "DSYNC")) {
        attr->enable_dsync = CT_TRUE;
        return CT_SUCCESS;
    }

    if (cm_str_equal_ins(value, "FDATASYNC")) {
        attr->enable_fdatasync = CT_TRUE;
        return CT_SUCCESS;
    }

    if (cm_str_equal_ins(value, "SETALL")) {
        attr->enable_asynch = CT_TRUE;
        attr->enable_directIO = CT_TRUE;
        attr->enable_logdirectIO = CT_TRUE;
        return CT_SUCCESS;
    }

    CT_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "FILE_OPTIONS", value);
    return CT_ERROR;
}

static status_t srv_get_ha_params(knl_attr_t *attr)
{
    errno_t errcode;
    uint32 host_cnt = 0;
    uint64 pkg_size;

    CT_RETURN_IFERR(srv_get_param_bool32("_BACKUP_LOG_PARALLEL", &attr->backup_log_prealloc));
    CT_RETURN_IFERR(srv_get_param_bool32("_DOUBLEWRITE", &attr->enable_double_write));
    CT_RETURN_IFERR(srv_get_param_uint32("BUILD_KEEP_ALIVE_TIMEOUT", &attr->build_keep_alive_timeout));
    if (attr->build_keep_alive_timeout < CT_BUILD_MIN_WAIT_TIME) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "BUILD_KEEP_ALIVE_TIMEOUT", (int64)CT_BUILD_MIN_WAIT_TIME);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("REPL_WAIT_TIMEOUT", &attr->repl_wait_timeout));
    if (attr->repl_wait_timeout < CT_REPL_MIN_WAIT_TIME) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "REPL_WAIT_TIMEOUT", (int64)CT_REPL_MIN_WAIT_TIME);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_size_uint64("_REPL_MAX_PKG_SIZE", &pkg_size));
    if (pkg_size != 0 && (pkg_size < CT_MIN_REPL_PKG_SIZE || pkg_size > CT_MAX_REPL_PKG_SIZE)) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "_REPL_MAX_PKG_SIZE", CT_MIN_REPL_PKG_SIZE, CT_MAX_REPL_PKG_SIZE);
        return CT_ERROR;
    }
    (void)cm_atomic_set(&attr->repl_pkg_size, (int64)pkg_size);

    attr->repl_port = g_instance->lsnr.tcp_replica.port;
    CT_RETURN_IFERR(srv_get_param_bool32("REPL_AUTH", &attr->repl_auth));
    CT_RETURN_IFERR(srv_get_param_bool32("REPL_SCRAM_AUTH", &attr->repl_scram_auth));

    if (!attr->repl_auth && attr->repl_scram_auth) {
        CT_LOG_RUN_INF("REPL_AUTH is false, set REPL_SCRAM_AUTH to true will not work. "
            "If it is running in standalone mode, please ignore this item");
    }

    const char *value = srv_get_param("REPL_TRUST_HOST");
    if (strlen(value) == 0) {
        g_instance->kernel.attr.repl_trust_host[0] = '\0';
        return CT_SUCCESS;
    }

    if (cm_verify_lsnr_addr(value, (uint32)strlen(value), &host_cnt) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "REPL_TRUST_HOST");
        return CT_ERROR;
    }

    if (host_cnt > CT_MAX_LSNR_HOST_COUNT) {
        CT_THROW_ERROR(ERR_IPADDRESS_NUM_EXCEED, CT_MAX_LSNR_HOST_COUNT);
        return CT_ERROR;
    }

    errcode = strncpy_s(g_instance->kernel.attr.repl_trust_host, CT_HOST_NAME_BUFFER_SIZE * CT_MAX_LSNR_HOST_COUNT,
        value, strlen(value));
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t srv_get_dblink_param(knl_attr_t *attr)
{
    CT_RETURN_IFERR(srv_get_param_uint32("MAX_LINK_TABLES", &attr->max_link_tables));
    if (attr->max_link_tables > CT_MAX_LINK_TABLES) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "MAX_LINK_TABLES", 0, CT_MAX_LINK_TABLES);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t srv_get_cpu_node_bind_param(knl_attr_t *attr)
{
    text_t text, num_text;
    char buf[CT_NUMBER_BUFFER_SIZE];
    uint32 max_cpus = cm_sys_get_nprocs();

    char *value = srv_get_param("CPU_NODE_BIND");
    if (CM_IS_EMPTY_STR(value)) {
        attr->cpu_count = max_cpus;
        attr->cpu_bind_lo = 0;
        attr->cpu_bind_hi = max_cpus - 1;
        PRTS_RETURN_IFERR(snprintf_s(buf, sizeof(buf), sizeof(buf) - 1, "%u %u", 0, max_cpus - 1));
        return cm_alter_config(&g_instance->config, "CPU_NODE_BIND", buf, CONFIG_SCOPE_MEMORY, CT_TRUE);
    }
    cm_str2text(value, &text);

    if (!cm_fetch_text(&text, ' ', '\0', &num_text) || text.len == 0 || num_text.len == 0) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "CPU_NODE_BIND");
        return CT_ERROR;
    }

    if (cm_text2uint32(&num_text, &attr->cpu_bind_lo) != CT_SUCCESS ||
        cm_text2uint32(&text, &attr->cpu_bind_hi) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "CPU_NODE_BIND");
        return CT_ERROR;
    }

    if (attr->cpu_bind_hi >= max_cpus || attr->cpu_bind_hi < attr->cpu_bind_lo) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "CPU_NODE_BIND");
        return CT_ERROR;
    }
    attr->cpu_count = attr->cpu_bind_hi - attr->cpu_bind_lo + 1;
    return CT_SUCCESS;
}

static status_t srv_get_isolevel_param(char *param_name, uint8 *param_value)
{
    char *value = srv_get_param(param_name);
    if (cm_str_equal_ins(value, "RC")) {
        *param_value = (uint8)ISOLATION_READ_COMMITTED;
    } else if (cm_str_equal_ins(value, "CC")) {
        *param_value = (uint8)ISOLATION_CURR_COMMITTED;
    } else {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t srv_get_ctrllog_backup_level_param(knl_attr_t *attr)
{
    char *value = srv_get_param("CTRLLOG_BACKUP_LEVEL");

    if (cm_str_equal_ins(value, "NONE")) {
        attr->ctrllog_backup_level = CTRLLOG_BACKUP_LEVEL_NONE;
    } else if (cm_str_equal_ins(value, "TYPICAL")) {
        attr->ctrllog_backup_level = CTRLLOG_BACKUP_LEVEL_TYPICAL;
    } else if (cm_str_equal_ins(value, "FULL")) {
        attr->ctrllog_backup_level = CTRLLOG_BACKUP_LEVEL_FULL;
    } else {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "DEFAULT_TABLESPACE_TYPE");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t srv_get_checksum_param(char *param_name, uint32 *param_value)
{
    char *value = srv_get_param(param_name);
    if (cm_str_equal_ins(value, "OFF")) {
        *param_value = (uint32)CKS_OFF;
    } else if (cm_str_equal_ins(value, "TYPICAL")) {
        *param_value = (uint32)CKS_TYPICAL;
    } else if (cm_str_equal_ins(value, "FULL")) {
        *param_value = (uint32)CKS_FULL;
    } else {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t srv_get_default_page_clean_mode_param(knl_attr_t *attr)
{
    char *value = srv_get_param("PAGE_CLEAN_MODE");

    if (cm_str_equal_ins(value, "SINGLE")) {
        attr->page_clean_mode = PAGE_CLEAN_MODE_SINGLESET;
    } else if (cm_str_equal_ins(value, "ALL")) {
        attr->page_clean_mode = PAGE_CLEAN_MODE_ALLSET;
    } else {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "PAGE_CLEAN_MODE");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t srv_check_enable_raft(knl_attr_t *attr)
{
    char *value = NULL;
    attr->enable_raft = CT_FALSE;

    value = srv_get_param("ENABLE_RAFT");
    if (cm_str_equal_ins(value, "TRUE")) {
#ifdef WIN32
        CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "raft parameter for windows");
        attr->enable_raft = CT_FALSE;
#else
        attr->enable_raft = CT_TRUE;
#endif
    } else {
        if (!cm_str_equal_ins(value, "FALSE")) {
            CT_THROW_ERROR(ERR_INVALID_PARAMETER, "ENABLE_RAFT");
            return CT_ERROR;
        }
    }

    if (!attr->enable_raft) {
        attr->lgwr_async_buf_size = CT_SHARED_PAGE_SIZE;
        attr->lgwr_head_buf_size = CT_SHARED_PAGE_SIZE;
        return CT_SUCCESS;
    }
    return CT_SUCCESS;
}

status_t srv_check_raft_priority_type(knl_attr_t *attr)
{
    char *value = NULL;
    errno_t errcode;

    value = srv_get_param("RAFT_PRIORITY_TYPE");
    if (strlen(value) != 0) {
        if (strncmp(value, "AZFirst", strlen(value)) && strncmp(value, "External", strlen(value)) &&
            strncmp(value, "Static", strlen(value)) && strncmp(value, "Random", strlen(value))) {
            CT_THROW_ERROR(ERR_INVALID_PARAMETER, "RAFT_PRIORITY_TYPE");
            return CT_ERROR;
        }
        errcode = strncpy_s(attr->raft_priority_type, CT_FILE_NAME_BUFFER_SIZE, value, strlen(value));
        if (errcode != EOK) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
            return CT_ERROR;
        }
    } else {
        attr->raft_priority_type[0] = '\0';
    }
    return CT_SUCCESS;
}

status_t srv_check_raft_priority_level(knl_attr_t *attr)
{
    char *value = NULL;
    errno_t errcode;
    text_t text;
    uint32 num;

    value = srv_get_param("RAFT_PRIORITY_LEVEL");
    if (strlen(value) != 0) {
        cm_str2text(value, &text);
        sql_remove_quota(&text);
        if (cm_str2uint32(text.str, &num) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (num > CT_MAX_RAFT_PRIORITY_LEVEL) {
            CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "RAFT_PRIORITY_LEVEL", (int64)0,
                (int64)CT_MAX_RAFT_PRIORITY_LEVEL);
            return CT_ERROR;
        }
        errcode = strncpy_s(attr->raft_priority_level, CT_FILE_NAME_BUFFER_SIZE, value, strlen(value));
        if (errcode != EOK) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
            return CT_ERROR;
        }
    } else {
        attr->raft_priority_level[0] = '\0';
    }
    return CT_SUCCESS;
}

status_t srv_check_raft_layout_info(knl_attr_t *attr)
{
    char *value = NULL;
    errno_t errcode;

    value = srv_get_param("RAFT_LAYOUT_INFO");
    if (strlen(value) != 0) {
        errcode = strncpy_s(attr->raft_layout_info, CT_FILE_NAME_BUFFER_SIZE, value, strlen(value));
        if (errcode != EOK) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
            return CT_ERROR;
        }
    } else {
        attr->raft_layout_info[0] = '\0';
    }
    return CT_SUCCESS;
}

status_t srv_check_raft_start_mode(knl_attr_t *attr)
{
    char *value = NULL;

    attr->raft_start_mode = 0;
    value = srv_get_param("RAFT_START_MODE");
    if (strlen(value) != 0) {
        if (cm_str2uint32(value, &attr->raft_start_mode) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_INVALID_PARAMETER, "RAFT_START_MODE");
            return CT_ERROR;
        }
        if (attr->raft_start_mode > CT_MAX_RAFT_START_MODE) {
            CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "RAFT_START_MODE", (int64)0, (int64)CT_MAX_RAFT_START_MODE);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t srv_check_raft_node_id(knl_attr_t *attr)
{
    char *value = NULL;

    value = srv_get_param("RAFT_NODE_ID");
    if (strlen(value) == 0) {
        CT_THROW_ERROR(ERR_PARAMETER_CANNOT_IGNORE, "RAFT_NODE_ID");
        return CT_ERROR;
    }
    if (cm_str2uint32(value, &attr->raft_node_id) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "RAFT_NODE_ID");
        return CT_ERROR;
    }
    if (attr->raft_node_id < 1) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "RAFT_NODE_ID", (int64)1);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t srv_check_raft_log_level(knl_attr_t *attr)
{
    char *value = NULL;

    attr->raft_log_level = 2;
    value = srv_get_param("RAFT_LOG_LEVEL");
    if (strlen(value) != 0) {
        uint32 log_level;
        if (cm_str2uint32(value, &log_level) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_INVALID_PARAMETER, "RAFT_LOG_LEVEL");
            return CT_ERROR;
        }

        if (log_level > CT_MAX_RAFT_LOG_LEVELE) {
            log_level = CT_MAX_RAFT_LOG_LEVELE;
        }
        attr->raft_log_level = log_level;
    }

    return CT_SUCCESS;
}

status_t srv_check_raft_kudu_dir(knl_attr_t *attr)
{
    char *value = NULL;
    char real_path[CT_FILE_NAME_BUFFER_SIZE] = { 0 };
    errno_t errcode;

    value = srv_get_param("RAFT_KUDU_DIR");
    if (strlen(value) == 0) {
        CT_LOG_RUN_INF("kudu dir is not set, reset to default under data dir");
        attr->raft_kudu_dir[0] = '\0';
    } else {
        CT_RETURN_IFERR(realpath_file(value, real_path, CT_FILE_NAME_BUFFER_SIZE));
        errcode = strncpy_s(attr->raft_kudu_dir, CT_FILE_NAME_BUFFER_SIZE - 1, value, strlen(value));
        if (errcode != EOK) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t srv_check_raft_peer_id(knl_attr_t *attr)
{
    char *value = srv_get_param("RAFT_PEER_IDS");
    errno_t errcode;

    if (strlen(value) == 0) {
        CT_THROW_ERROR(ERR_PARAMETER_CANNOT_IGNORE, "RAFT_PEER_IDS");
        return CT_ERROR;
    }
    errcode = strncpy_s(attr->raft_peer_ids, CT_HOST_NAME_BUFFER_SIZE - 1, value, strlen(value));
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t check_raft_ip_valid(const char *ip_port)
{
    if (ip_port == NULL) {
        return CT_ERROR;
    }

    char *port = strrchr(ip_port, ':');
    if (port == NULL) {
        return CT_ERROR;
    }
    char ip[CM_MAX_IP_LEN];
    errno_t errcode = strncpy_s(ip, CM_MAX_IP_LEN, ip_port, port - ip_port);
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CT_ERROR;
    }

    sock_addr_t sock_addr;

    return cm_ipport_to_sockaddr(ip, 0, &sock_addr);
}

static status_t split_raft_ip_port(char *ip_port)
{
#ifndef WIN32
    if (ip_port == NULL) {
        return CT_ERROR;
    }
    char *raft_adds = ip_port;
    char *ip = strsep(&raft_adds, ",");
    while (ip) {
        if (check_raft_ip_valid(ip)) {
            return CT_ERROR;
        }
        ip = strsep(&raft_adds, ",");
    }
#endif

    return CT_SUCCESS;
}

static status_t split_raft_adds(const char *value, char *raft_left_addrs, char *raft_right_addrs)
{
    errno_t errcode;
    char *addrs = strchr(value, ';');
    if (addrs) {
        errcode = strncpy_s(raft_right_addrs, CT_RAFT_PEERS_BUFFER_SIZE, addrs + 1, strlen(addrs + 1));
        if (errcode != EOK) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
            return CT_ERROR;
        }

        errcode = strncpy_s(raft_left_addrs, CT_RAFT_PEERS_BUFFER_SIZE, value, addrs - value);
        if (errcode != EOK) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
            return CT_ERROR;
        }
    } else {
        raft_left_addrs[0] = '\0';
        errcode = strncpy_s(raft_right_addrs, CT_RAFT_PEERS_BUFFER_SIZE, value, strlen(value));
        if (errcode != EOK) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t srv_check_raft_local_addr(knl_attr_t *attr)
{
    char *value = NULL;
    errno_t errcode;

    value = srv_get_param("RAFT_LOCAL_ADDR");
    if (strlen(value) == 0) {
        CT_THROW_ERROR(ERR_PARAMETER_CANNOT_IGNORE, "RAFT_LOCAL_ADDR");
        return CT_ERROR;
    }

    if (check_raft_ip_valid(value)) {
        CT_THROW_ERROR(ERR_TCP_INVALID_IPADDRESS, value);
        return CT_ERROR;
    }

    errcode = strncpy_s(attr->raft_local_addr, CT_HOST_NAME_BUFFER_SIZE, value, strlen(value));
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t srv_check_raft_peer_addrs(knl_attr_t *attr)
{
    char *value = NULL;
    errno_t errcode;

    value = srv_get_param("RAFT_PEER_ADDRS");
    if (strlen(value) == 0) {
        CT_THROW_ERROR(ERR_PARAMETER_CANNOT_IGNORE, "RAFT_PEER_ADDRS");
        return CT_ERROR;
    }

    errcode = strncpy_s(attr->raft_peer_addrs, CT_RAFT_PEERS_BUFFER_SIZE, value, strlen(value));
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CT_ERROR;
    }

    char raft_right_addrs[CT_RAFT_PEERS_BUFFER_SIZE];
    char raft_left_addrs[CT_RAFT_PEERS_BUFFER_SIZE];
    if (split_raft_adds(value, raft_left_addrs, raft_right_addrs)) {
        CT_THROW_ERROR(ERR_TCP_INVALID_IPADDRESS, value);
        attr->raft_peer_addrs[0] = '\0';
        return CT_ERROR;
    }

    if (raft_right_addrs[0] != '\0') {
        if (split_raft_ip_port(raft_right_addrs)) {
            CT_THROW_ERROR(ERR_TCP_INVALID_IPADDRESS, value);
            attr->raft_peer_addrs[0] = '\0';
            return CT_ERROR;
        }
    }

    if (raft_left_addrs[0] != '\0') {
        if (split_raft_ip_port(raft_left_addrs)) {
            CT_THROW_ERROR(ERR_TCP_INVALID_IPADDRESS, value);
            attr->raft_peer_addrs[0] = '\0';
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t srv_check_raft_cmds_buffer_size(knl_attr_t *attr)
{
    char *value = NULL;
    errno_t errcode;
    text_t text;
    uint32 num;

    value = srv_get_param("RAFT_PENDING_CMDS_BUFFER_SIZE");
    if (strlen(value) != 0) {
        cm_str2text(value, &text);
        sql_remove_quota(&text);
        if (cm_str2uint32(text.str, &num) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (num == 0) {
            CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "RAFT_PENDING_CMDS_BUFFER_SIZE", (int64)1);
            return CT_ERROR;
        }
        errcode = strncpy_s(attr->raft_pending_cmds_buffer_size, CT_MAX_NAME_LEN, value, strlen(value));
        if (errcode != EOK) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
            return CT_ERROR;
        }
    } else {
        attr->raft_pending_cmds_buffer_size[0] = '\0';
    }

    return CT_SUCCESS;
}

status_t srv_check_raft_send_buffer_size(knl_attr_t *attr)
{
    char *value = NULL;
    errno_t errcode;
    text_t text;
    uint32 num;

    value = srv_get_param("RAFT_SEND_BUFFER_SIZE");
    if (strlen(value) != 0) {
        cm_str2text(value, &text);
        sql_remove_quota(&text);
        if (cm_str2uint32(text.str, &num) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (num > CT_MAX_RAFT_SEND_BUFFER_SIZE || num < 1) {
            CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "RAFT_SEND_BUFFER_SIZE", (int64)1,
                (int64)CT_MAX_RAFT_SEND_BUFFER_SIZE);
            return CT_ERROR;
        }
        errcode = strncpy_s(attr->raft_send_buffer_size, CT_MAX_NAME_LEN, value, strlen(value));
        if (errcode != EOK) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
            return CT_ERROR;
        }
    } else {
        attr->raft_send_buffer_size[0] = '\0';
    }

    return CT_SUCCESS;
}

status_t srv_check_raft_receive_buffer_size(knl_attr_t *attr)
{
    char *value = NULL;
    errno_t errcode;
    text_t text;
    uint32 num;

    value = srv_get_param("RAFT_RECEIVE_BUFFER_SIZE");
    if (strlen(value) != 0) {
        cm_str2text(value, &text);
        sql_remove_quota(&text);
        if (cm_str2uint32(text.str, &num) != CT_SUCCESS) {
            return CT_ERROR;
        }
        if (num > CT_MAX_RAFT_RECEIVE_BUFFER_SIZE || num < 1) {
            CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "RAFT_RECEIVE_BUFFER_SIZE", (int64)1,
                (int64)CT_MAX_RAFT_RECEIVE_BUFFER_SIZE);
            return CT_ERROR;
        }
        errcode = strncpy_s(attr->raft_receive_buffer_size, CT_MAX_NAME_LEN, value, strlen(value));
        if (errcode != EOK) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
            return CT_ERROR;
        }
    } else {
        attr->raft_receive_buffer_size[0] = '\0';
    }

    return CT_SUCCESS;
}

status_t srv_check_raft_entry_cache_memory_size(knl_attr_t *attr)
{
    uint64 val;
    CT_RETURN_IFERR(srv_get_param_size_uint64("RAFT_RAFT_ENTRY_CACHE_MEMORY_SIZE", &val));

    if (val == 0) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "RAFT_RAFT_ENTRY_CACHE_MEMORY_SIZE", (int64)1);
        return CT_ERROR;
    }

    int iret = sprintf_s(attr->raft_entry_cache_memory_size, CT_MAX_NAME_LEN, "%llu", val);
    if (iret == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, iret);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t srv_check_raft_max_size_per_msg(knl_attr_t *attr)
{
    uint64 val;
    CT_RETURN_IFERR(srv_get_param_size_uint64("RAFT_MAX_SIZE_PER_MSG", &val));

    if (val < CT_MIN_RAFT_PER_MSG_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "RAFT_MAX_SIZE_PER_MSG", (int64)CT_MIN_RAFT_PER_MSG_SIZE);
        return CT_ERROR;
    }

    int iret = sprintf_s(attr->raft_max_size_per_msg, CT_MAX_NAME_LEN, "%llu", val);
    if (iret == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, iret);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t srv_check_raft_mem_threshold(knl_attr_t *attr)
{
    uint64 val;
    CT_RETURN_IFERR(srv_get_param_size_uint64("RAFT_MEMORY_THRESHOLD", &val));

    int iret = sprintf_s(attr->raft_mem_threshold, CT_MAX_NAME_LEN, "%llu", val);
    if (iret == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, iret);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t srv_check_raft_election_timeout(knl_attr_t *attr)
{
    uint32 val;
    CT_RETURN_IFERR(srv_get_param_size_uint32("RAFT_ELECTION_TIMEOUT", &val));

    int iret = sprintf_s(attr->raft_election_timeout, CT_MAX_NAME_LEN, "%u", val);
    if (iret == -1) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, iret);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t srv_check_raft_log_async_buf_num(knl_attr_t *attr)
{
    char *value = NULL;

    // set async log buffer size for raft
    value = srv_get_param("RAFT_LOG_ASYNC_BUF_NUM");
    if (strlen(value) == 0) {
        CT_THROW_ERROR(ERR_PARAMETER_CANNOT_IGNORE, "RAFT_LOG_ASYNC_BUF_NUM");
        return CT_ERROR;
    }
    if (cm_str2uint32(value, &attr->raft_log_async_buffer_num) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "RAFT_LOG_ASYNC_BUF_NUM");
        return CT_ERROR;
    }

    if (attr->raft_log_async_buffer_num > CT_MAX_RAFT_LOG_ASYNC_BUF || attr->raft_log_async_buffer_num < 1) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "RAFT_LOG_ASYNC_BUF_NUM", (int64)1, (int64)CT_MAX_RAFT_LOG_ASYNC_BUF);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t srv_check_raft_failover_lib_timeout(knl_attr_t *attr)
{
    char *value = NULL;

    value = srv_get_param("RAFT_FAILOVER_LIB_TIMEOUT");
    if (strlen(value) != 0) {
        if (cm_str2uint32(value, &attr->raft_failover_lib_timeout) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_INVALID_PARAMETER, "RAFT_FAILOVER_LIB_TIMEOUT");
            return CT_ERROR;
        }

        if (attr->raft_failover_lib_timeout < CT_MIN_RAFT_FAILOVER_WAIT_TIME) {
            CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "RAFT_FAILOVER_LIB_TIMEOUT", (int64)CT_MIN_RAFT_FAILOVER_WAIT_TIME);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t srv_check_raft_tls_dir(knl_attr_t *attr)
{
    char *value = srv_get_param("RAFT_TLS_DIR");
    errno_t errcode;

    if (strlen(value) == 0) {
        CT_LOG_RUN_INF("TLS dir is not set, reset to default by lib");
        attr->raft_tls_dir[0] = '\0';
        return CT_SUCCESS;
    }

    if (verify_file_path(value) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("verify TLS dir failed");
        return CT_ERROR;
    }
    errcode = strncpy_s(attr->raft_tls_dir, CT_FILE_NAME_BUFFER_SIZE - 1, value, strlen(value));
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t srv_check_raft_token_verify(knl_attr_t *attr)
{
    char *value = srv_get_param("RAFT_TOKEN_VERIFY");
    errno_t errcode;

    if (strlen(value) == 0) {
        CT_LOG_RUN_INF("token verify is not set, reset to default by lib");
        attr->raft_token_verify[0] = '\0';
        return CT_SUCCESS;
    }

    errcode = strncpy_s(attr->raft_token_verify, CT_FILE_NAME_BUFFER_SIZE - 1, value, strlen(value));
    if (errcode != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t srv_get_raft_params(knl_attr_t *attr)
{
    CT_RETURN_IFERR(srv_check_enable_raft(attr));
    CT_RETSUC_IFTRUE(!attr->enable_raft);

    CT_RETURN_IFERR(srv_check_raft_start_mode(attr));
    CT_RETURN_IFERR(srv_check_raft_node_id(attr));
    CT_RETURN_IFERR(srv_check_raft_log_level(attr));
    CT_RETURN_IFERR(srv_check_raft_kudu_dir(attr));
    CT_RETURN_IFERR(srv_check_raft_peer_id(attr));
    CT_RETURN_IFERR(srv_check_raft_local_addr(attr));
    CT_RETURN_IFERR(srv_check_raft_peer_addrs(attr));
    CT_RETURN_IFERR(srv_check_raft_priority_type(attr));
    CT_RETURN_IFERR(srv_check_raft_priority_level(attr));
    CT_RETURN_IFERR(srv_check_raft_layout_info(attr));
    CT_RETURN_IFERR(srv_check_raft_cmds_buffer_size(attr));
    CT_RETURN_IFERR(srv_check_raft_send_buffer_size(attr));
    CT_RETURN_IFERR(srv_check_raft_receive_buffer_size(attr));
    CT_RETURN_IFERR(srv_check_raft_entry_cache_memory_size(attr));
    CT_RETURN_IFERR(srv_check_raft_max_size_per_msg(attr));
    CT_RETURN_IFERR(srv_check_raft_log_async_buf_num(attr));
    CT_RETURN_IFERR(srv_check_raft_failover_lib_timeout(attr));
    CT_RETURN_IFERR(srv_check_raft_mem_threshold(attr));
    CT_RETURN_IFERR(srv_check_raft_election_timeout(attr));

    if (srv_check_raft_tls_dir(attr) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (srv_check_raft_token_verify(attr) != CT_SUCCESS) {
        return CT_ERROR;
    }

    attr->lgwr_async_buf_size = attr->raft_log_async_buffer_num * attr->log_buf_size;
    attr->lgwr_head_buf_size = CT_SHARED_PAGE_SIZE;
    return CT_SUCCESS;
}

static status_t srv_get_idx_recycle(knl_attr_t *attr)
{
    uint32 num;
    uint64 size;
    CT_RETURN_IFERR(srv_get_param_uint32("_INDEX_RECYCLE_PERCENT", &num));
    if (num > CT_MAX_INDEX_RECYCLE_PERCENT) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_INDEX_RECYCLE_PERCENT", (int64)CT_MAX_INDEX_RECYCLE_PERCENT);
        return CT_ERROR;
    }
    attr->idx_recycle_percent = num;

    CT_RETURN_IFERR(srv_get_param_size_uint64("_INDEX_RECYCLE_SIZE", &size));
    if (size > CT_MAX_INDEX_RECYCLE_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_INDEX_RECYCLE_SIZE", (int64)CT_MAX_INDEX_RECYCLE_SIZE);
        return CT_ERROR;
    }
    if (size < CT_MIN_INDEX_RECYCLE_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_INDEX_RECYCLE_SIZE", (int64)CT_MIN_INDEX_RECYCLE_SIZE);
        return CT_ERROR;
    }
    attr->idx_recycle_size = size;

    CT_RETURN_IFERR(srv_get_param_uint32("_FORCE_INDEX_RECYCLE", &num));
    if (num > CT_MAX_INDEX_FORCE_RECYCLE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_FORCE_INDEX_RECYCLE", (int64)CT_MAX_INDEX_FORCE_RECYCLE);
        return CT_ERROR;
    }
    attr->idx_force_recycle_time = num;

    CT_RETURN_IFERR(srv_get_param_uint32("_INDEX_RECYCLE_REUSE", &num));
    if (num > CT_MAX_INDEX_RECYCLE_REUSE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_INDEX_RECYCLE_REUSE", (int64)CT_MAX_INDEX_RECYCLE_REUSE);
        return CT_ERROR;
    }
    attr->idx_recycle_reuse_time = num;

    CT_RETURN_IFERR(srv_get_param_uint32("_INDEX_REBUILD_KEEP_STORAGE", &num));
    if (num > CT_MAX_INDEX_REBUILD_STORAGE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_INDEX_REBUILD_KEEP_STORAGE", (int64)CT_MAX_INDEX_REBUILD_STORAGE);
        return CT_ERROR;
    }
    attr->idx_rebuild_keep_storage_time = num;
    return CT_SUCCESS;
}

status_t srv_load_kernel_params(void)
{
    char *value = NULL;
    knl_attr_t *attr = &g_instance->kernel.attr;
    uint32 num32;

    // page_size
    CT_RETURN_IFERR(srv_get_page_size_param(attr));

    // column_count
    CT_RETURN_IFERR(srv_get_max_column_count_param(attr));

    attr->max_row_size = attr->page_size - 256;
    // ini_trans
    CT_RETURN_IFERR(srv_get_ini_trans_param(attr));

    // cr_mode
    CT_RETURN_IFERR(srv_get_cr_mode_param(attr));

    // row_format
    CT_RETURN_IFERR(srv_get_row_format_param(attr));

    CT_RETURN_IFERR(srv_get_undo_segments_param(attr));
    CT_RETURN_IFERR(srv_get_undo_active_segments_param(attr));

    if (attr->undo_active_segments > attr->undo_segments) {
        attr->undo_active_segments = attr->undo_segments;
    }
    CT_RETURN_IFERR(srv_get_auton_trans_segments_param(attr));
    CT_RETURN_IFERR(srv_get_param_bool32("_UNDO_AUTON_BIND_OWN_SEGMENT", &attr->undo_auton_bind_own));

    CT_RETURN_IFERR(srv_get_param_bool32("_UNDO_AUTO_SHRINK", &attr->undo_auto_shrink));
    CT_RETURN_IFERR(srv_get_param_bool32("_UNDO_AUTO_SHRINK_INACTIVE", &attr->undo_auto_shrink_inactive));
    CT_RETURN_IFERR(srv_get_param_uint32("_TX_ROLLBACK_PROC_NUM", &attr->tx_rollback_proc_num));
    if (attr->tx_rollback_proc_num < CT_MIN_ROLLBACK_PROC) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "TX_ROLLBACK_PROC_NUM", (int64)CT_MIN_ROLLBACK_PROC);
        return CT_ERROR;
    } else if (attr->tx_rollback_proc_num > CT_MAX_ROLLBACK_PROC) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "TX_ROLLBACK_PROC_NUM", (int64)CT_MAX_ROLLBACK_PROC);
        return CT_ERROR;
    }

    // db writer buffer
    attr->dbwr_buf_size = (uint64)CT_MAX_CKPT_GROUP_SIZE * attr->page_size;

    // transaction buffer
    attr->tran_buf_size = knl_txn_buffer_size(attr->page_size, attr->undo_segments);

    // data buffer
    CT_RETURN_IFERR(srv_get_param_size_uint64("DATA_BUFFER_SIZE", &attr->data_buf_size));
    if (attr->data_buf_size < CT_MIN_DATA_BUFFER_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "DATA_BUFFER_SIZE", CT_MIN_DATA_BUFFER_SIZE);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_size_uint32("BUFFER_PAGE_CLEAN_PERIOD", &attr->page_clean_period));
    if (attr->page_clean_period < 0) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "BUFFER_PAGE_CLEAN_PERIOD", 0);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("BUFFER_LRU_SEARCH_THRE", &attr->lru_search_threshold));
    if (attr->lru_search_threshold < CT_MIN_LRU_SEARCH_THRESHOLD ||
        attr->lru_search_threshold > CT_MAX_LRU_SEARCH_THRESHOLD) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "BUFFER_LRU_SEARCH_THRE", CT_MIN_LRU_SEARCH_THRESHOLD,
            CT_MAX_LRU_SEARCH_THRESHOLD);
        return CT_ERROR;
    }
    CT_RETURN_IFERR(srv_get_param_double("BUFFER_PAGE_CLEAN_RATIO", &attr->page_clean_ratio));
    if (attr->page_clean_ratio < CT_MIN_PAGE_CLEAN_RATIO || attr->page_clean_ratio > CT_MAX_PAGE_CLEAN_RATIO) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "BUFFER_PAGE_CLEAN_RATIO", CT_MIN_PAGE_CLEAN_RATIO,
            CT_MAX_PAGE_CLEAN_RATIO);
        return CT_ERROR;
    }
    // delay_cleanout
    CT_RETURN_IFERR(srv_get_param_bool32("DELAY_CLEANOUT", &attr->delay_cleanout));

    // CR pool
    CT_RETURN_IFERR(srv_get_param_size_uint64("CR_POOL_SIZE", &attr->cr_pool_size));
    if (attr->cr_pool_size < CT_MIN_CR_POOL_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "CR_POOL_SIZE", CT_MIN_CR_POOL_SIZE);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("CR_POOL_COUNT", &attr->cr_pool_count));
    if (attr->cr_pool_count > CT_MAX_CR_POOL_COUNT || attr->cr_pool_count <= 0) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "CR_POOL_COUNT", (int64)1, (int64)CT_MAX_CR_POOL_COUNT);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("BUF_POOL_NUM", &attr->buf_pool_num));
    if (attr->buf_pool_num > CT_MAX_BUF_POOL_NUM || attr->buf_pool_num <= 0) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "BUF_POOL_NUM", (int64)1, (int64)CT_MAX_BUF_POOL_NUM);
        return CT_ERROR;
    }

    // buffer iocbs
#ifndef WIN32
    attr->buf_iocbs_size = sizeof(buf_iocb_t) * BUF_IOCBS_MAX_NUM;
#endif

    // default extents
    CT_RETURN_IFERR(srv_get_param_uint32("DEFAULT_EXTENTS", &attr->default_extents));
    if (attr->default_extents != 8 && attr->default_extents != 16 && attr->default_extents != 32 &&
        attr->default_extents != 64 && attr->default_extents != 128) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "DEFAULT_EXTENTS");
        return CT_ERROR;
    }

    // default space type
    CT_RETURN_IFERR(srv_get_default_space_type_param(attr));

    // tablespace alarm threshold
    CT_RETURN_IFERR(srv_get_param_uint32("TABLESPACE_USAGE_ALARM_THRESHOLD", &attr->spc_usage_alarm_threshold));
    if (attr->spc_usage_alarm_threshold > CT_MAX_SPC_USAGE_ALARM_THRE) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "TABLESPACE_USAGE_ALARM_THRESHOLD");
        return CT_ERROR;
    }

    // undo usage alarm threshold
    CT_RETURN_IFERR(srv_get_param_uint32("UNDO_USAGE_ALARM_THRESHOLD", &attr->undo_usage_alarm_threshold));
    if (attr->undo_usage_alarm_threshold > CT_MAX_UNDO_ALARM_THRESHOLD) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "UNDO_USAGE_ALARM_THRESHOLD", (int64)CT_MAX_UNDO_ALARM_THRESHOLD);
        return CT_ERROR;
    }

    // txn undo usage alarm threshold
    CT_RETURN_IFERR(srv_get_param_uint32("TXN_UNDO_USAGE_ALARM_THRESHOLD", &attr->txn_undo_usage_alarm_threshold));
    if (attr->txn_undo_usage_alarm_threshold > CT_MAX_TXN_UNDO_ALARM_THRESHOLD) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "TXN_UNDO_USAGE_ALARM_THRESHOLD",
            (int64)CT_MAX_TXN_UNDO_ALARM_THRESHOLD);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("_SYSTIME_INCREASE_THREASHOLD", &num32));
    if (num32 > CT_MAX_SYSTIME_INC_THRE) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_SYSTIME_INCREASE_THREASHOLD");
        return CT_ERROR;
    } else {
        attr->systime_inc_threshold = (int64)DAY2SECONDS(num32);
    }

    // shared pool buffer + large pool buffer
    CT_RETURN_IFERR(srv_get_pool_params(attr));

    // log buffer
    CT_RETURN_IFERR(srv_get_log_buffer_param(attr));

    // should add value limitation check
    // temp buffer
    CT_RETURN_IFERR(srv_get_temp_buffer_param(attr));

    // dblink
    CT_RETURN_IFERR(srv_get_dblink_param(attr));

    // password_verify
    CT_RETURN_IFERR(srv_get_param_bool32("REPLACE_PASSWORD_VERIFY", &g_instance->kernel.attr.password_verify));

    // index buffer
    CT_RETURN_IFERR(srv_get_param_size_uint64("_INDEX_BUFFER_SIZE", &attr->index_buf_size));
    if (attr->index_buf_size < CT_MIN_INDEX_CACHE_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_INDEX_BUFFER_SIZE", CT_MIN_INDEX_CACHE_SIZE);
        return CT_ERROR;
    }
    if (attr->index_buf_size > CT_MAX_SGA_BUF_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_INDEX_BUFFER_SIZE", CT_MAX_SGA_BUF_SIZE);
        return CT_ERROR;
    }

    if (g_instance->session_pool.max_sessions <= g_instance->kernel.reserved_sessions +
        g_instance->sql_emerg_pool.max_sessions + g_instance->sql_par_pool.max_sessions) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "SESSIONS");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_ckpt_param(attr));

    value = srv_get_param("COMMIT_MODE");
    attr->commit_batch = cm_str_equal_ins(value, "BATCH");

    value = srv_get_param("COMMIT_WAIT");
    attr->commit_nowait = cm_str_equal_ins(value, "NOWAIT");

    CT_RETURN_IFERR(srv_get_param_uint32("DBWR_PROCESSES", &attr->dbwr_processes));
    if (!(attr->dbwr_processes > 0 && attr->dbwr_processes <= CT_MAX_DBWR_PROCESS)) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "DBWR_PROCESSES", (int64)1, (int64)CT_MAX_DBWR_PROCESS);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("LOG_REPLAY_PROCESSES", &attr->log_replay_processes));
    if (attr->log_replay_processes > CT_MAX_PARAL_RCY || attr->log_replay_processes < CT_DEFAULT_PARAL_RCY) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "LOG_REPLAY_PROCESSES", (int64)CT_DEFAULT_PARAL_RCY,
            (int64)CT_MAX_PARAL_RCY);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("REPLAY_PRELOAD_PROCESSES", &attr->rcy_preload_processes));
    if (attr->rcy_preload_processes > CT_MAX_PARAL_RCY) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "REPLAY_PRELOAD_PROCESSES", 0, (int64)CT_MAX_PARAL_RCY);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("_RCY_SLEEP_INTERVAL", &attr->rcy_sleep_interval));
    if (attr->rcy_sleep_interval < CT_MIN_RCY_SLEEP_INTERVAL || attr->rcy_sleep_interval > CT_MAX_RCY_SLEEP_INTERVAL) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "_RCY_SLEEP_INTERVAL", (int64)CT_MIN_RCY_SLEEP_INTERVAL,
            (int64)CT_MAX_RCY_SLEEP_INTERVAL);
        return CT_ERROR;
    }

    // cpu_count
    CT_RETURN_IFERR(srv_get_cpu_node_bind_param(attr));

    // spin count
    CT_RETURN_IFERR(srv_get_param_uint32("_SPIN_COUNT", &attr->spin_count));

    // qos
    CT_RETURN_IFERR(srv_get_qos_params(attr));

    CT_RETURN_IFERR(srv_get_param_bool32("_DISABLE_SOFT_PARSE", &attr->disable_soft_parse));

    CT_RETURN_IFERR(srv_get_checksum_param("PAGE_CHECKSUM", &attr->db_block_checksum));
    CT_RETURN_IFERR(srv_get_isolevel_param("DB_ISOLEVEL", &attr->db_isolevel));
    CT_RETURN_IFERR(srv_get_param_bool32("_SERIALIZED_COMMIT", &attr->serialized_commit));

    CT_RETURN_IFERR(srv_get_param_bool32("ENABLE_TX_FREE_PAGE_LIST", &attr->enable_tx_free_page_list));

    // thread_stack_size
    CT_RETURN_IFERR(srv_get_thread_stack_size(attr));

    CT_RETURN_IFERR(srv_get_param_uint32("UNDO_RESERVE_SIZE", &attr->undo_reserve_size));
    if (attr->undo_reserve_size < CT_UNDO_MIN_RESERVE_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "UNDO_RESERVE_SIZE", (int64)CT_UNDO_MIN_RESERVE_SIZE);
        return CT_ERROR;
    } else if (attr->undo_reserve_size > CT_UNDO_MAX_RESERVE_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "UNDO_RESERVE_SIZE", (int64)CT_UNDO_MAX_RESERVE_SIZE);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("UNDO_PREFETCH_PAGE_NUM", &attr->undo_prefetch_page_num));

    CT_RETURN_IFERR(srv_get_param_uint32("UNDO_RETENTION_TIME", &attr->undo_retention_time));
    if (attr->undo_retention_time < 1) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "UNDO_RETENTION_TIME", (int64)1);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("INDEX_DEFER_RECYCLE_TIME", &attr->index_defer_recycle_time));

    CT_RETURN_IFERR(srv_get_param_uint32("XA_SUSPEND_TIMEOUT", &attr->xa_suspend_timeout));
    if (attr->xa_suspend_timeout < 1) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "XA_SUSPEND_TIMEOUT", (int64)1);
        return CT_ERROR;
    }

    if (attr->xa_suspend_timeout > CT_MAX_SUSPEND_TIMEOUT) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "XA_SUSPEND_TIMEOUT", (int64)CT_MAX_SUSPEND_TIMEOUT);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("LOCK_WAIT_TIMEOUT", &attr->lock_wait_timeout));

    CT_RETURN_IFERR(srv_get_ha_params(attr));
    CT_RETURN_IFERR(srv_get_file_options_params(attr));
    CT_RETURN_IFERR(srv_get_raft_params(attr));

    CT_RETURN_IFERR(srv_get_param_bool32("_RCY_CHECK_PCN", &attr->rcy_check_pcn));
    CT_RETURN_IFERR(srv_get_param_bool32("LOCAL_TEMPORARY_TABLE_ENABLED", &attr->enable_ltt));
    CT_RETURN_IFERR(srv_get_param_bool32("UPPER_CASE_TABLE_NAMES", &attr->enable_upper_case_names));
    CT_RETURN_IFERR(srv_get_param_onoff("CBO", &attr->enable_cbo));
    CT_RETURN_IFERR(srv_get_param_bool32("RESOURCE_LIMIT", &attr->enable_resource_limit));
    CT_RETURN_IFERR(srv_get_param_bool32("DROP_NOLOGGING", &attr->drop_nologging));
    CT_RETURN_IFERR(srv_get_param_bool32("RECYCLEBIN", &attr->recyclebin));
    CT_RETURN_IFERR(srv_get_param_onoff("AUTO_INHERIT_USER", &attr->enable_auto_inherit));

    bool32 enable_idx_confs_dupl;
    CT_RETURN_IFERR(srv_get_param_bool32("ENABLE_IDX_CONFS_NAME_DUPL", &enable_idx_confs_dupl));
    if (enable_idx_confs_dupl) {
        CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "index and contraint duplicate name");
        return CT_ERROR;
    }
    CT_RETURN_IFERR(srv_get_param_bool32("ENABLE_IDX_KEY_LEN_CHECK", &attr->enable_idx_key_len_check));
    CT_RETURN_IFERR(srv_get_param_uint32("TC_LEVEL", &attr->tc_level));
    CT_RETURN_IFERR(srv_get_param_onoff("_AUTO_INDEX_RECYCLE", &attr->idx_auto_recycle));
    CT_RETURN_IFERR(srv_get_param_bool32("_INDEX_AUTO_REBUILD", &attr->idx_auto_rebuild));
    char *auto_rebuild_time = srv_get_param("_INDEX_AUTO_REBUILD_START_TIME");
    CT_RETURN_IFERR(srv_get_index_auto_rebuild(auto_rebuild_time, attr));
    CT_RETURN_IFERR(srv_get_idx_recycle(attr));
    CT_RETURN_IFERR(srv_get_param_uint32("_LNS_WAIT_TIME", &attr->lsnd_wait_time));

    CT_RETURN_IFERR(srv_get_param_uint32("_PRIVATE_ROW_LOCKS", &num32));

    if (num32 < CT_MIN_PRIVATE_LOCKS) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_PRIVATE_ROW_LOCKS", (int64)CT_MIN_PRIVATE_LOCKS);
        return CT_ERROR;
    } else if (num32 > CT_MAX_PRIVATE_LOCKS) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_PRIVATE_ROW_LOCKS", (int64)CT_MAX_PRIVATE_LOCKS);
        return CT_ERROR;
    } else {
        attr->private_row_locks = (uint8)num32;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("_PRIVATE_KEY_LOCKS", &num32));

    if (num32 < CT_MIN_PRIVATE_LOCKS) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_PRIVATE_KEY_LOCKS", (int64)CT_MIN_PRIVATE_LOCKS);
        return CT_ERROR;
    } else if (num32 > CT_MAX_PRIVATE_LOCKS) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_PRIVATE_KEY_LOCKS", (int64)CT_MAX_PRIVATE_LOCKS);
        return CT_ERROR;
    } else {
        attr->private_key_locks = (uint8)num32;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("DDL_LOCK_TIMEOUT", &num32));
    if (num32 < CT_MIN_DDL_LOCK_TIMEOUT || num32 > CT_MAX_DDL_LOCK_TIMEOUT) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "DDL_LOCK_TIMEOUT", (int64)CT_MIN_DDL_LOCK_TIMEOUT,
            (int64)CT_MAX_DDL_LOCK_TIMEOUT);
        return CT_ERROR;
    } else if (num32 == 0) {
        attr->ddl_lock_timeout = (uint32)LOCK_INF_WAIT;
    } else {
        attr->ddl_lock_timeout = (uint32)num32;
    }
    /* set rm count to suitable value */
    CT_RETURN_IFERR(srv_get_param_uint32("_MAX_RM_COUNT", &num32));
    if (num32 != 0) {
        if (g_instance->session_pool.expanded_max_sessions > CM_CALC_ALIGN(num32, CT_EXTEND_RMS)) {
            CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_MAX_RM_COUNT",
                (int64)g_instance->session_pool.expanded_max_sessions);
            return CT_ERROR;
        }

        if (CM_CALC_ALIGN(num32, CT_EXTEND_RMS) > CM_CALC_ALIGN_FLOOR(CT_MAX_RM_COUNT, CT_EXTEND_RMS)) {
            CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_MAX_RM_COUNT",
                (int64)CM_CALC_ALIGN_FLOOR(CT_MAX_RM_COUNT, CT_EXTEND_RMS));
            return CT_ERROR;
        }

        attr->max_rms = CM_CALC_ALIGN(num32, CT_EXTEND_RMS);
        char max_rms_buf[CT_MAX_RM_LEN] = { 0 };
        PRTS_RETURN_IFERR(snprintf_s(max_rms_buf, CT_MAX_RM_LEN, CT_MAX_RM_LEN - 1, "%u", attr->max_rms));
        CT_RETURN_IFERR(cm_alter_config(&g_instance->config, "_MAX_RM_COUNT", max_rms_buf, CONFIG_SCOPE_BOTH, CT_TRUE));
    } else {
        attr->max_rms = g_instance->session_pool.expanded_max_sessions;
        if (attr->max_rms < g_instance->session_pool.max_sessions * RM_SESSION_RATIO) {
            attr->max_rms = (uint32)(g_instance->session_pool.max_sessions * RM_SESSION_RATIO);
        }

        attr->max_rms = CM_CALC_ALIGN(attr->max_rms, CT_EXTEND_RMS);
    }

    CT_RETURN_IFERR(srv_get_param_uint32("_ASHRINK_WAIT_TIME", &attr->ashrink_wait_time));
    CT_RETURN_IFERR(srv_get_param_uint32("_SHRINK_WAIT_RECYCLED_PAGES", &attr->shrink_wait_recycled_pages));
    CT_RETURN_IFERR(srv_get_param_bool32("_TEMPTABLE_SUPPORT_BATCH_INSERT", &attr->temptable_support_batch));
    CT_RETURN_IFERR(srv_get_param_uint32("_SMALL_TABLE_SAMPLING_THRESHOLD", &num32));
    attr->small_table_sampling_threshold = num32;

    /* auto block repair */
    CT_RETURN_IFERR(srv_get_param_bool32("BLOCK_REPAIR_ENABLE", &attr->enable_abr));
    CT_RETURN_IFERR(srv_get_param_uint32("BLOCK_REPAIR_TIMEOUT", &num32));
    if (num32 < 1) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "BLOCK_REPAIR_TIMEOUT", (int64)1);
        return CT_ERROR;
    } else if (num32 > ABR_MAX_TIMEOUT) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "BLOCK_REPAIR_TIMEOUT", (int64)ABR_MAX_TIMEOUT);
        return CT_ERROR;
    } else {
        attr->abr_timeout = num32;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("NBU_BACKUP_TIMEOUT", &attr->nbu_backup_timeout));
    if (attr->nbu_backup_timeout < CT_NBU_BACKUP_MIN_WAIT_TIME) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "NBU_BACKUP_TIMEOUT", (int64)CT_NBU_BACKUP_MIN_WAIT_TIME);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_bool32("DEGRADE_SEARCH_MAP", &attr->enable_degrade_search));
    if (srv_get_param_size_uint64("LOB_REUSE_THRESHOLD", &g_instance->kernel.attr.lob_reuse_threshold) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (g_instance->kernel.attr.lob_reuse_threshold < CT_MIN_LOB_REUSE_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "LOB_REUSE_THRESHOLD", (int64)CT_MIN_LOB_REUSE_SIZE);
        return CT_ERROR;
    } else if (g_instance->kernel.attr.lob_reuse_threshold >= CT_MAX_LOB_REUSE_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "LOB_REUSE_THRESHOLD", (int64)CT_MAX_LOB_REUSE_SIZE);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_bool32("BUILD_DATAFILE_PARALLEL", &attr->build_datafile_parallel));
    CT_RETURN_IFERR(srv_get_param_bool32("_CHECK_SYSDATA_VERSION", &attr->check_sysdata_version));
    CT_RETURN_IFERR(srv_get_param_uint32("INIT_LOCK_POOL_PAGES", &num32));
    if (num32 < CT_MIN_LOCK_PAGES || num32 > CT_MAX_LOCK_PAGES) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "INIT_LOCK_POOL_PAGES", (int64)CT_MIN_LOCK_PAGES,
            (int64)CT_MAX_LOCK_PAGES);
        return CT_ERROR;
    }

    attr->init_lockpool_pages = num32;
    CT_RETURN_IFERR(srv_get_param_bool32("ENABLE_TEMP_SPACE_BITMAP", &attr->enable_temp_bitmap));
    CT_RETURN_IFERR(srv_get_param_bool32("MYSQL_METADATA_IN_CANTIAN", &attr->mysql_metadata_in_cantian));
    CT_RETURN_IFERR(srv_get_param_bool32("BUILD_DATAFILE_PREALLOCATE", &attr->build_datafile_prealloc));
    CT_RETURN_IFERR(srv_get_ctrllog_backup_level_param(attr));
    CT_RETURN_IFERR(srv_get_param_bool32("_TABLE_COMPRESS_ENABLE_BUFFER", &attr->tab_compress_enable_buf));
    CT_RETURN_IFERR(srv_get_param_size_uint64("_TABLE_COMPRESS_BUFFER_SIZE", &attr->tab_compress_buf_size));
    if (attr->tab_compress_buf_size < (int64)CT_MIN_TAB_COMPRESS_BUF_SIZE ||
        attr->tab_compress_buf_size > MIN((int64)CT_MAX_TAB_COMPRESS_BUF_SIZE, attr->temp_buf_size)) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "_TABLE_COMPRESS_BUFFER_SIZE", (int64)CT_MIN_TAB_COMPRESS_BUF_SIZE,
            MIN((int64)CT_MAX_TAB_COMPRESS_BUF_SIZE, attr->temp_buf_size));
        return CT_ERROR;
    }

    value = srv_get_param("_TABLE_COMPRESS_ALGO");
    if (cm_str_equal_ins(value, "NONE")) {
        g_instance->kernel.attr.default_compress_algo = COMPRESS_NONE;
    } else if (cm_str_equal_ins(value, "ZSTD")) {
        g_instance->kernel.attr.default_compress_algo = COMPRESS_ZSTD;
    } else {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "_TABLE_COMPRESS_ALGO", value);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("_BUFFER_PAGE_CLEAN_WAIT_TIMEOUT", &num32));
    g_instance->kernel.attr.page_clean_wait_timeout = (uint32)num32;
    CT_RETURN_IFERR(srv_get_param_uint32("_CHECKPOINT_TIMED_TASK_DELAY", &num32));
    g_instance->kernel.attr.ckpt_timed_task_delay = (uint32)num32;
    CT_RETURN_IFERR(srv_get_default_page_clean_mode_param(attr));
    CT_RETURN_IFERR(srv_get_param_size_uint32("BATCH_FLUSH_CAPACITY", &attr->batch_flush_capacity));
    if (attr->batch_flush_capacity < CT_MIN_BATCH_FLUSH_CAPACITY ||
        attr->batch_flush_capacity > CT_MAX_BATCH_FLUSH_CAPACITY) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "BATCH_FLUSH_CAPACITY", attr->batch_flush_capacity);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
