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
 * load_kernel.c
 *
 *
 * IDENTIFICATION
 * src/server/params/load_kernel.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_instance.h"
#include "srv_param_common.h"
#include "load_kernel.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RM_SESSION_RATIO 1.2
#define SGA_PAD(buf_size, page_size) ((buf_size) + CM_ALIGN8(((buf_size) / (page_size)) * sizeof(uint32)))

static status_t server_get_page_size_param(knl_attr_t *attribute)
{
    GS_RETURN_IFERR(server_get_param_size_uint32("PAGE_SIZE", &attribute->page_size));
    if (!(attribute->page_size == 8192 || attribute->page_size == 16384 || attribute->page_size == 32768)) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "PAGE_SIZE");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/**
 * get the value for column count parameter
 */
static status_t server_get_max_col_count_param(knl_attr_t *attribute)
{
    GS_RETURN_IFERR(server_get_param_uint32("MAX_COLUMN_COUNT", &attribute->max_column_count));
    if (!(attribute->max_column_count == 1024 || attribute->max_column_count == 2048 ||
          attribute->max_column_count == 3072 || attribute->max_column_count == 4096)) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "COLUMN_COUNT");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t server_get_ini_trans_param(knl_attr_t *attribute)
{
    GS_RETURN_IFERR(server_get_param_uint32("INI_TRANS", &attribute->initrans));
    if (attribute->initrans > GS_MAX_TRANS || attribute->initrans <= 0) {
        GS_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "INI_TRANS", (int64)1, (int64)GS_MAX_TRANS);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t server_get_cr_mode_param(knl_attr_t *attribute)
{
    char *value;

    value = server_get_param("CR_MODE");
    if (cm_str_equal_ins(value, "PAGE")) {
        attribute->cr_mode = CR_PAGE;
    } else if (cm_str_equal_ins(value, "ROW")) {
        attribute->cr_mode = CR_ROW;
    } else {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "CR_MODE");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t server_get_row_format_param(knl_attr_t *attribute)
{
    char *value;
    value = server_get_param("ROW_FORMAT");
    if (cm_str_equal_ins(value, "CSF")) {
        attribute->row_format = ROW_FORMAT_CSF;
    } else if (cm_str_equal_ins(value, "ASF")) {
        attribute->row_format = ROW_FORMAT_ASF;
    } else {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "ROW_FORMAT");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t server_get_undo_segs_param(knl_attr_t *attribute)
{
    if (server_get_param_uint32("_UNDO_SEGMENTS", &attribute->undo_segments) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (attribute->undo_segments < GS_MIN_UNDO_SEGMENT || attribute->undo_segments > GS_MAX_UNDO_SEGMENT) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "_UNDO_SEGMENTS");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t server_get_undo_active_segs_param(knl_attr_t *attribute)
{
    if (server_get_param_uint32("_UNDO_ACTIVE_SEGMENTS", &attribute->undo_active_segments) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (attribute->undo_active_segments < GS_MIN_UNDO_ACTIVE_SEGMENT ||
        attribute->undo_active_segments > GS_MAX_UNDO_ACTIVE_SEGMENT) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "_UNDO_ACTIVE_SEGMENTS");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t server_get_auton_trans_segs_param(knl_attr_t *attribute)
{
    if (server_get_param_uint32("_UNDO_AUTON_TRANS_SEGMENTS", &attribute->undo_auton_trans_segments) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (attribute->undo_auton_trans_segments < GS_MIN_AUTON_TRANS_SEGMENT ||
        attribute->undo_auton_trans_segments >= GS_MAX_UNDO_SEGMENT) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "_UNDO_AUTON_TRANS_SEGMENTS");
        return GS_ERROR;
    }

    if (attribute->undo_auton_trans_segments >= attribute->undo_segments) {
        attribute->undo_auton_trans_segments = attribute->undo_segments - 1;
    }

    return GS_SUCCESS;
}

static status_t server_get_default_spc_type_param(knl_attr_t *attribute)
{
    char *value = server_get_param("DEFAULT_TABLESPACE_TYPE");

    if (cm_str_equal_ins(value, "NORMAL")) {
        attribute->default_space_type = SPACE_NORMAL;
    } else if (cm_str_equal_ins(value, "BITMAP")) {
        attribute->default_space_type = SPACE_BITMAP;
    } else {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "DEFAULT_TABLESPACE_TYPE");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t server_get_vma_params(knl_attr_t *attribute)
{
    GS_RETURN_IFERR(server_get_param_uint32("_VMP_CACHES_EACH_SESSION", &attribute->vmp_cache_pages));

    GS_RETURN_IFERR(server_get_param_size_uint64("VARIANT_MEMORY_AREA_SIZE", &attribute->vma_size));
    if (attribute->vma_size < GS_MIN_VMA_SIZE) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "VARIANT_MEMORY_AREA_SIZE", GS_MIN_VMA_SIZE);
        return GS_ERROR;
    }
    if (attribute->vma_size > GS_MAX_SGA_BUF_SIZE) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "VARIANT_MEMORY_AREA_SIZE", GS_MAX_SGA_BUF_SIZE);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(server_get_param_size_uint64("LARGE_VARIANT_MEMORY_AREA_SIZE", &attribute->large_vma_size));
    if (attribute->large_vma_size < GS_MIN_LARGE_VMA_SIZE) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "LARGE_VARIANT_MEMORY_AREA_SIZE", GS_MIN_LARGE_VMA_SIZE);
        return GS_ERROR;
    }
    if (attribute->large_vma_size > GS_MAX_SGA_BUF_SIZE) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "LARGE_VARIANT_MEMORY_AREA_SIZE", GS_MAX_SGA_BUF_SIZE);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(server_get_param_uint32("_VMP_CACHES_EACH_SESSION", &attribute->vmp_cache_pages));
    GS_RETURN_IFERR(server_get_param_bool32("_VMA_MEM_CHECK", &g_vma_mem_check));
    return GS_SUCCESS;
}

static status_t server_get_pma_params(knl_attr_t *attribute)
{
    uint64 hash_area_size;
    GS_RETURN_IFERR(server_get_param_size_uint64("PMA_BUFFER_SIZE", &attribute->pma_size));
    GS_RETURN_IFERR(server_verf_param_uint64("PMA_BUFFER_SIZE", attribute->pma_size, 0, PMA_MAX_SIZE));

    GS_RETURN_IFERR(server_get_param_size_uint64("HASH_AREA_SIZE", &hash_area_size));
    GS_RETURN_IFERR(server_verf_param_uint64("HASH_AREA_SIZE", hash_area_size, 0, PMA_MAX_SIZE));

    // adjust hash area size
    g_instance->sql.hash_area_size = CM_CALC_ALIGN(hash_area_size, PMA_PAGE_SIZE);

    // adjust private memory area size
    uint64 page_count = attribute->pma_size / PMA_PAGE_SIZE;
    uint64 pool_size = page_count * sizeof(pm_pool_t);
    uint64 maps_size = page_count * sizeof(uint32) * VM_PAGES_PER_PPAGE;
    uint64 buf_size = page_count * (PMA_PAGE_SIZE + sizeof(uint32)) + pool_size + maps_size;
    attribute->pma_size = CM_CALC_ALIGN(buf_size, GS_MAX_ALIGN_SIZE_4K);
    return GS_SUCCESS;
}

static status_t server_get_pool_params(knl_attr_t *attribute)
{
    // private pool buffer
    GS_RETURN_IFERR(server_get_vma_params(attribute));
    GS_RETURN_IFERR(server_get_pma_params(attribute));

    // shared pool buffer
    GS_RETURN_IFERR(server_get_param_size_uint64("SHARED_POOL_SIZE", &attribute->shared_area_size));
    if (attribute->shared_area_size < GS_MIN_SHARED_POOL_SIZE) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "SHARED_POOL_SIZE", GS_MIN_SHARED_POOL_SIZE);
        return GS_ERROR;
    }
    if (attribute->shared_area_size > GS_MAX_SGA_BUF_SIZE) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "SHARED_POOL_SIZE", GS_MAX_SGA_BUF_SIZE);
        return GS_ERROR;
    }

    attribute->shared_area_size = SGA_PAD(attribute->shared_area_size, GS_SHARED_PAGE_SIZE);

    GS_RETURN_IFERR(server_get_param_double("_SQL_POOL_FACTOR", &attribute->sql_pool_factor));
    if (attribute->sql_pool_factor < GS_MIN_SQL_POOL_FACTOR || attribute->sql_pool_factor > GS_MAX_SQL_POOL_FACTOR) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "_SQL_POOL_FACTOR");
        return GS_ERROR;
    }

    // large pool buffer
    GS_RETURN_IFERR(server_get_param_size_uint64("LARGE_POOL_SIZE", &attribute->large_pool_size));
    if (attribute->large_pool_size < GS_MIN_LARGE_POOL_SIZE) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "LARGE_POOL_SIZE", GS_MIN_LARGE_POOL_SIZE);
        return GS_ERROR;
    }
    if (attribute->large_pool_size > GS_MAX_SGA_BUF_SIZE) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "LARGE_POOL_SIZE", GS_MAX_SGA_BUF_SIZE);
        return GS_ERROR;
    }
    attribute->large_pool_size = SGA_PAD(attribute->large_pool_size, GS_LARGE_PAGE_SIZE);

    // buddy pool buffer
    attribute->buddy_init_size = BUDDY_INIT_BLOCK_SIZE;
    attribute->buddy_max_size = BUDDY_MEM_POOL_INIT_SIZE;

    return GS_SUCCESS;
}

static status_t server_get_log_buf_param(knl_attr_t *attribute)
{
    GS_RETURN_IFERR(server_get_param_size_uint64("LOG_BUFFER_SIZE", &attribute->log_buf_size));
    if (attribute->log_buf_size < GS_MIN_LOG_BUFFER_SIZE || attribute->log_buf_size > GS_MAX_LOG_BUFFER_SIZE) {
        GS_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "LOG_BUFFER_SIZE", GS_MIN_LOG_BUFFER_SIZE, GS_MAX_LOG_BUFFER_SIZE);
        return GS_ERROR;
    }
    attribute->lgwr_buf_size = attribute->log_buf_size / 2;
    if (cm_get_cipher_len((uint32)attribute->lgwr_buf_size, (uint32 *)&attribute->lgwr_cipher_buf_size) != GS_SUCCESS) {
        return GS_ERROR;
    }
    knl_panic(attribute->lgwr_cipher_buf_size >= attribute->lgwr_buf_size);
    if (attribute->lgwr_cipher_buf_size < attribute->lgwr_buf_size) {
        GS_LOG_RUN_ERR("ERROR: wrong lgwr_cipher_buf_size");
        return GS_ERROR;
    }
    attribute->lgwr_cipher_buf_size += sizeof(cipher_ctrl_t);
    attribute->lgwr_cipher_buf_size = CM_CALC_ALIGN(attribute->lgwr_cipher_buf_size, SIZE_K(4));
    attribute->lgwr_buf_size = attribute->lgwr_cipher_buf_size;

    GS_RETURN_IFERR(server_get_param_uint32("LOG_BUFFER_COUNT", &attribute->log_buf_count));
    if (!(attribute->log_buf_count > 0 && attribute->log_buf_count <= GS_MAX_LOG_BUFFERS)) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "LOG_BUFFER_COUNT");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t server_get_ckpt_param(knl_attr_t *attribute)
{
    GS_RETURN_IFERR(server_get_param_bool32("_CHECKPOINT_MERGE_IO", &attribute->ckpt_flush_neighbors));

    GS_RETURN_IFERR(server_get_param_uint32("CHECKPOINT_PAGES", &attribute->ckpt_interval));
    if (attribute->ckpt_interval == 0) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "CHECKPOINT_PAGES", (int64)1);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(server_get_param_uint32("CHECKPOINT_PERIOD", &attribute->ckpt_timeout));
    if (attribute->ckpt_timeout == 0) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "CHECKPOINT_PERIOD", (int64)1);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(server_get_param_uint32("CHECKPOINT_IO_CAPACITY", &attribute->ckpt_io_capacity));
    if (attribute->ckpt_io_capacity == 0) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "CHECKPOINT_IO_CAPACITY", (int64)1);
        return GS_ERROR;
    }

    if (attribute->ckpt_io_capacity > GS_CKPT_GROUP_SIZE) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "CHECKPOINT_IO_CAPACITY", (int64)GS_CKPT_GROUP_SIZE);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}
static status_t server_get_tmp_buf_param(knl_attr_t *attribute)
{
    GS_RETURN_IFERR(server_get_param_size_uint64("TEMP_BUFFER_SIZE", &attribute->temp_buf_size));

    if (attribute->temp_buf_size < GS_MIN_TEMP_BUFFER_SIZE || attribute->temp_buf_size > GS_MAX_TEMP_BUFFER_SIZE) {
        GS_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "TEMP_BUFFER_SIZE", GS_MIN_TEMP_BUFFER_SIZE, GS_MAX_TEMP_BUFFER_SIZE);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(server_get_param_uint32("MAX_TEMP_TABLES", &attribute->max_temp_tables));

    if (attribute->max_temp_tables < GS_RESERVED_TEMP_TABLES) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "MAX_TEMP_TABLES", GS_RESERVED_TEMP_TABLES);
        return GS_ERROR;
    }

    if (attribute->max_temp_tables > GS_MAX_TEMP_TABLES) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "MAX_TEMP_TABLES", (int64)GS_MAX_TEMP_TABLES);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(server_get_param_uint32("TEMP_POOL_NUM", &attribute->temp_pool_num));
    if (attribute->temp_pool_num > GS_MAX_TEMP_POOL_NUM || attribute->temp_pool_num <= 0) {
        GS_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "TEMP_POOL_NUM", (int64)1, (int64)GS_MAX_TEMP_POOL_NUM);
        return GS_ERROR;
    }

    return server_get_param_uint32("_MAX_VM_FUNC_STACK_COUNT", &g_vm_max_stack_count);
}

static status_t server_get_qos_params(knl_attr_t *attribute)
{
    GS_RETURN_IFERR(server_get_param_bool32("_ENABLE_QOS", &attribute->enable_qos));

    GS_RETURN_IFERR(server_get_param_double("_QOS_CTRL_FACTOR", &attribute->qos_factor));
    if (attribute->qos_factor > GS_MAX_QOS_CTRL_FACTOR || attribute->qos_factor <= GS_MIN_QOS_CTRL_FACTOR) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "_QOS_CTRL_FACTOR");
        return GS_ERROR;
    }
    attribute->qos_threshold = (uint32)(int32)(attribute->cpu_count * attribute->qos_factor);

    GS_RETURN_IFERR(server_get_param_uint32("_QOS_SLEEP_TIME", &attribute->qos_sleep_time));
    if (attribute->qos_sleep_time <= 0) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "_QOS_SLEEP_TIME");
        return GS_ERROR;
    }

    GS_RETURN_IFERR(server_get_param_uint32("_QOS_RANDOM_RANGE", &attribute->qos_random_range));
    if (attribute->qos_random_range <= 0) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "_QOS_RANDOM_RANGE");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t server_get_thread_stack_size(knl_attr_t *attribute)
{
    GS_RETURN_IFERR(server_get_param_size_uint64("_THREAD_STACK_SIZE", &attribute->thread_stack_size));

    long stack_rlimit = cm_get_os_thread_stack_rlimit();
    if (attribute->thread_stack_size > (uint64)(stack_rlimit - GS_STACK_DEPTH_SLOP) ||
        attribute->thread_stack_size < GS_MIN_THREAD_STACK_SIZE) {
        GS_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "_THREAD_STACK_SIZE", (int64)GS_MIN_THREAD_STACK_SIZE,
            (int64)(stack_rlimit - GS_STACK_DEPTH_SLOP));
        return GS_ERROR;
    }

    attribute->reactor_thread_stack_size = attribute->thread_stack_size;
    return GS_SUCCESS;
}

static status_t server_get_file_opts_params(knl_attr_t *attribute)
{
    const char *value = server_get_param("FILE_OPTIONS");
    attribute->enable_asynch = GS_FALSE;
    attribute->enable_directIO = GS_FALSE;
    attribute->enable_logdirectIO = GS_FALSE;
    attribute->enable_dsync = GS_FALSE;
    attribute->enable_fdatasync = GS_FALSE;
    attribute->enable_OSYNC = GS_FALSE;

    if (cm_str_equal_ins(value, "NONE")) {
        attribute->enable_OSYNC = GS_TRUE;
        return GS_SUCCESS;
    }

    if (cm_str_equal_ins(value, "DIRECTIO")) {
        attribute->enable_logdirectIO = GS_TRUE;
        attribute->enable_OSYNC = GS_TRUE;
        return GS_SUCCESS;
    }

    if (cm_str_equal_ins(value, "FULLDIRECTIO")) {
        attribute->enable_directIO = GS_TRUE;
        attribute->enable_logdirectIO = GS_TRUE;
        attribute->enable_OSYNC = GS_TRUE;
        return GS_SUCCESS;
    }

    if (cm_str_equal_ins(value, "ASYNCH")) {
        attribute->enable_asynch = GS_TRUE;
        attribute->enable_directIO = GS_TRUE;
        attribute->enable_logdirectIO = GS_TRUE;
        return GS_SUCCESS;
    }

    if (cm_str_equal_ins(value, "DSYNC")) {
        attribute->enable_dsync = GS_TRUE;
        return GS_SUCCESS;
    }

    if (cm_str_equal_ins(value, "FDATASYNC")) {
        attribute->enable_fdatasync = GS_TRUE;
        return GS_SUCCESS;
    }

    if (cm_str_equal_ins(value, "SETALL")) {
        attribute->enable_asynch = GS_TRUE;
        attribute->enable_directIO = GS_TRUE;
        attribute->enable_logdirectIO = GS_TRUE;
        return GS_SUCCESS;
    }

    GS_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "FILE_OPTIONS", value);
    return GS_ERROR;
}

static status_t server_get_ha_params(knl_attr_t *attribute)
{
    errno_t errcode;
    uint32 host_cnt = 0;
    uint64 pkg_size;

    GS_RETURN_IFERR(server_get_param_bool32("_BACKUP_LOG_PARALLEL", &attribute->backup_log_prealloc));
    GS_RETURN_IFERR(server_get_param_bool32("_DOUBLEWRITE", &attribute->enable_double_write));
    GS_RETURN_IFERR(server_get_param_uint32("BUILD_KEEP_ALIVE_TIMEOUT", &attribute->build_keep_alive_timeout));
    if (attribute->build_keep_alive_timeout < GS_BUILD_MIN_WAIT_TIME) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "BUILD_KEEP_ALIVE_TIMEOUT", (int64)GS_BUILD_MIN_WAIT_TIME);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(server_get_param_uint32("REPL_WAIT_TIMEOUT", &attribute->repl_wait_timeout));
    if (attribute->repl_wait_timeout < GS_REPL_MIN_WAIT_TIME) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "REPL_WAIT_TIMEOUT", (int64)GS_REPL_MIN_WAIT_TIME);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(server_get_param_size_uint64("_REPL_MAX_PKG_SIZE", &pkg_size));
    if (pkg_size != 0 && (pkg_size < GS_MIN_REPL_PKG_SIZE || pkg_size > GS_MAX_REPL_PKG_SIZE)) {
        GS_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "_REPL_MAX_PKG_SIZE", GS_MIN_REPL_PKG_SIZE, GS_MAX_REPL_PKG_SIZE);
        return GS_ERROR;
    }
    (void)cm_atomic_set(&attribute->repl_pkg_size, (int64)pkg_size);

    attribute->repl_port = g_instance->lsnr.tcp_replica.port;
    GS_RETURN_IFERR(server_get_param_bool32("REPL_AUTH", &attribute->repl_auth));
    GS_RETURN_IFERR(server_get_param_bool32("REPL_SCRAM_AUTH", &attribute->repl_scram_auth));

    if (!attribute->repl_auth && attribute->repl_scram_auth) {
        GS_LOG_RUN_INF("REPL_AUTH is false, set REPL_SCRAM_AUTH to true will not work. "
            "If it is running in standalone mode, please ignore this item");
    }

    const char *value = server_get_param("REPL_TRUST_HOST");
    if (strlen(value) == 0) {
        g_instance->kernel.attr.repl_trust_host[0] = '\0';
        return GS_SUCCESS;
    }

    if (cm_verify_lsnr_addr(value, (uint32)strlen(value), &host_cnt) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "REPL_TRUST_HOST");
        return GS_ERROR;
    }

    if (host_cnt > GS_MAX_LSNR_HOST_COUNT) {
        GS_THROW_ERROR(ERR_IPADDRESS_NUM_EXCEED, GS_MAX_LSNR_HOST_COUNT);
        return GS_ERROR;
    }

    errcode = strncpy_s(g_instance->kernel.attr.repl_trust_host, GS_HOST_NAME_BUFFER_SIZE * GS_MAX_LSNR_HOST_COUNT,
        value, strlen(value));
    if (errcode != EOK) {
        GS_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t server_get_dblink_param(knl_attr_t *attribute)
{
    GS_RETURN_IFERR(server_get_param_uint32("MAX_LINK_TABLES", &attribute->max_link_tables));
    if (attribute->max_link_tables > GS_MAX_LINK_TABLES) {
        GS_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "MAX_LINK_TABLES", 0, GS_MAX_LINK_TABLES);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t server_get_isolevel_param(char *param_name, uint8 *param_value)
{
    char *value = server_get_param(param_name);
    if (cm_str_equal_ins(value, "RC")) {
        *param_value = (uint8)ISOLATION_READ_COMMITTED;
    } else if (cm_str_equal_ins(value, "CC")) {
        *param_value = (uint8)ISOLATION_CURR_COMMITTED;
    } else {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t server_get_ctrllog_bak_level_param(knl_attr_t *attribute)
{
    char *value = server_get_param("CTRLLOG_BACKUP_LEVEL");

    if (cm_str_equal_ins(value, "NONE")) {
        attribute->ctrllog_backup_level = CTRLLOG_BACKUP_LEVEL_NONE;
    } else if (cm_str_equal_ins(value, "TYPICAL")) {
        attribute->ctrllog_backup_level = CTRLLOG_BACKUP_LEVEL_TYPICAL;
    } else if (cm_str_equal_ins(value, "FULL")) {
        attribute->ctrllog_backup_level = CTRLLOG_BACKUP_LEVEL_FULL;
    } else {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "DEFAULT_TABLESPACE_TYPE");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t server_get_checksum_param(char *param_name, uint32 *param_value)
{
    char *value = server_get_param(param_name);
    if (cm_str_equal_ins(value, "OFF")) {
        *param_value = (uint32)CKS_OFF;
    } else if (cm_str_equal_ins(value, "TYPICAL")) {
        *param_value = (uint32)CKS_TYPICAL;
    } else if (cm_str_equal_ins(value, "FULL")) {
        *param_value = (uint32)CKS_FULL;
    } else {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t server_get_default_page_clean_mode_param(knl_attr_t *attribute)
{
    char *value = server_get_param("PAGE_CLEAN_MODE");

    if (cm_str_equal_ins(value, "SINGLE")) {
        attribute->page_clean_mode = PAGE_CLEAN_MODE_SINGLESET;
    } else if (cm_str_equal_ins(value, "ALL")) {
        attribute->page_clean_mode = PAGE_CLEAN_MODE_ALLSET;
    } else {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "PAGE_CLEAN_MODE");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t server_get_index_recycle(knl_attr_t *attribute)
{
    uint32 num;
    uint64 size;
    GS_RETURN_IFERR(server_get_param_uint32("_INDEX_RECYCLE_PERCENT", &num));
    if (num > GS_MAX_INDEX_RECYCLE_PERCENT) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_INDEX_RECYCLE_PERCENT", (int64)GS_MAX_INDEX_RECYCLE_PERCENT);
        return GS_ERROR;
    }
    attribute->idx_recycle_percent = num;

    GS_RETURN_IFERR(server_get_param_size_uint64("_INDEX_RECYCLE_SIZE", &size));
    if (size > GS_MAX_INDEX_RECYCLE_SIZE) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_INDEX_RECYCLE_SIZE", (int64)GS_MAX_INDEX_RECYCLE_SIZE);
        return GS_ERROR;
    }
    if (size < GS_MIN_INDEX_RECYCLE_SIZE) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_INDEX_RECYCLE_SIZE", (int64)GS_MIN_INDEX_RECYCLE_SIZE);
        return GS_ERROR;
    }
    attribute->idx_recycle_size = size;

    GS_RETURN_IFERR(server_get_param_uint32("_FORCE_INDEX_RECYCLE", &num));
    if (num > GS_MAX_INDEX_FORCE_RECYCLE) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_FORCE_INDEX_RECYCLE", (int64)GS_MAX_INDEX_FORCE_RECYCLE);
        return GS_ERROR;
    }
    attribute->idx_force_recycle_time = num;

    GS_RETURN_IFERR(server_get_param_uint32("_INDEX_RECYCLE_REUSE", &num));
    if (num > GS_MAX_INDEX_RECYCLE_REUSE) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_INDEX_RECYCLE_REUSE", (int64)GS_MAX_INDEX_RECYCLE_REUSE);
        return GS_ERROR;
    }
    attribute->idx_recycle_reuse_time = num;

    GS_RETURN_IFERR(server_get_param_uint32("_INDEX_REBUILD_KEEP_STORAGE", &num));
    if (num > GS_MAX_INDEX_REBUILD_STORAGE) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_INDEX_REBUILD_KEEP_STORAGE", (int64)GS_MAX_INDEX_REBUILD_STORAGE);
        return GS_ERROR;
    }
    attribute->idx_rebuild_keep_storage_time = num;
    return GS_SUCCESS;
}

status_t server_load_knl_params(void)
{
    char *value = NULL;
    knl_attr_t *attr = &g_instance->kernel.attr;
    uint32 num32;

    // page_size
    GS_RETURN_IFERR(server_get_page_size_param(attr));

    // column_count
    GS_RETURN_IFERR(server_get_max_col_count_param(attr));

    attr->max_row_size = attr->page_size - 256;
    // ini_trans
    GS_RETURN_IFERR(server_get_ini_trans_param(attr));

    // cr_mode
    GS_RETURN_IFERR(server_get_cr_mode_param(attr));

    // row_format
    GS_RETURN_IFERR(server_get_row_format_param(attr));

    GS_RETURN_IFERR(server_get_undo_segs_param(attr));
    GS_RETURN_IFERR(server_get_undo_active_segs_param(attr));

    if (attr->undo_active_segments > attr->undo_segments) {
        attr->undo_active_segments = attr->undo_segments;
    }
    GS_RETURN_IFERR(server_get_auton_trans_segs_param(attr));
    GS_RETURN_IFERR(server_get_param_bool32("_UNDO_AUTON_BIND_OWN_SEGMENT", &attr->undo_auton_bind_own));

    GS_RETURN_IFERR(server_get_param_bool32("_UNDO_AUTO_SHRINK", &attr->undo_auto_shrink));
    GS_RETURN_IFERR(server_get_param_bool32("_UNDO_AUTO_SHRINK_INACTIVE", &attr->undo_auto_shrink_inactive));
    GS_RETURN_IFERR(server_get_param_uint32("_TX_ROLLBACK_PROC_NUM", &attr->tx_rollback_proc_num));
    if (attr->tx_rollback_proc_num < GS_MIN_ROLLBACK_PROC) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "TX_ROLLBACK_PROC_NUM", (int64)GS_MIN_ROLLBACK_PROC);
        return GS_ERROR;
    } else if (attr->tx_rollback_proc_num > GS_MAX_ROLLBACK_PROC) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "TX_ROLLBACK_PROC_NUM", (int64)GS_MAX_ROLLBACK_PROC);
        return GS_ERROR;
    }

    // db writer buffer
    attr->dbwr_buf_size = (uint64)GS_CKPT_GROUP_SIZE * attr->page_size;

    // transaction buffer
    attr->tran_buf_size = knl_txn_buffer_size(attr->page_size, attr->undo_segments);

    // data buffer
    GS_RETURN_IFERR(server_get_param_size_uint64("DATA_BUFFER_SIZE", &attr->data_buf_size));
    if (attr->data_buf_size < GS_MIN_DATA_BUFFER_SIZE) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "DATA_BUFFER_SIZE", GS_MIN_DATA_BUFFER_SIZE);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(server_get_param_size_uint32("BUFFER_PAGE_CLEAN_PERIOD", &attr->page_clean_period));
    if (attr->page_clean_period < 0) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "BUFFER_PAGE_CLEAN_PERIOD", 0);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(server_get_param_uint32("BUFFER_LRU_SEARCH_THRE", &attr->lru_search_threshold));
    if (attr->lru_search_threshold < GS_MIN_LRU_SEARCH_THRESHOLD ||
        attr->lru_search_threshold > GS_MAX_LRU_SEARCH_THRESHOLD) {
        GS_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "BUFFER_LRU_SEARCH_THRE", GS_MIN_LRU_SEARCH_THRESHOLD,
            GS_MAX_LRU_SEARCH_THRESHOLD);
        return GS_ERROR;
    }
    GS_RETURN_IFERR(server_get_param_double("BUFFER_PAGE_CLEAN_RATIO", &attr->page_clean_ratio));
    if (attr->page_clean_ratio < GS_MIN_PAGE_CLEAN_RATIO || attr->page_clean_ratio > GS_MAX_PAGE_CLEAN_RATIO) {
        GS_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "BUFFER_PAGE_CLEAN_RATIO", GS_MIN_PAGE_CLEAN_RATIO,
            GS_MAX_PAGE_CLEAN_RATIO);
        return GS_ERROR;
    }
    // delay_cleanout
    GS_RETURN_IFERR(server_get_param_bool32("DELAY_CLEANOUT", &attr->delay_cleanout));

    // CR pool
    GS_RETURN_IFERR(server_get_param_size_uint64("CR_POOL_SIZE", &attr->cr_pool_size));
    if (attr->cr_pool_size < GS_MIN_CR_POOL_SIZE) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "CR_POOL_SIZE", GS_MIN_CR_POOL_SIZE);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(server_get_param_uint32("CR_POOL_COUNT", &attr->cr_pool_count));
    if (attr->cr_pool_count > GS_MAX_CR_POOL_COUNT || attr->cr_pool_count <= 0) {
        GS_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "CR_POOL_COUNT", (int64)1, (int64)GS_MAX_CR_POOL_COUNT);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(server_get_param_uint32("BUF_POOL_NUM", &attr->buf_pool_num));
    if (attr->buf_pool_num > GS_MAX_BUF_POOL_NUM || attr->buf_pool_num <= 0) {
        GS_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "BUF_POOL_NUM", (int64)1, (int64)GS_MAX_BUF_POOL_NUM);
        return GS_ERROR;
    }

    // buffer iocbs
#ifndef WIN32
    attr->buf_iocbs_size = sizeof(buf_iocb_t) * BUF_IOCBS_MAX_NUM;
#endif

    // default extents
    GS_RETURN_IFERR(server_get_param_uint32("DEFAULT_EXTENTS", &attr->default_extents));
    if (attr->default_extents != 8 && attr->default_extents != 16 && attr->default_extents != 32 &&
        attr->default_extents != 64 && attr->default_extents != 128) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "DEFAULT_EXTENTS");
        return GS_ERROR;
    }

    // default space type
    GS_RETURN_IFERR(server_get_default_spc_type_param(attr));

    // tablespace alarm threshold
    GS_RETURN_IFERR(server_get_param_uint32("TABLESPACE_USAGE_ALARM_THRESHOLD", &attr->spc_usage_alarm_threshold));
    if (attr->spc_usage_alarm_threshold > GS_MAX_SPC_USAGE_ALARM_THRE) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "TABLESPACE_USAGE_ALARM_THRESHOLD");
        return GS_ERROR;
    }

    // undo usage alarm threshold
    GS_RETURN_IFERR(server_get_param_uint32("UNDO_USAGE_ALARM_THRESHOLD", &attr->undo_usage_alarm_threshold));
    if (attr->undo_usage_alarm_threshold > GS_MAX_UNDO_ALARM_THRESHOLD) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "UNDO_USAGE_ALARM_THRESHOLD", (int64)GS_MAX_UNDO_ALARM_THRESHOLD);
        return GS_ERROR;
    }

    // txn undo usage alarm threshold
    GS_RETURN_IFERR(server_get_param_uint32("TXN_UNDO_USAGE_ALARM_THRESHOLD", &attr->txn_undo_usage_alarm_threshold));
    if (attr->txn_undo_usage_alarm_threshold > GS_MAX_TXN_UNDO_ALARM_THRESHOLD) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "TXN_UNDO_USAGE_ALARM_THRESHOLD",
            (int64)GS_MAX_TXN_UNDO_ALARM_THRESHOLD);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(server_get_param_uint32("_SYSTIME_INCREASE_THREASHOLD", &num32));
    if (num32 > GS_MAX_SYSTIME_INC_THRE) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "_SYSTIME_INCREASE_THREASHOLD");
        return GS_ERROR;
    } else {
        attr->systime_inc_threshold = (int64)DAY2SECONDS(num32);
    }

    // shared pool buffer + large pool buffer
    GS_RETURN_IFERR(server_get_pool_params(attr));

    // log buffer
    GS_RETURN_IFERR(server_get_log_buf_param(attr));

    // should add value limitation check
    // temp buffer
    GS_RETURN_IFERR(server_get_tmp_buf_param(attr));

    // dblink
    GS_RETURN_IFERR(server_get_dblink_param(attr));

    // password_verify
    GS_RETURN_IFERR(server_get_param_bool32("REPLACE_PASSWORD_VERIFY", &g_instance->kernel.attr.password_verify));

    // index buffer
    GS_RETURN_IFERR(server_get_param_size_uint64("_INDEX_BUFFER_SIZE", &attr->index_buf_size));
    if (attr->index_buf_size < GS_MIN_INDEX_CACHE_SIZE) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_INDEX_BUFFER_SIZE", GS_MIN_INDEX_CACHE_SIZE);
        return GS_ERROR;
    }
    if (attr->index_buf_size > GS_MAX_SGA_BUF_SIZE) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_INDEX_BUFFER_SIZE", GS_MAX_SGA_BUF_SIZE);
        return GS_ERROR;
    }

    if (g_instance->session_pool.max_sessions <= g_instance->kernel.reserved_sessions + g_instance->sql_par_pool.max_sessions) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "SESSIONS");
        return GS_ERROR;
    }

    GS_RETURN_IFERR(server_get_ckpt_param(attr));

    value = server_get_param("COMMIT_MODE");
    attr->commit_batch = cm_str_equal_ins(value, "BATCH");

    value = server_get_param("COMMIT_WAIT");
    attr->commit_nowait = cm_str_equal_ins(value, "NOWAIT");

    GS_RETURN_IFERR(server_get_param_uint32("DBWR_PROCESSES", &attr->dbwr_processes));
    if (!(attr->dbwr_processes > 0 && attr->dbwr_processes <= GS_MAX_DBWR_PROCESS)) {
        GS_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "DBWR_PROCESSES", (int64)1, (int64)GS_MAX_DBWR_PROCESS);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(server_get_param_uint32("LOG_REPLAY_PROCESSES", &attr->log_replay_processes));
    if (attr->log_replay_processes > GS_MAX_PARAL_RCY || attr->log_replay_processes < GS_DEFAULT_PARAL_RCY) {
        GS_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "LOG_REPLAY_PROCESSES", (int64)GS_DEFAULT_PARAL_RCY,
            (int64)GS_MAX_PARAL_RCY);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(server_get_param_uint32("REPLAY_PRELOAD_PROCESSES", &attr->rcy_preload_processes));
    if (attr->rcy_preload_processes > GS_MAX_PARAL_RCY) {
        GS_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "REPLAY_PRELOAD_PROCESSES", 0, (int64)GS_MAX_PARAL_RCY);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(server_get_param_uint32("_RCY_SLEEP_INTERVAL", &attr->rcy_sleep_interval));
    if (attr->rcy_sleep_interval < GS_MIN_RCY_SLEEP_INTERVAL || attr->rcy_sleep_interval > GS_MAX_RCY_SLEEP_INTERVAL) {
        GS_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "_RCY_SLEEP_INTERVAL", (int64)GS_MIN_RCY_SLEEP_INTERVAL,
            (int64)GS_MAX_RCY_SLEEP_INTERVAL);
        return GS_ERROR;
    }

    // spin count
    GS_RETURN_IFERR(server_get_param_uint32("_SPIN_COUNT", &attr->spin_count));

    // qos
    GS_RETURN_IFERR(server_get_qos_params(attr));

    GS_RETURN_IFERR(server_get_param_bool32("_DISABLE_SOFT_PARSE", &attr->disable_soft_parse));

    GS_RETURN_IFERR(server_get_checksum_param("PAGE_CHECKSUM", &attr->db_block_checksum));
    GS_RETURN_IFERR(server_get_isolevel_param("DB_ISOLEVEL", &attr->db_isolevel));
    GS_RETURN_IFERR(server_get_param_bool32("_SERIALIZED_COMMIT", &attr->serialized_commit));

    GS_RETURN_IFERR(server_get_param_bool32("ENABLE_TX_FREE_PAGE_LIST", &attr->enable_tx_free_page_list));

    // thread_stack_size
    GS_RETURN_IFERR(server_get_thread_stack_size(attr));

    GS_RETURN_IFERR(server_get_param_uint32("UNDO_RESERVE_SIZE", &attr->undo_reserve_size));
    if (attr->undo_reserve_size < GS_UNDO_MIN_RESERVE_SIZE) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "UNDO_RESERVE_SIZE", (int64)GS_UNDO_MIN_RESERVE_SIZE);
        return GS_ERROR;
    } else if (attr->undo_reserve_size > GS_UNDO_MAX_RESERVE_SIZE) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "UNDO_RESERVE_SIZE", (int64)GS_UNDO_MAX_RESERVE_SIZE);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(server_get_param_uint32("UNDO_PREFETCH_PAGE_NUM", &attr->undo_prefetch_page_num));

    GS_RETURN_IFERR(server_get_param_uint32("UNDO_RETENTION_TIME", &attr->undo_retention_time));
    if (attr->undo_retention_time < 1) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "UNDO_RETENTION_TIME", (int64)1);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(server_get_param_uint32("INDEX_DEFER_RECYCLE_TIME", &attr->index_defer_recycle_time));

    GS_RETURN_IFERR(server_get_param_uint32("XA_SUSPEND_TIMEOUT", &attr->xa_suspend_timeout));
    if (attr->xa_suspend_timeout < 1) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "XA_SUSPEND_TIMEOUT", (int64)1);
        return GS_ERROR;
    }

    if (attr->xa_suspend_timeout > GS_MAX_SUSPEND_TIMEOUT) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "XA_SUSPEND_TIMEOUT", (int64)GS_MAX_SUSPEND_TIMEOUT);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(server_get_param_uint32("LOCK_WAIT_TIMEOUT", &attr->lock_wait_timeout));

    GS_RETURN_IFERR(server_get_ha_params(attr));
    GS_RETURN_IFERR(server_get_file_opts_params(attr));

    GS_RETURN_IFERR(server_get_param_bool32("_RCY_CHECK_PCN", &attr->rcy_check_pcn));
    GS_RETURN_IFERR(server_get_param_bool32("LOCAL_TEMPORARY_TABLE_ENABLED", &attr->enable_ltt));
    GS_RETURN_IFERR(server_get_param_bool32("UPPER_CASE_TABLE_NAMES", &attr->enable_upper_case_names));
    GS_RETURN_IFERR(server_get_param_bool32("RESOURCE_LIMIT", &attr->enable_resource_limit));
    GS_RETURN_IFERR(server_get_param_bool32("DROP_NOLOGGING", &attr->drop_nologging));
    GS_RETURN_IFERR(server_get_param_bool32("RECYCLEBIN", &attr->recyclebin));
    GS_RETURN_IFERR(server_get_param_onoff("AUTO_INHERIT_USER", &attr->enable_auto_inherit));

    bool32 enable_idx_confs_dupl;
    GS_RETURN_IFERR(server_get_param_bool32("ENABLE_IDX_CONFS_NAME_DUPL", &enable_idx_confs_dupl));
    if (enable_idx_confs_dupl) {
        GS_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "index and contraint duplicate name");
        return GS_ERROR;
    }
    GS_RETURN_IFERR(server_get_param_bool32("ENABLE_IDX_KEY_LEN_CHECK", &attr->enable_idx_key_len_check));
    GS_RETURN_IFERR(server_get_param_uint32("TC_LEVEL", &attr->tc_level));
    GS_RETURN_IFERR(server_get_param_onoff("_AUTO_INDEX_RECYCLE", &attr->idx_auto_recycle));
    GS_RETURN_IFERR(server_get_param_bool32("_INDEX_AUTO_REBUILD", &attr->idx_auto_rebuild));
    char *auto_rebuild_time = server_get_param("_INDEX_AUTO_REBUILD_START_TIME");
    GS_RETURN_IFERR(server_get_idx_auto_rebuild(auto_rebuild_time, attr));
    GS_RETURN_IFERR(server_get_index_recycle(attr));
    GS_RETURN_IFERR(server_get_param_uint32("_LNS_WAIT_TIME", &attr->lsnd_wait_time));

    GS_RETURN_IFERR(server_get_param_uint32("_PRIVATE_ROW_LOCKS", &num32));

    if (num32 < GS_MIN_PRIVATE_LOCKS) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_PRIVATE_ROW_LOCKS", (int64)GS_MIN_PRIVATE_LOCKS);
        return GS_ERROR;
    } else if (num32 > GS_MAX_PRIVATE_LOCKS) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_PRIVATE_ROW_LOCKS", (int64)GS_MAX_PRIVATE_LOCKS);
        return GS_ERROR;
    } else {
        attr->private_row_locks = (uint8)num32;
    }

    GS_RETURN_IFERR(server_get_param_uint32("_PRIVATE_KEY_LOCKS", &num32));

    if (num32 < GS_MIN_PRIVATE_LOCKS) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_PRIVATE_KEY_LOCKS", (int64)GS_MIN_PRIVATE_LOCKS);
        return GS_ERROR;
    } else if (num32 > GS_MAX_PRIVATE_LOCKS) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_PRIVATE_KEY_LOCKS", (int64)GS_MAX_PRIVATE_LOCKS);
        return GS_ERROR;
    } else {
        attr->private_key_locks = (uint8)num32;
    }

    GS_RETURN_IFERR(server_get_param_uint32("DDL_LOCK_TIMEOUT", &num32));
    if (num32 < GS_MIN_DDL_LOCK_TIMEOUT || num32 > GS_MAX_DDL_LOCK_TIMEOUT) {
        GS_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "DDL_LOCK_TIMEOUT", (int64)GS_MIN_DDL_LOCK_TIMEOUT,
            (int64)GS_MAX_DDL_LOCK_TIMEOUT);
        return GS_ERROR;
    } else if (num32 == 0) {
        attr->ddl_lock_timeout = (uint32)LOCK_INF_WAIT;
    } else {
        attr->ddl_lock_timeout = (uint32)num32;
    }
    /* set rm count to suitable value */
    GS_RETURN_IFERR(server_get_param_uint32("_MAX_RM_COUNT", &num32));
    if (num32 != 0) {
        if (g_instance->session_pool.expanded_max_sessions > CM_CALC_ALIGN(num32, GS_EXTEND_RMS)) {
            GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_MAX_RM_COUNT",
                (int64)g_instance->session_pool.expanded_max_sessions);
            return GS_ERROR;
        }

        if (CM_CALC_ALIGN(num32, GS_EXTEND_RMS) > CM_CALC_ALIGN_FLOOR(GS_MAX_RM_COUNT, GS_EXTEND_RMS)) {
            GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_MAX_RM_COUNT",
                (int64)CM_CALC_ALIGN_FLOOR(GS_MAX_RM_COUNT, GS_EXTEND_RMS));
            return GS_ERROR;
        }

        attr->max_rms = CM_CALC_ALIGN(num32, GS_EXTEND_RMS);
        char max_rms_buf[GS_MAX_RM_LEN] = { 0 };
        PRTS_RETURN_IFERR(snprintf_s(max_rms_buf, GS_MAX_RM_LEN, GS_MAX_RM_LEN - 1, "%u", attr->max_rms));
        GS_RETURN_IFERR(cm_alter_config(&g_instance->config, "_MAX_RM_COUNT", max_rms_buf, CONFIG_SCOPE_BOTH, GS_TRUE));
    } else {
        attr->max_rms = g_instance->session_pool.expanded_max_sessions;
        if (attr->max_rms < g_instance->session_pool.max_sessions * RM_SESSION_RATIO) {
            attr->max_rms = (uint32)(g_instance->session_pool.max_sessions * RM_SESSION_RATIO);
        }

        attr->max_rms = CM_CALC_ALIGN(attr->max_rms, GS_EXTEND_RMS);
    }

    GS_RETURN_IFERR(server_get_param_uint32("_ASHRINK_WAIT_TIME", &attr->ashrink_wait_time));
    GS_RETURN_IFERR(server_get_param_uint32("_SHRINK_WAIT_RECYCLED_PAGES", &attr->shrink_wait_recycled_pages));
    GS_RETURN_IFERR(server_get_param_bool32("_TEMPTABLE_SUPPORT_BATCH_INSERT", &attr->temptable_support_batch));
    GS_RETURN_IFERR(server_get_param_uint32("_SMALL_TABLE_SAMPLING_THRESHOLD", &num32));
    attr->small_table_sampling_threshold = num32;

    /* auto block repair */
    GS_RETURN_IFERR(server_get_param_bool32("BLOCK_REPAIR_ENABLE", &attr->enable_abr));
    GS_RETURN_IFERR(server_get_param_uint32("BLOCK_REPAIR_TIMEOUT", &num32));
    if (num32 < 1) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "BLOCK_REPAIR_TIMEOUT", (int64)1);
        return GS_ERROR;
    } else if (num32 > ABR_MAX_TIMEOUT) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "BLOCK_REPAIR_TIMEOUT", (int64)ABR_MAX_TIMEOUT);
        return GS_ERROR;
    } else {
        attr->abr_timeout = num32;
    }

    GS_RETURN_IFERR(server_get_param_uint32("NBU_BACKUP_TIMEOUT", &attr->nbu_backup_timeout));
    if (attr->nbu_backup_timeout < GS_NBU_BACKUP_MIN_WAIT_TIME) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "NBU_BACKUP_TIMEOUT", (int64)GS_NBU_BACKUP_MIN_WAIT_TIME);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(server_get_param_bool32("DEGRADE_SEARCH_MAP", &attr->enable_degrade_search));
    if (server_get_param_size_uint64("LOB_REUSE_THRESHOLD",
                                     &g_instance->kernel.attr.lob_reuse_threshold) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (g_instance->kernel.attr.lob_reuse_threshold < GS_MIN_LOB_REUSE_SIZE) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "LOB_REUSE_THRESHOLD", (int64)GS_MIN_LOB_REUSE_SIZE);
        return GS_ERROR;
    } else if (g_instance->kernel.attr.lob_reuse_threshold >= GS_MAX_LOB_REUSE_SIZE) {
        GS_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "LOB_REUSE_THRESHOLD", (int64)GS_MAX_LOB_REUSE_SIZE);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(server_get_param_bool32("BUILD_DATAFILE_PARALLEL", &attr->build_datafile_parallel));
    GS_RETURN_IFERR(server_get_param_bool32("_CHECK_SYSDATA_VERSION", &attr->check_sysdata_version));
    GS_RETURN_IFERR(server_get_param_uint32("INIT_LOCK_POOL_PAGES", &num32));
    if (num32 < GS_MIN_LOCK_PAGES || num32 > GS_MAX_LOCK_PAGES) {
        GS_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "INIT_LOCK_POOL_PAGES", (int64)GS_MIN_LOCK_PAGES,
            (int64)GS_MAX_LOCK_PAGES);
        return GS_ERROR;
    }

    attr->init_lockpool_pages = num32;
    GS_RETURN_IFERR(server_get_param_bool32("ENABLE_TEMP_SPACE_BITMAP", &attr->enable_temp_bitmap));
    GS_RETURN_IFERR(server_get_param_bool32("BUILD_DATAFILE_PREALLOCATE", &attr->build_datafile_prealloc));
    GS_RETURN_IFERR(server_get_ctrllog_bak_level_param(attr));
    GS_RETURN_IFERR(server_get_param_bool32("_TABLE_COMPRESS_ENABLE_BUFFER", &attr->tab_compress_enable_buf));
    GS_RETURN_IFERR(server_get_param_size_uint64("_TABLE_COMPRESS_BUFFER_SIZE", &attr->tab_compress_buf_size));
    if (attr->tab_compress_buf_size < (int64)GS_MIN_TAB_COMPRESS_BUF_SIZE ||
        attr->tab_compress_buf_size > MIN((int64)GS_MAX_TAB_COMPRESS_BUF_SIZE, attr->temp_buf_size)) {
        GS_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "_TABLE_COMPRESS_BUFFER_SIZE", (int64)GS_MIN_TAB_COMPRESS_BUF_SIZE,
            MIN((int64)GS_MAX_TAB_COMPRESS_BUF_SIZE, attr->temp_buf_size));
        return GS_ERROR;
    }

    value = server_get_param("_TABLE_COMPRESS_ALGO");
    if (cm_str_equal_ins(value, "NONE")) {
        g_instance->kernel.attr.default_compress_algo = COMPRESS_NONE;
    } else if (cm_str_equal_ins(value, "ZSTD")) {
        g_instance->kernel.attr.default_compress_algo = COMPRESS_ZSTD;
    } else {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "_TABLE_COMPRESS_ALGO", value);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(server_get_param_uint32("_BUFFER_PAGE_CLEAN_WAIT_TIMEOUT", &num32));
    g_instance->kernel.attr.page_clean_wait_timeout = (uint32)num32;
    GS_RETURN_IFERR(server_get_param_uint32("_CHECKPOINT_TIMED_TASK_DELAY", &num32));
    g_instance->kernel.attr.ckpt_timed_task_delay = (uint32)num32;
    GS_RETURN_IFERR(server_get_default_page_clean_mode_param(attr));
    GS_RETURN_IFERR(server_get_param_size_uint32("BATCH_FLUSH_CAPACITY", &attr->batch_flush_capacity));
    if (attr->batch_flush_capacity < GS_MIN_BATCH_FLUSH_CAPACITY ||
        attr->batch_flush_capacity > GS_MAX_BATCH_FLUSH_CAPACITY) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "BATCH_FLUSH_CAPACITY", attr->batch_flush_capacity);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

#ifdef __cplusplus
}
#endif
