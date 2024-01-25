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
 * srv_sga.c
 *
 *
 * IDENTIFICATION
 * src/server/srv_sga.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_module.h"
#include "cm_log.h"
#include "cm_kmc.h"
#include "srv_sga.h"
#include "srv_instance.h"
#include "dtc_database.h"

#ifndef WIN32
#include <sys/mman.h>
#ifndef MAP_HUGETLB
#define MAP_HUGETLB SHM_HUGETLB
#endif
#endif

status_t srv_swap_out(handle_t se, vm_page_t *page, uint64 *swid, uint32 *cipher_len)
{
    knl_session_t *session = (knl_session_t *)se;
    page_id_t extent;
    if (knl_alloc_swap_extent(session, &extent) != CT_SUCCESS) {
        return CT_ERROR;
    }

    knl_begin_session_wait(se, DIRECT_PATH_WRITE_TEMP, CT_TRUE);
    if (knl_write_swap_data(session, extent, page->data, CT_VMEM_PAGE_SIZE, cipher_len) != CT_SUCCESS) {
        return CT_ERROR;
    }
    knl_end_session_wait(se, DIRECT_PATH_WRITE_TEMP);

    *swid = *(uint64 *)&extent;

    CT_LOG_DEBUG_INF("TEMP: swap out to disk page (%d:%d), free(%d), vm(ctrl_id = %d)", extent.file, extent.page,
        (SPACE_GET(session, dtc_my_ctrl(session)->swap_space))->head->free_extents.count, page->vmid);
    return CT_SUCCESS;
}

status_t srv_swap_in(handle_t se, uint64 swid, uint32 cipher_len, vm_page_t *page)
{
    knl_session_t *session = (knl_session_t *)se;
    page_id_t extent = *(page_id_t *)&swid;

    knl_begin_session_wait(session, DIRECT_PATH_READ_TEMP, CT_TRUE);
    if (knl_read_swap_data(session, extent, cipher_len, page->data, CT_VMEM_PAGE_SIZE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    knl_end_session_wait(session, DIRECT_PATH_READ_TEMP);

    knl_release_swap_extent(session, extent);

    CT_LOG_DEBUG_INF("TEMP: swap in disk page from (%d:%d), free(%d),vm(ctrl_id=%d)", extent.file, extent.page,
        (SPACE_GET(session, dtc_my_ctrl(session)->swap_space))->head->free_extents.count, page->vmid);
    return CT_SUCCESS;
}

void srv_swap_clean(handle_t session, uint64 swid)
{
    page_id_t extent = *(page_id_t *)&swid;
    knl_release_swap_extent(session, extent);
}

uint32 srv_get_swap_extents(handle_t session)
{
    return knl_get_swap_extents(session);
}

void srv_stat_begin_vm(handle_t se)
{
    session_t *session = (session_t *)se;
    sql_stmt_t *stmt = session->current_stmt;
    if (stmt == NULL || !cm_log_param_instance()->longsql_print_enable) {
        return;
    }

    vm_stat_t *vm_stat = &stmt->vm_stat;
    MEMS_RETVOID_IFERR(cm_gettimeofday(&vm_stat->time_begin));
}

void srv_stat_end_vm(handle_t se)
{
    session_t *session = (session_t *)se;
    sql_stmt_t *stmt = session->current_stmt;
    if (stmt == NULL || !cm_log_param_instance()->longsql_print_enable) {
        return;
    }

    vm_stat_t *vm_stat = &stmt->vm_stat;
    timeval_t tv_end;
    MEMS_RETVOID_IFERR(cm_gettimeofday(&tv_end));
    vm_stat->time_elapsed += TIMEVAL_DIFF_US(&vm_stat->time_begin, &tv_end);
}

void srv_stat_vm(handle_t se, vm_stat_mode_t mode)
{
    session_t *session = (session_t *)se;
    sql_stmt_t *stmt = session->current_stmt;
    if (stmt == NULL) {
        return;
    }
    vm_stat_t *vm_stat = &stmt->vm_stat;
    switch (mode) {
        case VM_STAT_OPEN:
            vm_stat->open_pages++;
            vm_stat->max_open_pages = MAX(vm_stat->max_open_pages, vm_stat->open_pages - vm_stat->close_pages);
            break;
        case VM_STAT_CLOSE:
            vm_stat->close_pages++;
            break;
        case VM_STAT_ALLOC:
            vm_stat->alloc_pages++;
            break;
        case VM_STAT_FREE:
            vm_stat->free_pages++;
            break;
        case VM_STAT_SWAP_IN:
            vm_stat->swap_in_pages++;
            break;
        case VM_STAT_SWAP_OUT:
            vm_stat->swap_out_pages++;
            break;
        case VM_STAT_BEGIN:
            srv_stat_begin_vm(se);
            break;
        case VM_STAT_END:
            srv_stat_end_vm(se);
            break;
        default:
            cm_assert(0);
    }
}

static void srv_init_vm_pools(vm_pool_t *pool, char *buf, int64 buf_size, const vm_swapper_t *swapper, vm_statis_t stat)
{
    vm_init_pool(pool, buf, buf_size, swapper, stat);
    pool->temp_pools = g_instance->kernel.temp_pool;
    pool->pool_hwm = g_instance->kernel.temp_ctx_count;
}

static void srv_init_normal_vmem_pool(vm_swapper_t *swapper)
{
    knl_attr_t *attr = &g_instance->kernel.attr;
    vm_pool_t *pool = NULL;

    for (uint32 i = 0; i < g_instance->kernel.temp_ctx_count; i++) {
        pool = &g_instance->kernel.temp_pool[i];
        srv_init_vm_pools(pool, attr->temp_buf + i * attr->temp_buf_inst_align_size, (int64)attr->temp_buf_inst_size,
            swapper, srv_stat_vm);
        pool->pool_id = i;
        pool->map_pages[0].pool_id = pool->pool_id;
    }
}

static status_t srv_init_rsrc_vmem_pool(vm_swapper_t *swapper)
{
    rsrc_plan_t *plan = GET_RSRC_MGR->plan;
    knl_attr_t *attr = &g_instance->kernel.attr;
    knl_instance_t *ctx = &g_instance->kernel;
    vm_pool_t *pool = NULL;
    rsrc_group_t *group = NULL;
    uint64 offset, buf_size;
    uint32 temp_ctx_count = 1;

    offset = 0;
    for (uint32 i = 1; i < plan->group_count; i++) {
        group = plan->groups[i];
        if (group->max_temp_pool == CT_MAX_UINT32) {
            group->temp_pool = &ctx->temp_pool[0];
            continue;
        }
        pool = &ctx->temp_pool[temp_ctx_count++];
        buf_size = (uint64)group->max_temp_pool << 20; // convert megabyte to bytes
        if (buf_size < CT_MIN_TEMP_BUFFER_SIZE) {
            CT_LOG_RUN_ERR("Temp pool (%llu) for control group '%s' is too small, less than the minimum(%llu)",
                buf_size, group->knl_group.name, (uint64)CT_MIN_TEMP_BUFFER_SIZE);
            return CT_ERROR;
        }
        if (offset + buf_size > attr->temp_buf_size) {
            CT_LOG_RUN_ERR("Resource plan allocated temp pool(%llu) exceeds the limit(%llu)", offset + buf_size,
                attr->temp_buf_size);
            return CT_ERROR;
        }
        srv_init_vm_pools(pool, attr->temp_buf + offset, (int64)buf_size, swapper, srv_stat_vm);
        pool->pool_id = i;
        pool->map_pages[0].pool_id = pool->pool_id;
        offset += buf_size;
        group->temp_pool = pool;
    }

    if (offset == 0) {
        srv_init_normal_vmem_pool(swapper);
        for (uint32 i = 0; i < plan->group_count; i++) {
            plan->groups[i]->temp_pool = &ctx->temp_pool[i % ctx->temp_ctx_count];
        }
        return CT_SUCCESS;
    }

    /* leave the rest temp pool to default group */
    buf_size = attr->temp_buf_size - offset;
    if (buf_size < CT_MIN_TEMP_BUFFER_SIZE) {
        CT_LOG_RUN_ERR("The rest temp pool(%llu) for default control group is too small, less than the minimum(%llu)",
            buf_size, (uint64)CT_MIN_TEMP_BUFFER_SIZE);
        return CT_ERROR;
    }
    pool = &ctx->temp_pool[0];
    srv_init_vm_pools(pool, attr->temp_buf + offset, (int64)buf_size, swapper, srv_stat_vm);
    plan->groups[0]->temp_pool = pool;
    ctx->temp_ctx_count = temp_ctx_count;
    return CT_SUCCESS;
}

static vm_swapper_t g_vm_swapper = {
    .in = srv_swap_in,
    .out = srv_swap_out,
    .clean = srv_swap_clean,
    .get_swap_extents = srv_get_swap_extents
};

/* reinit temp pool when resource manager started */
status_t srv_init_vmem_pool(void)
{
    if (GET_RSRC_MGR->plan != NULL) {
        if (srv_init_rsrc_vmem_pool(&g_vm_swapper) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        srv_init_normal_vmem_pool(&g_vm_swapper);
    }
    return CT_SUCCESS;
}

#define SGA_BARRIER_SIZE 64

static status_t load_large_pages_param(large_pages_mode_t *large_pages_mode)
{
    char *value = srv_get_param("USE_LARGE_PAGES");

    if (cm_str_equal_ins(value, "TRUE")) {
        *large_pages_mode = LARGE_PAGES_TRUE;
    } else if (cm_str_equal_ins(value, "FALSE")) {
        *large_pages_mode = LARGE_PAGES_FALSE;
    } else if (cm_str_equal_ins(value, "ONLY")) {
        *large_pages_mode = LARGE_PAGES_ONLY;
    } else {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "USE_LARGE_PAGES");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t srv_alloc_sga(sga_t *sga)
{
    large_pages_mode_t large_pages_mode;

    if (CT_SUCCESS != load_large_pages_param(&large_pages_mode)) {
        return CT_ERROR;
    }

    // LARGE_PAGES is a feature supported only by linux
#ifndef WIN32

    if (large_pages_mode == LARGE_PAGES_ONLY || large_pages_mode == LARGE_PAGES_TRUE) {
        sga->buf = mmap(0, (size_t)sga->size + CT_MAX_ALIGN_SIZE_4K, PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_HUGETLB | MAP_ANONYMOUS, (int)CT_INVALID_ID32, 0);
        if (sga->buf != (char *)(int)CT_INVALID_ID32) {
            g_instance->attr.mem_alloc_from_large_page = CT_TRUE;
            return CT_SUCCESS;
        }
        if (large_pages_mode == LARGE_PAGES_ONLY) {
            CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sga->size, "sga");
            return CT_ERROR;
        }
    }

#endif
    if (CT_MAX_UINT64 - (size_t)sga->size < CT_MAX_ALIGN_SIZE_4K) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sga->size, "sga");
        return CT_ERROR;
    }
    sga->buf = malloc((size_t)sga->size + CT_MAX_ALIGN_SIZE_4K);

    if (sga->buf == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sga->size, "sga");
        return CT_ERROR;
    }

    g_instance->attr.mem_alloc_from_large_page = CT_FALSE;

    return CT_SUCCESS;
}

static inline uint64 srv_calc_buf_size(uint64 size)
{
    uint64 align_size = CM_CALC_ALIGN(size + SGA_BARRIER_SIZE, CT_MAX_ALIGN_SIZE_4K);
    return align_size;
}

static inline void srv_set_sga_buffer(char **buf, uint64 size, uint64 *offset)
{
    sga_t *sga = &g_instance->sga;
    char *barrier = NULL;

    *buf = sga->buf + *offset;
    barrier = sga->buf + *offset + size;
    *offset += srv_calc_buf_size(size);

    MEMS_RETVOID_IFERR(memset_s(barrier, SGA_BARRIER_SIZE, 0xFF, SGA_BARRIER_SIZE));
}

static uint64 srv_calc_data_buf_size(knl_instance_t *kernel)
{
    buf_context_t *ctx = &kernel->buf_ctx;

    /* * adjust buf_ctx_count to match the data_buf_size */
    if ((kernel->attr.buf_pool_num > 1) &&
        (kernel->attr.data_buf_size < BUF_POOL_SIZE_THRESHOLD * kernel->attr.buf_pool_num)) {
        ctx->buf_set_count = MAX(1, (uint32)(kernel->attr.data_buf_size / BUF_POOL_SIZE_THRESHOLD));
        CT_LOG_RUN_WAR("The parameter buffer pool num (%d) is too large, reset to (%d), each buffer "
            "pool must not be smaller than (%lld).",
            kernel->attr.buf_pool_num, ctx->buf_set_count, BUF_POOL_SIZE_THRESHOLD);
    } else {
        ctx->buf_set_count = kernel->attr.buf_pool_num;
    }
    kernel->attr.data_buf_part_size = kernel->attr.data_buf_size / ctx->buf_set_count;
    kernel->attr.data_buf_part_align_size = srv_calc_buf_size(kernel->attr.data_buf_part_size);
    return kernel->attr.data_buf_part_align_size * ctx->buf_set_count;
}

static uint64 srv_calc_cr_pool_size(knl_instance_t *kernel)
{
    /* * adjust pcrp_ctx_count to match the cr_pool_size */
    if ((kernel->attr.cr_pool_count > 1) &&
        (kernel->attr.cr_pool_size < CR_POOL_SIZE_THRESHOLD * kernel->attr.cr_pool_count)) {
        kernel->pcrp_ctx.pcrp_set_count = MAX(1, (uint32)(kernel->attr.cr_pool_size / CR_POOL_SIZE_THRESHOLD));
        CT_LOG_RUN_WAR("The parameter CR_POOL_COUNT (%d) is too large, reset to (%d), "
            "each CR pool must not be smaller than (%lld).",
            kernel->attr.cr_pool_count, kernel->pcrp_ctx.pcrp_set_count, CR_POOL_SIZE_THRESHOLD);
    } else {
        kernel->pcrp_ctx.pcrp_set_count = kernel->attr.cr_pool_count;
    }

    kernel->attr.cr_pool_part_size = kernel->attr.cr_pool_size / kernel->pcrp_ctx.pcrp_set_count;
    kernel->attr.cr_pool_part_align_size = srv_calc_buf_size(kernel->attr.cr_pool_part_size);
    return kernel->attr.cr_pool_part_align_size * kernel->pcrp_ctx.pcrp_set_count;
}

static uint64 srv_calc_temp_buf_size(knl_instance_t *kernel)
{
    if ((kernel->attr.temp_pool_num > 1) &&
        (kernel->attr.temp_buf_size < TEMP_POOL_SIZE_THRESHOLD * kernel->attr.temp_pool_num)) {
        kernel->temp_ctx_count = MAX(1, (uint32)(kernel->attr.temp_buf_size / TEMP_POOL_SIZE_THRESHOLD));
        CT_LOG_RUN_WAR("The parameter temp pool num (%d) is too large, reset to (%d), "
            "each temp pool must not be smaller than (%lld).",
            kernel->attr.temp_pool_num, kernel->temp_ctx_count, TEMP_POOL_SIZE_THRESHOLD);
    } else {
        kernel->temp_ctx_count = kernel->attr.temp_pool_num;
    }
    kernel->attr.temp_buf_inst_size = kernel->attr.temp_buf_size / kernel->temp_ctx_count;
    kernel->attr.temp_buf_inst_align_size = srv_calc_buf_size(kernel->attr.temp_buf_inst_size);
    return kernel->attr.temp_buf_inst_align_size * kernel->temp_ctx_count;
}

static void srv_calc_sga_size(sga_t *sga)
{
    knl_instance_t *kernel = &g_instance->kernel;

    sga->size += srv_calc_data_buf_size(kernel);
    sga->size += srv_calc_cr_pool_size(kernel);
    sga->size += srv_calc_buf_size(kernel->attr.log_buf_size);
    sga->size += srv_calc_buf_size(kernel->attr.shared_area_size);
    sga->size += srv_calc_buf_size(kernel->attr.vma_size);
    sga->size += srv_calc_buf_size(kernel->attr.large_vma_size);
    sga->size += srv_calc_buf_size(kernel->attr.pma_size);
    sga->size += srv_calc_buf_size(kernel->attr.tran_buf_size);
    sga->size += srv_calc_buf_size(kernel->attr.dbwr_buf_size);
    sga->size += srv_calc_buf_size(kernel->attr.lgwr_buf_size);
    sga->size += srv_calc_buf_size(kernel->attr.lgwr_cipher_buf_size);
    sga->size += srv_calc_buf_size(kernel->attr.lgwr_async_buf_size);
    sga->size += srv_calc_buf_size(kernel->attr.lgwr_head_buf_size);
    sga->size += srv_calc_buf_size(kernel->attr.large_pool_size);
    sga->size += srv_calc_buf_size(kernel->attr.buf_iocbs_size);
    sga->size += srv_calc_temp_buf_size(kernel);
    sga->size += srv_calc_buf_size(kernel->attr.index_buf_size);
}

static void srv_set_sga_bufs(sga_t *sga)
{
    knl_instance_t *kernel = &g_instance->kernel;
    char *temp_buf = NULL;
    uint64 offset = (CT_MAX_ALIGN_SIZE_4K - ((uint64)sga->buf) % CT_MAX_ALIGN_SIZE_4K);

    /* * allocate each data buffer part */
    srv_set_sga_buffer(&sga->data_buf, kernel->attr.data_buf_part_size, &offset);
    for (uint32 i = 1; i < kernel->buf_ctx.buf_set_count; i++) {
        srv_set_sga_buffer(&temp_buf, kernel->attr.data_buf_part_size, &offset);
    }

    /* * allocate each CR pool part */
    srv_set_sga_buffer(&sga->cr_buf, kernel->attr.cr_pool_part_size, &offset);
    for (uint32 i = 1; i < kernel->pcrp_ctx.pcrp_set_count; i++) {
        srv_set_sga_buffer(&temp_buf, kernel->attr.cr_pool_part_size, &offset);
    }

    srv_set_sga_buffer(&sga->log_buf, kernel->attr.log_buf_size, &offset);
    srv_set_sga_buffer(&sga->shared_buf, kernel->attr.shared_area_size, &offset);
    srv_set_sga_buffer(&sga->vma_buf, kernel->attr.vma_size, &offset);
    srv_set_sga_buffer(&sga->vma_large_buf, kernel->attr.large_vma_size, &offset);
    srv_set_sga_buffer(&sga->pma_buf, kernel->attr.pma_size, &offset);
    srv_set_sga_buffer(&sga->tran_buf, kernel->attr.tran_buf_size, &offset);
    srv_set_sga_buffer(&sga->dbwr_buf, kernel->attr.dbwr_buf_size, &offset);
    srv_set_sga_buffer(&sga->lgwr_buf, kernel->attr.lgwr_buf_size, &offset);
    srv_set_sga_buffer(&sga->lgwr_cipher_buf, kernel->attr.lgwr_cipher_buf_size, &offset);
    srv_set_sga_buffer(&sga->lgwr_async_buf, kernel->attr.lgwr_async_buf_size, &offset);
    srv_set_sga_buffer(&sga->lgwr_head_buf, kernel->attr.lgwr_head_buf_size, &offset);
    srv_set_sga_buffer(&sga->large_buf, kernel->attr.large_pool_size, &offset);
    srv_set_sga_buffer(&sga->buf_iocbs, kernel->attr.buf_iocbs_size, &offset);

    uint64 start_offset = offset;
    srv_set_sga_buffer(&sga->temp_buf, kernel->attr.temp_buf_inst_size, &offset);
    CM_ASSERT(offset - start_offset == kernel->attr.temp_buf_inst_align_size);
    for (uint32 i = 1; i < kernel->temp_ctx_count; i++) {
        char *tmp_data_buf = NULL;
        srv_set_sga_buffer(&tmp_data_buf, kernel->attr.temp_buf_inst_size, &offset);
        CM_ASSERT(offset - start_offset == kernel->attr.temp_buf_inst_align_size * (i + 1));
    }
    srv_set_sga_buffer(&sga->index_buf, kernel->attr.index_buf_size, &offset);
}

static status_t srv_init_sga_bufs(sga_t *sga)
{
    knl_instance_t *kernel = &g_instance->kernel;

    marea_attach("shared area", sga->shared_buf, (size_t)kernel->attr.shared_area_size, CT_SHARED_PAGE_SIZE,
        &sga->shared_area);

    marea_attach("variant memory area", sga->vma_buf, (size_t)kernel->attr.vma_size, CT_VMA_PAGE_SIZE, &sga->vma.marea);
    CT_RETURN_IFERR(marea_reset_page_buf(&sga->vma.marea, VMC_MAGIC));

    marea_attach("variant memory large area", sga->vma_large_buf, (size_t)kernel->attr.large_vma_size,
        CT_LARGE_VMA_PAGE_SIZE, &sga->vma.large_marea);
    CT_RETURN_IFERR(marea_reset_page_buf(&sga->vma.large_marea, VMC_MAGIC));

    pm_area_init("private memory area", sga->pma_buf, (size_t)kernel->attr.pma_size, &sga->pma);

    mpool_attach("large pool", sga->large_buf, (int64)kernel->attr.large_pool_size, CT_LARGE_PAGE_SIZE,
        &sga->large_pool);
    if (mem_pool_init(&sga->buddy_pool, "buddy pool", kernel->attr.buddy_init_size, kernel->attr.buddy_max_size) !=
        CT_SUCCESS) {
        return CT_ERROR;
    }
    kernel->attr.data_buf = sga->data_buf;
    kernel->attr.cr_buf = sga->cr_buf;
    kernel->attr.log_buf = sga->log_buf;
    kernel->attr.lgwr_buf = sga->lgwr_buf;
    kernel->attr.lgwr_cipher_buf = sga->lgwr_cipher_buf;
    kernel->attr.lgwr_async_buf = sga->lgwr_async_buf;
    kernel->attr.lgwr_head_buf = sga->lgwr_head_buf;
    kernel->attr.ckpt_buf = sga->dbwr_buf;
    kernel->attr.tran_buf = sga->tran_buf;
    kernel->attr.temp_buf = sga->temp_buf;
    kernel->attr.index_buf = sga->index_buf;
    kernel->attr.shared_area = &sga->shared_area;
    kernel->attr.large_pool = &sga->large_pool;
    kernel->attr.buf_iocbs = sga->buf_iocbs;

    srv_init_normal_vmem_pool(&g_vm_swapper);
    return CT_SUCCESS;
}

status_t srv_create_sga(void)
{
    sga_t *sga = &g_instance->sga;

    srv_calc_sga_size(sga);

    if (srv_alloc_sga(sga) != CT_SUCCESS) {
        return CT_ERROR;
    }

    srv_set_sga_bufs(sga);

    if (srv_init_sga_bufs(sga) != CT_SUCCESS) {
        srv_destroy_sga();
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void srv_destroy_sga()
{
    sql_destroy_context_pool();
    mem_pool_deinit(&g_instance->sga.buddy_pool);
#ifdef WIN32
    CM_FREE_PTR(g_instance->sga.buf);
#else
    if (g_instance->attr.mem_alloc_from_large_page) {
        (void)munmap(g_instance->sga.buf, g_instance->sga.size);
    } else {
        CM_FREE_PTR(g_instance->sga.buf);
    }
#endif
    g_instance->sga.buf = NULL;
}
