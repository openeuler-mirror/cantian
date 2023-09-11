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
 * srv_sga.c
 *
 *
 * IDENTIFICATION
 * src/server/srv_sga.c
 *
 * -------------------------------------------------------------------------
 */
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

status_t server_swap_out(handle_t se, vm_page_t *page, uint64 *swid, uint32 *cipher_len)
{
    knl_session_t *session = (knl_session_t *)se;
    page_id_t extent;
    if (knl_alloc_swap_extent(session, &extent) != GS_SUCCESS) {
        return GS_ERROR;
    }

    knl_begin_session_wait(se, DIRECT_PATH_WRITE_TEMP, GS_TRUE);
    if (knl_write_swap_data(session, extent, page->data, GS_VMEM_PAGE_SIZE, cipher_len) != GS_SUCCESS) {
        return GS_ERROR;
    }
    knl_end_session_wait(se);

    *swid = *(uint64 *)&extent;

    GS_LOG_DEBUG_INF("TEMP: swap out to disk page (%d:%d), free(%d), vm(ctrl_id = %d)", extent.file, extent.page,
        (SPACE_GET(session, dtc_my_ctrl(session)->swap_space))->head->free_extents.count, page->vmid);
    return GS_SUCCESS;
}

status_t server_swap_in(handle_t se, uint64 swid, uint32 cipher_len, vm_page_t *page)
{
    knl_session_t *session = (knl_session_t *)se;
    page_id_t extent = *(page_id_t *)&swid;

    knl_begin_session_wait(session, DIRECT_PATH_READ_TEMP, GS_TRUE);
    if (knl_read_swap_data(session, extent, cipher_len, page->data, GS_VMEM_PAGE_SIZE) != GS_SUCCESS) {
        return GS_ERROR;
    }
    knl_end_session_wait(session);

    knl_release_swap_extent(session, extent);

    GS_LOG_DEBUG_INF("TEMP: swap in disk page from (%d:%d), free(%d),vm(ctrl_id=%d)", extent.file, extent.page,
        (SPACE_GET(session, dtc_my_ctrl(session)->swap_space))->head->free_extents.count, page->vmid);
    return GS_SUCCESS;
}

void server_swap_clean(handle_t session, uint64 swid)
{
    page_id_t extent = *(page_id_t *)&swid;
    knl_release_swap_extent(session, extent);
}

uint32 server_get_swap_exts(handle_t session)
{
    return knl_get_swap_extents(session);
}

void server_stat_vm(handle_t se, vm_stat_mode_t mode)
{
}

static void server_init_vm_pools(vm_pool_t *pool, char *buf, int64 buf_size, const vm_swapper_t *swapper, vm_statis_t stat)
{
    vm_init_pool(pool, buf, buf_size, swapper, stat);
    pool->temp_pools = g_instance->kernel.temp_pool;
    pool->pool_hwm = g_instance->kernel.temp_ctx_count;
}

static void server_init_normal_vmem_pool(vm_swapper_t *swapper)
{
    knl_attr_t *attr = &g_instance->kernel.attr;
    vm_pool_t *pool = NULL;

    for (uint32 i = 0; i < g_instance->kernel.temp_ctx_count; i++) {
        pool = &g_instance->kernel.temp_pool[i];
        server_init_vm_pools(pool, attr->temp_buf + i * attr->temp_buf_inst_align_size, (int64)attr->temp_buf_inst_size,
            swapper, server_stat_vm);
        pool->pool_id = i;
        pool->map_pages[0].pool_id = pool->pool_id;
    }
}

static vm_swapper_t g_vm_swapper = {
    .in = server_swap_in,
    .out = server_swap_out,
    .clean = server_swap_clean,
    .get_swap_extents = server_get_swap_exts
};

#define SGA_BARRIER_SIZE 64

static status_t load_large_pages_param(large_pages_mode_t *large_pages_mode)
{
    char *value = server_get_param("USE_LARGE_PAGES");

    if (cm_str_equal_ins(value, "TRUE")) {
        *large_pages_mode = LARGE_PAGES_TRUE;
    } else if (cm_str_equal_ins(value, "FALSE")) {
        *large_pages_mode = LARGE_PAGES_FALSE;
    } else if (cm_str_equal_ins(value, "ONLY")) {
        *large_pages_mode = LARGE_PAGES_ONLY;
    } else {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, "USE_LARGE_PAGES");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t server_alloc_sga(sga_t *sga)
{
    large_pages_mode_t large_pages_mode;

    if (GS_SUCCESS != load_large_pages_param(&large_pages_mode)) {
        return GS_ERROR;
    }

    // LARGE_PAGES is a feature supported only by linux
#ifndef WIN32

    if (large_pages_mode == LARGE_PAGES_ONLY || large_pages_mode == LARGE_PAGES_TRUE) {
        sga->buf = mmap(0, (size_t)sga->size + GS_MAX_ALIGN_SIZE_4K, PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_HUGETLB | MAP_ANONYMOUS, (int)GS_INVALID_ID32, 0);
        if (sga->buf != (char *)(int)GS_INVALID_ID32) {
            g_instance->attr.mem_alloc_from_large_page = GS_TRUE;
            return GS_SUCCESS;
        }
        if (large_pages_mode == LARGE_PAGES_ONLY) {
            GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sga->size, "sga");
            return GS_ERROR;
        }
    }

#endif
    if (GS_MAX_UINT64 - (size_t)sga->size < GS_MAX_ALIGN_SIZE_4K) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sga->size, "sga");
        return GS_ERROR;
    }
    sga->buf = malloc((size_t)sga->size + GS_MAX_ALIGN_SIZE_4K);

    if (sga->buf == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sga->size, "sga");
        return GS_ERROR;
    }

    g_instance->attr.mem_alloc_from_large_page = GS_FALSE;

    return GS_SUCCESS;
}

static inline uint64 server_calc_buf_size(uint64 size)
{
    uint64 align_size = CM_CALC_ALIGN(size + SGA_BARRIER_SIZE, GS_MAX_ALIGN_SIZE_4K);
    return align_size;
}

static inline void server_set_sga_buf(char **buf, uint64 size, uint64 *offset)
{
    sga_t *sga = &g_instance->sga;
    char *barrier = NULL;

    *buf = sga->buf + *offset;
    barrier = sga->buf + *offset + size;
    *offset += server_calc_buf_size(size);

    MEMS_RETVOID_IFERR(memset_s(barrier, SGA_BARRIER_SIZE, 0xFF, SGA_BARRIER_SIZE));
}

static uint64 server_calc_data_buf_size(knl_instance_t *kernel)
{
    buf_context_t *ctx = &kernel->buf_ctx;

    /* * adjust buf_ctx_count to match the data_buf_size */
    if ((kernel->attr.buf_pool_num > 1) &&
        (kernel->attr.data_buf_size < BUF_POOL_SIZE_THRESHOLD * kernel->attr.buf_pool_num)) {
        ctx->buf_set_count = MAX(1, (uint32)(kernel->attr.data_buf_size / BUF_POOL_SIZE_THRESHOLD));
        GS_LOG_RUN_WAR("The parameter buffer pool num (%d) is too large, reset to (%d), each buffer "
            "pool must not be smaller than (%lld).",
            kernel->attr.buf_pool_num, ctx->buf_set_count, BUF_POOL_SIZE_THRESHOLD);
    } else {
        ctx->buf_set_count = kernel->attr.buf_pool_num;
    }
    kernel->attr.data_buf_part_size = kernel->attr.data_buf_size / ctx->buf_set_count;
    kernel->attr.data_buf_part_align_size = server_calc_buf_size(kernel->attr.data_buf_part_size);
    return kernel->attr.data_buf_part_align_size * ctx->buf_set_count;
}

static uint64 server_calc_cr_pool_size(knl_instance_t *kernel)
{
    /* * adjust pcrp_ctx_count to match the cr_pool_size */
    if ((kernel->attr.cr_pool_count > 1) &&
        (kernel->attr.cr_pool_size < CR_POOL_SIZE_THRESHOLD * kernel->attr.cr_pool_count)) {
        kernel->pcrp_ctx.pcrp_set_count = MAX(1, (uint32)(kernel->attr.cr_pool_size / CR_POOL_SIZE_THRESHOLD));
        GS_LOG_RUN_WAR("The parameter CR_POOL_COUNT (%d) is too large, reset to (%d), "
            "each CR pool must not be smaller than (%lld).",
            kernel->attr.cr_pool_count, kernel->pcrp_ctx.pcrp_set_count, CR_POOL_SIZE_THRESHOLD);
    } else {
        kernel->pcrp_ctx.pcrp_set_count = kernel->attr.cr_pool_count;
    }

    kernel->attr.cr_pool_part_size = kernel->attr.cr_pool_size / kernel->pcrp_ctx.pcrp_set_count;
    kernel->attr.cr_pool_part_align_size = server_calc_buf_size(kernel->attr.cr_pool_part_size);
    return kernel->attr.cr_pool_part_align_size * kernel->pcrp_ctx.pcrp_set_count;
}

static uint64 server_calc_temp_buf_size(knl_instance_t *kernel)
{
    if ((kernel->attr.temp_pool_num > 1) &&
        (kernel->attr.temp_buf_size < TEMP_POOL_SIZE_THRESHOLD * kernel->attr.temp_pool_num)) {
        kernel->temp_ctx_count = MAX(1, (uint32)(kernel->attr.temp_buf_size / TEMP_POOL_SIZE_THRESHOLD));
        GS_LOG_RUN_WAR("The parameter temp pool num (%d) is too large, reset to (%d), "
            "each temp pool must not be smaller than (%lld).",
            kernel->attr.temp_pool_num, kernel->temp_ctx_count, TEMP_POOL_SIZE_THRESHOLD);
    } else {
        kernel->temp_ctx_count = kernel->attr.temp_pool_num;
    }
    kernel->attr.temp_buf_inst_size = kernel->attr.temp_buf_size / kernel->temp_ctx_count;
    kernel->attr.temp_buf_inst_align_size = server_calc_buf_size(kernel->attr.temp_buf_inst_size);
    return kernel->attr.temp_buf_inst_align_size * kernel->temp_ctx_count;
}

static void server_calc_sga_size(sga_t *sga)
{
    knl_instance_t *kernel = &g_instance->kernel;

    sga->size += server_calc_data_buf_size(kernel);
    sga->size += server_calc_cr_pool_size(kernel);
    sga->size += server_calc_buf_size(kernel->attr.log_buf_size);
    sga->size += server_calc_buf_size(kernel->attr.shared_area_size);
    sga->size += server_calc_buf_size(kernel->attr.vma_size);
    sga->size += server_calc_buf_size(kernel->attr.large_vma_size);
    sga->size += server_calc_buf_size(kernel->attr.pma_size);
    sga->size += server_calc_buf_size(kernel->attr.tran_buf_size);
    sga->size += server_calc_buf_size(kernel->attr.dbwr_buf_size);
    sga->size += server_calc_buf_size(kernel->attr.lgwr_buf_size);
    sga->size += server_calc_buf_size(kernel->attr.lgwr_cipher_buf_size);
    sga->size += server_calc_buf_size(kernel->attr.lgwr_async_buf_size);
    sga->size += server_calc_buf_size(kernel->attr.lgwr_head_buf_size);
    sga->size += server_calc_buf_size(kernel->attr.large_pool_size);
    sga->size += server_calc_buf_size(kernel->attr.buf_iocbs_size);
    sga->size += server_calc_temp_buf_size(kernel);
    sga->size += server_calc_buf_size(kernel->attr.index_buf_size);
}

static void server_set_sga_bufs(sga_t *sga)
{
    knl_instance_t *kernel = &g_instance->kernel;
    char *temp_buf = NULL;
    uint64 offset = (GS_MAX_ALIGN_SIZE_4K - ((uint64)sga->buf) % GS_MAX_ALIGN_SIZE_4K);

    /* * allocate each data buffer part */
    server_set_sga_buf(&sga->data_buf, kernel->attr.data_buf_part_size, &offset);
    for (uint32 i = 1; i < kernel->buf_ctx.buf_set_count; i++) {
        server_set_sga_buf(&temp_buf, kernel->attr.data_buf_part_size, &offset);
    }

    /* * allocate each CR pool part */
    server_set_sga_buf(&sga->cr_buf, kernel->attr.cr_pool_part_size, &offset);
    for (uint32 i = 1; i < kernel->pcrp_ctx.pcrp_set_count; i++) {
        server_set_sga_buf(&temp_buf, kernel->attr.cr_pool_part_size, &offset);
    }

    server_set_sga_buf(&sga->log_buf, kernel->attr.log_buf_size, &offset);
    server_set_sga_buf(&sga->shared_buf, kernel->attr.shared_area_size, &offset);
    server_set_sga_buf(&sga->vma_buf, kernel->attr.vma_size, &offset);
    server_set_sga_buf(&sga->vma_large_buf, kernel->attr.large_vma_size, &offset);
    server_set_sga_buf(&sga->pma_buf, kernel->attr.pma_size, &offset);
    server_set_sga_buf(&sga->tran_buf, kernel->attr.tran_buf_size, &offset);
    server_set_sga_buf(&sga->dbwr_buf, kernel->attr.dbwr_buf_size, &offset);
    server_set_sga_buf(&sga->lgwr_buf, kernel->attr.lgwr_buf_size, &offset);
    server_set_sga_buf(&sga->lgwr_cipher_buf, kernel->attr.lgwr_cipher_buf_size, &offset);
    server_set_sga_buf(&sga->lgwr_async_buf, kernel->attr.lgwr_async_buf_size, &offset);
    server_set_sga_buf(&sga->lgwr_head_buf, kernel->attr.lgwr_head_buf_size, &offset);
    server_set_sga_buf(&sga->large_buf, kernel->attr.large_pool_size, &offset);
    server_set_sga_buf(&sga->buf_iocbs, kernel->attr.buf_iocbs_size, &offset);

    uint64 start_offset = offset;
    server_set_sga_buf(&sga->temp_buf, kernel->attr.temp_buf_inst_size, &offset);
    CM_ASSERT(offset - start_offset == kernel->attr.temp_buf_inst_align_size);
    for (uint32 i = 1; i < kernel->temp_ctx_count; i++) {
        char *tmp_data_buf = NULL;
        server_set_sga_buf(&tmp_data_buf, kernel->attr.temp_buf_inst_size, &offset);
        CM_ASSERT(offset - start_offset == kernel->attr.temp_buf_inst_align_size * (i + 1));
    }
    server_set_sga_buf(&sga->index_buf, kernel->attr.index_buf_size, &offset);
}

static status_t server_init_sga_bufs(sga_t *sga)
{
    knl_instance_t *kernel = &g_instance->kernel;

    marea_attach("shared area", sga->shared_buf, (size_t)kernel->attr.shared_area_size, GS_SHARED_PAGE_SIZE,
        &sga->shared_area);

    marea_attach("variant memory area", sga->vma_buf, (size_t)kernel->attr.vma_size, GS_VMA_PAGE_SIZE, &sga->vma.marea);
    GS_RETURN_IFERR(marea_reset_page_buf(&sga->vma.marea, VMC_MAGIC));

    marea_attach("variant memory large area", sga->vma_large_buf, (size_t)kernel->attr.large_vma_size,
        GS_LARGE_VMA_PAGE_SIZE, &sga->vma.large_marea);
    GS_RETURN_IFERR(marea_reset_page_buf(&sga->vma.large_marea, VMC_MAGIC));

    pm_area_init("private memory area", sga->pma_buf, (size_t)kernel->attr.pma_size, &sga->pma);

    mpool_attach("large pool", sga->large_buf, (int64)kernel->attr.large_pool_size, GS_LARGE_PAGE_SIZE,
        &sga->large_pool);
    if (mem_pool_init(&sga->buddy_pool, "buddy pool", kernel->attr.buddy_init_size, kernel->attr.buddy_max_size) !=
        GS_SUCCESS) {
        return GS_ERROR;
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

    server_init_normal_vmem_pool(&g_vm_swapper);
    return GS_SUCCESS;
}

status_t server_create_sga(void)
{
    sga_t *sga = &g_instance->sga;

    server_calc_sga_size(sga);

    if (server_alloc_sga(sga) != GS_SUCCESS) {
        return GS_ERROR;
    }

    server_set_sga_bufs(sga);

    if (server_init_sga_bufs(sga) != GS_SUCCESS) {
        server_destroy_sga();
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

void server_destroy_sga()
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
