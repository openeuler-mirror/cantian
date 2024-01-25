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
 * cm_dbs_pgpool.c
 *
 *
 * IDENTIFICATION
 * src/common/cm_dbs_pgpool.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_dbs_module.h"
#include "cm_dbs_pgpool.h"
 
#include <stdint.h>
#include <fcntl.h>
#include <semaphore.h>
 
#include "cm_spinlock.h"
#include "cm_log.h"
#include "cm_error.h"
#include "cm_dbs_map.h"
#include "cm_dbs_ctrl.h"
#include "cm_dbs_intf.h"
#include "cm_dbstore.h"

#define DBS_DEFAULT_POOL_SIZE (1 << 20)
#define DBS_PAGE_POOL_PART_SIZE SIZE_M(64) // PagePool的Partition大小

int64 cm_dbs_pg_seek(int32 handle, int64 offset, int32 origin)
{
    if (origin != SEEK_END) {
        CT_LOG_RUN_ERR("Unsupported seek type(%d).", origin);
        return -1;
    }
    PagePoolAttr attr = { 0 };
    cm_dbs_map_item_s obj = { 0 };
    if (cm_dbs_map_get(handle, &obj) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to find page pool by index %d", handle);
        return -1;
    }
    int32 ret = strcpy_sp(attr.nsName, sizeof(attr.nsName), obj.ns_name);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to copy ns name");
        return CT_ERROR;
    }

    uint64_t capacity = 0;
    ret = dbs_global_handle()->get_pagepool_logic_capacity(&obj.obj_id, &attr, &capacity);
    if (ret != 0) {
        CT_LOG_RUN_ERR("Failed(%d) to get pagepool logic capacity.", ret);
        return -1;
    }
    return (int64)capacity;
}

status_t cm_dbs_pg_create(const char *name, int64 size, uint32 flags, int32 *handle)
{
    int32 ret;
    uint32 pageSize;
    uint64 pgPoolSize = (uint64)size;
    if (pgPoolSize == 0) {
        pgPoolSize = DBS_DEFAULT_POOL_SIZE;
    }
    cm_dbs_map_item_s obj = { 0 };
    PagePoolAttr attr = { 0 };
    cm_dbs_cfg_s *cfg = cm_dbs_get_cfg();
    if (flags == 0xFFFFFFFF) {
        pageSize = cfg->ctrlFilePgSize;
    } else {
        pageSize = cfg->dataFilePgSize;
    }
    attr.pagePoolPartNum = cfg->partition_num;
    attr.pageSize = pageSize;
    attr.initSize = pgPoolSize;
    char *nsName = NULL;
    ret = cm_dbs_get_ns_name(DEV_TYPE_PGPOOL, &nsName);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to get ns id");
        return CT_ERROR;
    }
    ret = strcpy_sp(attr.nsName, sizeof(attr.nsName), nsName);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to copy ns name");
        return CT_ERROR;
    }
    ret = dbs_global_handle()->create_pagepool((char *)name, &attr, &obj.obj_id);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to create page pool %s", name);
        return CT_ERROR;
    }
    ret = dbs_global_handle()->open_pagepool((char *)name, &attr, &obj.obj_id);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to open page pool %s", name);
        return CT_ERROR;
    }
    obj.pagepool.page_size = pageSize;
    obj.ns_name = nsName;
    ret = cm_dbs_map_set(name, &obj, handle);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to insert page pool to map");
        return CT_ERROR;
    }
    CT_LOG_DEBUG_INF("Create page pool %s, page size %u, pool size %llu success", name, pageSize, pgPoolSize);
    return CT_SUCCESS;
}

status_t cm_dbs_pg_destroy(const char *name)
{
    PagePoolAttr attr = { 0 };
    char *nsName = NULL;
    int32 ret = cm_dbs_get_ns_name(DEV_TYPE_PGPOOL, &nsName);
    if (ret != 0) {
        CT_LOG_RUN_ERR("Failed to get ns id");
        return CT_ERROR;
    }
    ret = strcpy_sp(attr.nsName, sizeof(attr.nsName), nsName);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to copy ns name");
        return CT_ERROR;
    }
    ret = dbs_global_handle()->destroy_pagepool((char *)name, &attr);
    if (ret != 0) {
        CT_LOG_RUN_ERR("Failed to detroy page pool");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cm_dbs_pg_open(const char *name, int32 *handle)
{
    int32 ret;
    cm_dbs_map_item_s obj = { 0 };
    PagePoolAttr attr = { 0 };

    char *nsName = NULL;
    ret = cm_dbs_get_ns_name(DEV_TYPE_PGPOOL, &nsName);
    if (ret == CT_ERROR) {
        CT_LOG_DEBUG_ERR("Failed to Get ns id");
        return CT_ERROR;
    }
    ret = strcpy_sp(attr.nsName, sizeof(attr.nsName), nsName);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to copy ns name");
        return CT_ERROR;
    }
    ret = dbs_global_handle()->open_pagepool((char *)name, &attr, &obj.obj_id);
    if (ret != 0) {
        CT_LOG_DEBUG_ERR("Failed to open page pool name=%s", name);
        return CT_ERROR;
    }
    obj.pagepool.page_size = attr.pageSize;
    obj.ns_name = nsName;
    status_t stat = cm_dbs_map_set(name, &obj, handle);
    if (stat != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to insert page pool to map");
        return CT_ERROR;
    }
    CT_LOG_DEBUG_INF("Open page pool(%s, %u) at handle(%d) successfully.", name, attr.pageSize, *handle);
    return CT_SUCCESS;
}

void cm_dbs_pg_close(int32 handle)
{
    cm_dbs_map_item_s obj = { 0 };

    if (handle == -1) {
        return;
    }

    status_t stat = cm_dbs_map_get(handle, &obj);
    if (stat != CT_SUCCESS) {
        CT_LOG_RUN_WAR("Failed to get pagepool object from cache by handle(%d).", handle);
        return;
    }
    cm_dbs_map_remove(handle);
    int32 ret = dbs_global_handle()->close_pagepool(&obj.obj_id);
    if (ret != 0) {
        CT_LOG_RUN_WAR("Failed(%d) to close pagepool from dbstor.", ret);
        return;
    }
    CT_LOG_DEBUG_INF("Close pagepool at handle(%d) successfully.", handle);
}

static void cm_dbs_pg_init_opt(DbsPageOption *pgOpt, int32 pageSize, uint32_t opcode)
{
    pgOpt->priority = 0;
    pgOpt->opcode = opcode;
    pgOpt->offset = 0;
    pgOpt->length = pageSize;
    pgOpt->lsn = 1;
    pgOpt->callBack.cb = NULL;
    pgOpt->callBack.ctx = NULL;
    (void)memset_s(&pgOpt->session, sizeof(SessionId), 0, sizeof(SessionId));
    return;
}

status_t cm_dbs_pg_read(int32 handle, int64 offset, void *buf, int32 size, int32 *read_size)
{
    int32 ret;
    int32 pageSize;
    cm_dbs_map_item_s obj = { 0 };
    DbsPageOption pgOpt;
    PageValue pgValue;
    DbsPageId startPageId;
    uint32_t num;

    if (cm_dbs_map_get(handle, &obj) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to find page pool by index %d", handle);
        return CT_ERROR;
    }

    pageSize = obj.pagepool.page_size;
    if ((offset % pageSize) != 0 || (size % pageSize) != 0) {
        CT_LOG_RUN_ERR("Param is exception, offset %llu size %u", offset, size);
        return CT_ERROR;
    }
    pgValue.buf.len = size;
    pgValue.type = DBS_DATA_FORMAT_BUFFER;
    cm_dbs_pg_init_opt(&pgOpt, pageSize, CS_PAGE_POOL_READ);
    startPageId = offset / pageSize;
    num = (size + pageSize - 1) / pageSize;
    pgValue.buf.buf = (char *)buf;
    
    ret = dbs_global_handle()->dbs_mget_page(&obj.obj_id, startPageId, num, &pgOpt, &pgValue);
    if (ret != 0) {
        char name[CSS_MAX_NAME_LEN + 1];
        cm_dbs_map_get_name(handle, name, sizeof(name));
        CT_LOG_RUN_ERR("Read page %s fail, offset:0x%llx", name, offset);
        return CT_ERROR;
    }

    *read_size = size;
    return CT_SUCCESS;
}

void cm_dbs_print_err_info(int32 handle, uint32_t opcode, int64 offset, DbsPageId pgId, int32 size, int32 ret)
{
    char name[CSS_MAX_NAME_LEN + 1] = { 0 };
    cm_dbs_map_get_name(handle, name, sizeof(name));
    if (opcode == CS_PAGE_POOL_WRITE) {
        CT_LOG_RUN_ERR("Mput page %s fail, offset:0x%llx, pgId %lu, size %d, ret %d", name, offset, pgId, size, ret);
    } else {
        CT_LOG_RUN_ERR("Write page %s fail, offset:0x%llx, pgId %lu, size %d, ret %d", name, offset, pgId, size, ret);
    }
}

static status_t cm_dbs_pg_comm_write(int32 handle, int64 offset, const void *buf, int32 size, uint32_t opcode,
                                     uint32 *partid)
{
    int32 ret;
    uint32 pageSize;
    cm_dbs_map_item_s obj = { 0 };
    DbsPageOption pgOpt;
    PageValue pgValue;
    DbsPageId pgId;
    int32 x = 0;

    if (cm_dbs_map_get(handle, &obj) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to find page pool by index %d", handle);
        return CT_ERROR;
    }

    if (obj.pagepool.page_size == 0) {
        CT_LOG_RUN_ERR("Page size is invalid, page pool by index %d", handle);
        return CT_ERROR;
    }
    pageSize = obj.pagepool.page_size;

    if (((offset % pageSize) != 0) || ((size % pageSize) != 0)) {
        CT_LOG_RUN_ERR("Offset %lld or size %d is invalid, page pool by index %d", offset, size, handle);
        return CT_ERROR;
    }

    pgValue.type = DBS_DATA_FORMAT_BUFFER;
    if (opcode == CS_PAGE_POOL_WRITE) {
        pgValue.buf.len = size;
        pgValue.buf.buf = (char *)buf;
        cm_dbs_pg_init_opt(&pgOpt, size, opcode);
        pgId = offset / pageSize;
        ret = dbs_global_handle()->dbs_mput_continue_pages(&obj.obj_id, pgId, (size / pageSize), &pgOpt, &pgValue);
    } else if (opcode == CS_PAGE_POOL_ASYNC_WRITE) {
        pgValue.buf.len = pageSize;
        cm_dbs_pg_init_opt(&pgOpt, pageSize, opcode);

        for (x = 0; x < size; x += pageSize) {
            pgId = (offset + x) / pageSize;
            pgValue.buf.buf = (char *)buf + x;

            ret = dbs_global_handle()->dbs_put_page_async(&obj.obj_id, pgId, &pgOpt, &pgValue, *partid);
            if (ret != 0) {
                break;
            }
        }
    } else {
        CT_LOG_RUN_ERR("Opcode %u is invalid", opcode);
        return CT_ERROR;
    }

    if (ret != 0) {
        cm_dbs_print_err_info(handle, opcode, offset, ((offset + x) / pageSize), size, ret);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cm_dbs_pg_cal_part_id(uint64 pgid, uint32 pageSize, uint32 *partid)
{
    cm_dbs_cfg_s *cfg = cm_dbs_get_cfg();
    if (cfg->partition_num <= 0) {
        CT_LOG_RUN_ERR("The part capacity(%u) should not smaller than 1.", cfg->partition_num);
        return CT_ERROR;
    }
    *partid = ((pgid * pageSize) / DBS_PAGE_POOL_PART_SIZE) % cfg->partition_num;
    return CT_SUCCESS;
}

status_t cm_dbs_pg_write(int32 handle, int64 offset, const void *buf, int32 size)
{
    return cm_dbs_pg_comm_write(handle, offset, buf, size, CS_PAGE_POOL_WRITE, NULL);
}

status_t cm_dbs_pg_asyn_write(int32 handle, int64 offset, const void *buf, int32 size, uint32 partid)
{
    return cm_dbs_pg_comm_write(handle, offset, buf, size, CS_PAGE_POOL_ASYNC_WRITE, &partid);
}

status_t cm_dbs_sync_page(int32 handle, uint32 partid)
{
    cm_dbs_map_item_s obj = { 0 };
    if (cm_dbs_map_get(handle, &obj) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to find pgpool obj by handle(%d).", handle);
        return CT_ERROR;
    }
 
    int32 ret = dbs_global_handle()->sync_page_by_part_index(&obj.obj_id, partid);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed(%d) to sync page, partid %u.", ret, partid);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cm_dbs_pg_extend(int32 handle, int64 offset, int64 size)
{
    cm_dbs_map_item_s obj = { 0 };
    if (cm_dbs_map_get(handle, &obj) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to find pgpool obj by handle(%d).", handle);
        return CT_ERROR;
    }
    PagePoolAttr attr = { 0 };
    int32 ret = strcpy_sp(attr.nsName, sizeof(attr.nsName), obj.ns_name);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to copy ns name");
        return CT_ERROR;
    }
    ret = dbs_global_handle()->expand_pagepool_logic_capacity(&obj.obj_id, &attr, (uint64)offset, (uint64)size);
    if (ret != 0) {
        CT_LOG_RUN_ERR("Failed(%d) to extend pgpool(%lld) size(%lld).", ret, offset, size);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cm_dbs_pg_truncate(int32 handle, int64 keep_size)
{
    if (keep_size < 0) {
        CT_LOG_RUN_ERR("Failed to truncate pagepool because of invalid size(%lld).", keep_size);
        return CT_ERROR;
    }
    cm_dbs_map_item_s obj = { 0 };
    if (cm_dbs_map_get(handle, &obj) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to find pgpool obj by handle(%d).", handle);
        return CT_ERROR;
    }
    PagePoolAttr attr = { 0 };
    
    int32 ret = strcpy_sp(attr.nsName, sizeof(attr.nsName), obj.ns_name);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to copy ns name");
        return CT_ERROR;
    }
    uint64_t capacity = 0;
    ret = dbs_global_handle()->get_pagepool_logic_capacity(&obj.obj_id, &attr, &capacity);
    if (ret != 0) {
        CT_LOG_RUN_ERR("Failed(%d) to get pagepool logic capacity.", ret);
        return CT_ERROR;
    }
    uint64_t new_size = (uint64_t)keep_size;
    if (capacity == new_size) {
        return CT_SUCCESS;
    }
    if (capacity < new_size) {
        ret = dbs_global_handle()->expand_pagepool_logic_capacity(&obj.obj_id, &attr, capacity, new_size - capacity);
    } else {
        ret = dbs_global_handle()->expand_pagepool_logic_capacity(&obj.obj_id, &attr, new_size, 0);
    }
    if (ret != 0) {
        CT_LOG_RUN_ERR("Failed(%d) to truncate PagePool size from %lu to %lu.", ret, capacity, new_size);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cm_dbs_pg_rename(const char *src_name, const char *dst_name)
{
    if (src_name == NULL || strlen(src_name) == 0) {
        CT_LOG_RUN_ERR("The src name is invalid.");
        return CT_ERROR;
    }
    if (dst_name == NULL || strlen(dst_name) == 0) {
        CT_LOG_RUN_ERR("The dst name is invalid.");
        return CT_ERROR;
    }
    if (strcmp(src_name, dst_name) == 0) {
        CT_LOG_RUN_WAR("The dst name is same as the src(%s).", src_name);
        return CT_SUCCESS;
    }
    PagePoolAttr attr = { 0 };
    char *nsName = NULL;
    if (cm_dbs_get_ns_name(DEV_TYPE_PGPOOL, &nsName) != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to get namespace id for pagepool.");
        return CT_ERROR;
    }
    int32_t ret = strcpy_sp(attr.nsName, sizeof(attr.nsName), nsName);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to copy ns name");
        return CT_ERROR;
    }

    /* call the interface of DBStor to rename the pagepool */
    ret = dbs_global_handle()->rename_pagepool((char *)src_name, (char *)dst_name, &attr);
    if (ret != 0) {
        CT_LOG_RUN_ERR("Failed(%d) to rename pagepool from %s to %s.", ret, src_name, dst_name);
        return CT_ERROR;
    }
    CT_LOG_DEBUG_INF("Rename pagepool from %s to %s successfully.", src_name, dst_name);
    return CT_SUCCESS;
}

bool32 cm_dbs_pg_exist(const char *name)
{
    PagePoolAttr attr = { 0 };
    char *nsName = NULL;
    int32 ret = cm_dbs_get_ns_name(DEV_TYPE_PGPOOL, &nsName);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed(%d) to get namespace id for pagepool.", ret);
        return CT_FALSE;
    }
    ret = strcpy_sp(attr.nsName, sizeof(attr.nsName), nsName);
    if (ret != CT_SUCCESS) {
        CT_LOG_RUN_ERR("Failed to copy ns name");
        return CT_ERROR;
    }
    PagePoolId id = { 0 };
    ret = dbs_global_handle()->open_pagepool((char *)name, &attr, &id);
    if (ret == -ENOENT) {
        CT_LOG_DEBUG_INF("The pagepool(%s) does not exist.", name);
        return CT_FALSE;
    } else if (ret != 0) {
        CT_LOG_RUN_ERR("Failed(%d) to open pagepool(%s)", ret, name);
        return CT_FALSE;
    }
    (void)dbs_global_handle()->close_pagepool(&id);
    CT_LOG_DEBUG_INF("The pagepool named %s exists.", name);
    return CT_TRUE;
}
