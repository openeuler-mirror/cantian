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
 * cms_gcc_imp.c
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_gcc_imp.c
 *
 * -------------------------------------------------------------------------
 */
#include "cms_defs.h"
#include "cm_file.h"
#include "cms_gcc.h"
#include "cm_malloc.h"
#include "cm_disk.h"
#include "cm_ip.h"
#include "cms_disk_lock.h"
#include "cms_log.h"

#define GCC_IMP_OBJ_MAGIC_LEN               10

status_t cms_text2int32(const text_t* text_src, int32* value)
{
    if (cm_text2int(text_src, value) != GS_SUCCESS) {
        int err_code = cm_get_error_code();
        if (err_code == ERR_SQL_SYNTAX_ERROR) {
            cm_reset_error();
            GS_THROW_ERROR(ERR_CMS_CONVERT_VALUE, T2S(text_src), "unsigned int");
        }
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t cms_text2uint32(const text_t* text_src, uint32* value)
{
    if (cm_text2uint32(text_src, value) != GS_SUCCESS) {
        int err_code = cm_get_error_code();
        if (err_code == ERR_SQL_SYNTAX_ERROR) {
            cm_reset_error();
            GS_THROW_ERROR(ERR_CMS_CONVERT_VALUE, T2S(text_src), "unsigned int");
        }
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static inline bool32 cms_check_import_attr_names_valid(const char *head, uint32 head_len)
{
    for (uint32 i = 0; i < head_len; i++) {
        if (head[i] != '_' && (head[i] < 'A' || head[i] > 'Z')) {
            return GS_FALSE;
        }
    }

    return GS_TRUE;
}

static status_t cms_import_parse_attr_names(text_t *line, text_t *attr_names, uint32 max_count, uint32 *count)
{
    text_t temp;
    uint32 i = 0;

    while (cm_fetch_text(line, ',', '\0', &temp)) {
        cm_trim_text(&temp);
        if (temp.len == 0) {
            GS_THROW_ERROR(ERR_CMS_GCC_IMPORT, "one attribute name is empty");
            return GS_ERROR;
        }

        if (!cms_check_import_attr_names_valid(temp.str, temp.len)) {
            GS_THROW_ERROR(ERR_CMS_GCC_IMPORT, "one attribute name is invalid or empty");
            return GS_ERROR;
        }
        attr_names[i].str = temp.str;
        attr_names[i].len = temp.len;
        if (line->str != NULL) {
            i++;
        }
        if (i >= max_count) {
            GS_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "too many attribute names (maximum: %u)", max_count);
            return GS_ERROR;
        }
    }
    *count = i + 1;

    return GS_SUCCESS;
}

static status_t cms_import_head_attrs(cms_gcc_t *gcc, cms_gcc_head_t *head)
{
    cms_gcc_head_t *gcc_head = &gcc->head;

    gcc_head->magic = CMS_GCC_HEAD_MAGIC;
    gcc_head->cheksum = head->cheksum;

    const cms_gcc_t* current_gcc = cms_get_read_gcc();
    gcc_head->meta_ver = current_gcc->head.meta_ver;
    cms_release_gcc(&current_gcc);

    gcc_head->data_ver = head->data_ver;
    gcc_head->node_count = head->node_count;

    return GS_SUCCESS;
}

static inline status_t cms_import_parse_head_attr(cms_gcc_head_t *gcc_head, text_t *attr_head, text_t *attr_text)
{
    if (gcc_head->meta_ver == 0 && cm_compare_text_str(attr_head, "META_VER") == 0) {
        GS_RETURN_IFERR(cms_text2uint32(attr_text, &gcc_head->meta_ver));
    } else if (gcc_head->node_count == 0 && cm_compare_text_str(attr_head, "NODE_COUNT") == 0) {
        if (attr_text->len == 0) {
            GS_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "%s cannot be empty", T2S(attr_head));
            return GS_ERROR;
        }
        GS_RETURN_IFERR(cms_text2uint32(attr_text, &gcc_head->node_count));
        if (gcc_head->node_count > CMS_MAX_NODE_COUNT) {
            GS_THROW_ERROR(ERR_CMS_NUM_EXCEED, "NODE_COUNT", (uint32)CMS_MAX_NODE_COUNT);
            return GS_ERROR;
        }
    } else if (gcc_head->data_ver == 0 && cm_compare_text_str(attr_head, "DATA_VER") == 0) {
        if (attr_text->len == 0) {
            GS_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "%s cannot be empty", T2S(attr_head));
            return GS_ERROR;
        }
        GS_RETURN_IFERR(cms_text2uint32(attr_text, &gcc_head->data_ver));
    } else if (gcc_head->cheksum == 0 && cm_compare_text_str(attr_head, "CHECKSUM") == 0) {
        GS_RETURN_IFERR(cms_text2uint32(attr_text, &gcc_head->cheksum));
    } else {
        GS_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "'%s' is an invalid attribute name", T2S(attr_head));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t cms_import_parse_head(cms_gcc_t *gcc, text_t *text, text_t *line, source_location_t *loc)
{
    text_t temp;
    text_t attr_names[CMS_IMP_NODE_ATTR_NUM] = { { NULL, 0 } };
    cms_gcc_head_t gcc_head;
    uint32 imp_attr_count;
    errno_t ret;

    if (cms_import_parse_attr_names(line, attr_names, (uint32)CMS_IMP_HEAD_ATTR_NUM, &imp_attr_count) != GS_SUCCESS) {
        cm_set_error_loc(*loc);
        return GS_ERROR;
    }

    while (cm_fetch_line(text, line, GS_TRUE)) {
        cm_ltrim_text(line);
        (loc->line)++;
        if (line->len == 0) {
            continue;
        }
        if (line->str[0] == '#') {
            break;
        }

        ret = memset_sp(&gcc_head, sizeof(cms_gcc_head_t), 0, sizeof(cms_gcc_head_t));
        MEMS_RETURN_IFERR(ret);

        uint32 comma_num = 0;
        while (cm_fetch_text(line, ',', '\0', &temp)) {
            cm_trim_text(&temp);
            if (cms_import_parse_head_attr(&gcc_head, &attr_names[comma_num], &temp) != GS_SUCCESS) {
                cm_set_error_loc(*loc);
                return GS_ERROR;
            }
            if (line->str != NULL) {
                comma_num++;
            }

            if (comma_num > imp_attr_count - 1) {
                break;
            }
        }
        if (comma_num != imp_attr_count - 1) {
            GS_SRC_THROW_ERROR(*loc, ERR_CMS_GCC_IMPORT, "the number of attributes and attribute names does not match");
            return GS_ERROR;
        }

        if (cms_import_head_attrs(gcc, &gcc_head) != GS_SUCCESS) {
            cm_set_error_loc(*loc);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static inline status_t cms_check_import_node_valid(cms_node_def_t *node_def)
{
    if (node_def->node_id >= CMS_MAX_NODE_COUNT) {
        GS_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "NODE_ID must be less than %u", (uint32)CMS_MAX_NODE_COUNT);
        return GS_ERROR;
    }

    if (!cms_check_name_valid(node_def->name, (uint32)strlen(node_def->name))) {
        GS_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "node name");
        return GS_ERROR;
    }

    if (!cm_check_ip_valid(node_def->ip)) {
        GS_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "node ip");
        return GS_ERROR;
    }

    if (node_def->port == 0 || node_def->port > GS_MAX_UINT16) {
        GS_THROW_ERROR(ERR_CMS_PORT_OUT_RANGE, 1, GS_MAX_UINT16);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t cms_import_node_attrs(cms_gcc_t *gcc, cms_node_def_t *node_def)
{
    cms_node_def_t *gcc_node = NULL;
    errno_t ret;

    if (node_def->node_id >= gcc->head.node_count) {
        GS_THROW_ERROR(ERR_CMS_GCC_IMPORT, "node id must be less than node count in gcc head");
        return GS_ERROR;
    }

    GS_RETURN_IFERR(cms_check_import_node_valid(node_def));

    gcc_node = &gcc->node_def[node_def->node_id];
    if (gcc_node->magic == CMS_GCC_NODE_MAGIC) {
        GS_THROW_ERROR_EX(ERR_CMS_OBJECT_EXISTS, "node_id '%u'", node_def->node_id);
        return GS_ERROR;
    }

    GS_RETURN_IFERR(cms_check_node_exists(gcc, node_def->name, node_def->ip, node_def->port));

    gcc_node->magic = CMS_GCC_NODE_MAGIC;
    gcc_node->node_id = node_def->node_id;
    ret = strncpy_sp(gcc_node->name, CMS_NAME_BUFFER_SIZE, node_def->name, strlen(node_def->name));
    MEMS_RETURN_IFERR(ret);

    ret = strncpy_sp(gcc_node->ip, CMS_IP_BUFFER_SIZE, node_def->ip, strlen(node_def->ip));
    MEMS_RETURN_IFERR(ret);

    gcc_node->port = node_def->port;
    gcc->head.node_count = MAX(node_def->node_id + 1, gcc->head.node_count);

    return GS_SUCCESS;
}

static inline status_t cms_import_parse_node_attr(cms_node_def_t *node_def, text_t *attr_head, text_t *attr_text)
{
    errno_t ret;

    if (attr_text->len == 0) {
        GS_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "%s cannot be empty", T2S(attr_head));
        return GS_ERROR;
    }

    if (node_def->node_id == 0 && cm_compare_text_str(attr_head, "NODE_ID") == 0) {
        GS_RETURN_IFERR(cms_text2uint32(attr_text, &node_def->node_id));
    } else if (*node_def->name == 0 && cm_compare_text_str(attr_head, "NAME") == 0) {
        if (attr_text->len > CMS_MAX_NAME_LEN) {
            GS_THROW_ERROR(ERR_NAME_TOO_LONG, "node", attr_text->len, CMS_MAX_NAME_LEN);
            return GS_ERROR;
        }
        ret = strncpy_sp(node_def->name, attr_text->len + 1, attr_text->str, attr_text->len);
        MEMS_RETURN_IFERR(ret);
    } else if (*node_def->ip == 0 && cm_compare_text_str(attr_head, "IP") == 0) {
        if (attr_text->len > CMS_MAX_IP_LEN) {
            GS_THROW_ERROR(ERR_INVALID_IPADDRESS_LENGTH, attr_text->len);
            return GS_ERROR;
        }
        ret = strncpy_sp(node_def->ip, attr_text->len + 1, attr_text->str, attr_text->len);
        MEMS_RETURN_IFERR(ret);
    } else if (node_def->port == 0 && cm_compare_text_str(attr_head, "PORT") == 0) {
        GS_RETURN_IFERR(cms_text2uint32(attr_text, &node_def->port));
    } else {
        GS_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "'%s' is an invalid attribute name", T2S(attr_head));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t cms_import_parse_node(cms_gcc_t *gcc, text_t *text, text_t *line, source_location_t *loc)
{
    text_t temp;
    text_t attr_names[CMS_IMP_NODE_ATTR_NUM] = { { NULL, 0 } };
    cms_node_def_t node_def;
    uint32 imp_attr_count;
    errno_t ret;

    if (cms_import_parse_attr_names(line, attr_names, (uint32)CMS_IMP_NODE_ATTR_NUM, &imp_attr_count) != GS_SUCCESS) {
        cm_set_error_loc(*loc);
        return GS_ERROR;
    }

    while (cm_fetch_line(text, line, GS_TRUE)) {
        cm_ltrim_text(line);
        (loc->line)++;
        if (line->len == 0) {
            continue;
        }
        if (line->str[0] == '#') {
            break;
        }

        ret = memset_sp(&node_def, sizeof(cms_node_def_t), 0, sizeof(cms_node_def_t));
        MEMS_RETURN_IFERR(ret);

        uint32 comma_num = 0;
        while (cm_fetch_text(line, ',', '\0', &temp)) {
            cm_trim_text(&temp);
            if (cms_import_parse_node_attr(&node_def, &attr_names[comma_num], &temp) != GS_SUCCESS) {
                cm_set_error_loc(*loc);
                return GS_ERROR;
            }
            if (line->str != NULL) {
                comma_num++;
            }

            if (comma_num > imp_attr_count - 1) {
                break;
            }
        }
        if (comma_num != imp_attr_count - 1) {
            GS_SRC_THROW_ERROR(*loc, ERR_CMS_GCC_IMPORT, "the number of attributes and attribute names does not match");
            return GS_ERROR;
        }

        if (cms_import_node_attrs(gcc, &node_def) != GS_SUCCESS) {
            cm_set_error_loc(*loc);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t cms_import_votedisk_attrs(cms_gcc_t *gcc, cms_votedisk_t *votedisk)
{
    uint32 disk_id;
    cms_votedisk_t* gcc_votedisk = NULL;
    errno_t ret;

    GS_RETURN_IFERR(cms_check_votedisk(votedisk->path));

    for (disk_id = 0; disk_id < CMS_MAX_VOTEDISK_COUNT; disk_id++) {
        if (gcc->votedisks[disk_id].magic == CMS_GCC_VOTEDISK_MAGIC &&
            cm_compare_str(gcc->votedisks[disk_id].path, votedisk->path) == 0) {
            GS_THROW_ERROR(ERR_CMS_OBJECT_EXISTS, "the votedisk");
            return GS_ERROR;
        }
    }

    for (disk_id = 0; disk_id < CMS_MAX_VOTEDISK_COUNT; disk_id++) {
        if (gcc->votedisks[disk_id].magic != CMS_GCC_VOTEDISK_MAGIC) {
            gcc_votedisk = &gcc->votedisks[disk_id];
            break;
        }
    }

    if (disk_id == CMS_MAX_VOTEDISK_COUNT || gcc_votedisk == NULL) {
        GS_THROW_ERROR(ERR_CMS_NUM_EXCEED, "votedisk");
        return GS_ERROR;
    }

    gcc_votedisk->magic = CMS_GCC_VOTEDISK_MAGIC;
    ret = strncpy_sp(gcc_votedisk->path, CMS_FILE_NAME_BUFFER_SIZE, votedisk->path, strlen(votedisk->path));
    MEMS_RETURN_IFERR(ret);

    return GS_SUCCESS;
}

static inline status_t cms_import_parse_votedisk_attr(cms_votedisk_t *votedisk, text_t *attr_head, text_t *attr_text)
{
    errno_t ret;

    if (attr_text->len == 0) {
        GS_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "%s cannot be empty", T2S(attr_head));
        return GS_ERROR;
    }

    if (*votedisk->path == 0 && cm_compare_text_str(attr_head, "PATH") == 0) {
        if (attr_text->len > CMS_MAX_FILE_NAME_LEN) {
            GS_THROW_ERROR(ERR_FILE_PATH_TOO_LONG, CMS_MAX_FILE_NAME_LEN);
            return GS_ERROR;
        }
        if (!cms_check_path_valid(attr_text->str, attr_text->len)) {
            GS_THROW_ERROR(ERR_CMS_INVALID_PATH, "votedisk");
            return GS_ERROR;
        }
        ret = strncpy_sp(votedisk->path, attr_text->len + 1, attr_text->str, attr_text->len);
        MEMS_RETURN_IFERR(ret);
    } else {
        GS_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "'%s' is an invalid attribute name", T2S(attr_head));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t cms_import_parse_votedisk(cms_gcc_t *gcc, text_t *text, text_t *line, source_location_t *loc)
{
    text_t temp;
    text_t attr_names[CMS_IMP_VOIEDISK_ATTR_NUM] = { { NULL, 0 } };
    cms_votedisk_t votedisk;
    uint32 imp_attr_count;
    errno_t ret;

    if (cms_import_parse_attr_names(line, attr_names, (uint32)CMS_IMP_VOIEDISK_ATTR_NUM, &imp_attr_count) != GS_SUCCESS) {
        cm_set_error_loc(*loc);
        return GS_ERROR;
    }

    while (cm_fetch_line(text, line, GS_TRUE)) {
        cm_ltrim_text(line);
        (loc->line)++;
        if (line->len == 0) {
            continue;
        }
        if (line->str[0] == '#') {
            break;
        }
        ret = memset_sp(&votedisk, sizeof(cms_votedisk_t), 0, sizeof(cms_votedisk_t));
        MEMS_RETURN_IFERR(ret);

        uint32 comma_num = 0;
        while (cm_fetch_text(line, ',', '\0', &temp)) {
            cm_trim_text(&temp);
            if (cms_import_parse_votedisk_attr(&votedisk, &attr_names[comma_num], &temp) != GS_SUCCESS) {
                cm_set_error_loc(*loc);
                return GS_ERROR;
            }
            if (line->str != NULL) {
                comma_num++;
            }

            if (comma_num > imp_attr_count - 1) {
                break;
            }
        }
        if (comma_num != imp_attr_count - 1) {
            GS_SRC_THROW_ERROR(*loc, ERR_CMS_GCC_IMPORT, "the number of attributes and attribute names does not match");
            return GS_ERROR;
        }

        if (cms_import_votedisk_attrs(gcc, &votedisk) != GS_SUCCESS) {
            cm_set_error_loc(*loc);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t cms_import_resgrp_attrs(cms_gcc_t *gcc, cms_resgrp_t *resgrp)
{
    uint32 grp_id;
    cms_resgrp_t* gcc_resgrp = NULL;
    errno_t ret;

    if (resgrp->grp_id >= CMS_MAX_RESOURCE_GRP_COUNT) {
        GS_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "GROUP_ID must be less than %u", (uint32)CMS_MAX_RESOURCE_GRP_COUNT);
        return GS_ERROR;
    }
    if (!cms_check_name_valid(resgrp->name, (uint32)strlen(resgrp->name))) {
        GS_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "resource group name");
        return GS_ERROR;
    }

    for (grp_id = 0; grp_id < CMS_MAX_RESOURCE_GRP_COUNT; grp_id++) {
        if (gcc->resgrp[grp_id].magic == CMS_GCC_RES_GRP_MAGIC &&
            cm_compare_str(gcc->resgrp[grp_id].name, resgrp->name) == 0) {
            GS_THROW_ERROR(ERR_CMS_OBJECT_EXISTS, "the resource group");
            return GS_ERROR;
        }
    }

    gcc_resgrp = &gcc->resgrp[resgrp->grp_id];

    if (gcc_resgrp->magic == CMS_GCC_RES_GRP_MAGIC) {
        GS_THROW_ERROR(ERR_CMS_OBJECT_EXISTS, "the resource group id");
        return GS_ERROR;
    }

    gcc_resgrp->magic = CMS_GCC_RES_GRP_MAGIC;
    gcc_resgrp->grp_id = resgrp->grp_id;
    ret = strncpy_sp(gcc_resgrp->name, CMS_NAME_BUFFER_SIZE, resgrp->name, strlen(resgrp->name));
    MEMS_RETURN_IFERR(ret);

    return GS_SUCCESS;
}

static inline status_t cms_import_parse_resgrp_attr(cms_resgrp_t *resgrp, text_t *attr_head, text_t *attr_text)
{
    errno_t ret;

    if (attr_text->len == 0) {
        GS_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "%s cannot be empty", T2S(attr_head));
        return GS_ERROR;
    }

    if (resgrp->grp_id == 0 && cm_compare_text_str(attr_head, "GROUP_ID") == 0) {
        GS_RETURN_IFERR(cms_text2uint32(attr_text, &resgrp->grp_id));
    } else if (*resgrp->name == 0 && cm_compare_text_str(attr_head, "NAME") == 0) {
        if (attr_text->len > CMS_MAX_NAME_LEN) {
            GS_THROW_ERROR(ERR_NAME_TOO_LONG, "resource group", attr_text->len, CMS_MAX_NAME_LEN);
            return GS_ERROR;
        }
        ret = strncpy_sp(resgrp->name, attr_text->len + 1, attr_text->str, attr_text->len);
        MEMS_RETURN_IFERR(ret);
    } else {
        GS_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "'%s' is an invalid attribute name", T2S(attr_head));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t cms_import_parse_resgrp(cms_gcc_t *gcc, text_t *text, text_t *line, source_location_t *loc)
{
    text_t temp;
    text_t attr_names[CMS_IMP_RES_GRP_ATTR_NUM] = { { NULL, 0 } };
    cms_resgrp_t resgrp;
    uint32 imp_attr_count;
    errno_t ret;

    if (cms_import_parse_attr_names(line, attr_names, (uint32)CMS_IMP_RES_GRP_ATTR_NUM, &imp_attr_count) != GS_SUCCESS) {
        cm_set_error_loc(*loc);
        return GS_ERROR;
    }

    while (cm_fetch_line(text, line, GS_TRUE)) {
        cm_ltrim_text(line);
        (loc->line)++;
        if (line->len == 0) {
            continue;
        }
        if (line->str[0] == '#') {
            break;
        }

        ret = memset_sp(&resgrp, sizeof(cms_resgrp_t), 0, sizeof(cms_resgrp_t));
        MEMS_RETURN_IFERR(ret);

        uint32 comma_num = 0;
        while (cm_fetch_text(line, ',', '\0', &temp)) {
            cm_trim_text(&temp);
            if (cms_import_parse_resgrp_attr(&resgrp, &attr_names[comma_num], &temp) != GS_SUCCESS) {
                cm_set_error_loc(*loc);
                return GS_ERROR;
            }
            if (line->str != NULL) {
                comma_num++;
            }

            if (comma_num > imp_attr_count - 1) {
                break;
            }
        }
        if (comma_num != imp_attr_count - 1) {
            GS_SRC_THROW_ERROR(*loc, ERR_CMS_GCC_IMPORT, "the number of attributes and attribute names does not match");
            return GS_ERROR;
        }

        if (resgrp.grp_id == 0) {
            if (cm_strcmpni(resgrp.name, "default", strlen(resgrp.name)) == 0) {
                continue;
            } else {
                GS_SRC_THROW_ERROR(*loc, ERR_CMS_GCC_IMPORT, "group 0 must be default");
                return GS_ERROR;
            }
        }
        if (cms_import_resgrp_attrs(gcc, &resgrp) != GS_SUCCESS) {
            cm_set_error_loc(*loc);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static inline status_t cms_check_import_res_valid(cms_res_t *res)
{
    if (res->res_id >= CMS_MAX_RESOURCE_COUNT) {
        GS_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "RES_ID must be less than %u", (uint32)CMS_MAX_RESOURCE_COUNT);
        return GS_ERROR;
    }

    if (res->grp_id >= CMS_MAX_RESOURCE_GRP_COUNT) {
        GS_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "GROUP_ID must be less than %u", (uint32)CMS_MAX_RESOURCE_GRP_COUNT);
        return GS_ERROR;
    }

    if (!cms_check_name_valid(res->name, (uint32)strlen(res->name))) {
        GS_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "resource name");
        return GS_ERROR;
    }

    if (!cms_check_name_valid(res->type, (uint32)strlen(res->type))) {
        GS_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "resource type");
        return GS_ERROR;
    }

    if (!cms_check_path_valid(res->script, (uint32)strlen(res->script))) {
        GS_THROW_ERROR(ERR_CMS_INVALID_PATH, "resource script");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t cms_import_res_attrs(cms_gcc_t *gcc, cms_res_t *res)
{
    uint32 res_id;
    cms_res_t* gcc_res = NULL;
    errno_t ret;

    GS_RETURN_IFERR(cms_check_import_res_valid(res));
    if (gcc->resgrp[res->grp_id].magic != CMS_GCC_RES_GRP_MAGIC) {
        GS_THROW_ERROR_EX(ERR_CMS_OBJECT_NOT_FOUND, "the resource group id '%u'", res->grp_id);
        return GS_ERROR;
    }

    for (res_id = 0; res_id < CMS_MAX_RESOURCE_COUNT; res_id++) {
        if (gcc->res[res_id].magic == CMS_GCC_RES_MAGIC &&
            cm_compare_str(gcc->res[res_id].name, res->name) == 0) {
            GS_THROW_ERROR_EX(ERR_CMS_OBJECT_EXISTS, "the resource '%s'", res->name);
            return GS_ERROR;
        }
        if (gcc->res[res_id].magic == CMS_GCC_RES_MAGIC && res->grp_id == gcc->res[res_id].grp_id &&
            cm_compare_str(gcc->res[res_id].type, res->type) == 0) {
            GS_THROW_ERROR(ERR_CMS_SAME_RESOURCE_TYPE, gcc->resgrp[res->grp_id].name);
            return GS_ERROR;
        }
    }
    gcc_res = &gcc->res[res->res_id];

    if (gcc_res->magic == CMS_GCC_RES_MAGIC) {
        GS_THROW_ERROR_EX(ERR_CMS_OBJECT_EXISTS, "the resource %u ", res->res_id);
        return GS_ERROR;
    }

    gcc_res->magic = CMS_GCC_RES_MAGIC;
    gcc_res->res_id = res->res_id;
    gcc_res->grp_id = res->grp_id;
    ret = strncpy_sp(gcc_res->name, CMS_NAME_BUFFER_SIZE, res->name, strlen(res->name));
    MEMS_RETURN_IFERR(ret);
    ret = strncpy_sp(gcc_res->type, CMS_NAME_BUFFER_SIZE, res->type, strlen(res->type));
    MEMS_RETURN_IFERR(ret);
    ret = strncpy_sp(gcc_res->script, CMS_FILE_NAME_BUFFER_SIZE, res->script, strlen(res->script));
    MEMS_RETURN_IFERR(ret);
    gcc_res->level = res->level;
    gcc_res->auto_start = res->auto_start;
    gcc_res->start_timeout = (res->start_timeout == 0) ? CMS_RES_START_TIMEOUT : res->start_timeout;
    gcc_res->stop_timeout = (res->stop_timeout == 0) ? CMS_RES_STOP_TIMEOUT : res->stop_timeout;
    gcc_res->check_timeout = (res->check_timeout == 0) ? CMS_RES_CHECK_TIMEOUT : res->check_timeout;
    gcc_res->hb_timeout = (res->hb_timeout == 0) ? CMS_RES_HB_TIMEOUT : res->hb_timeout;
    gcc_res->check_interval = (res->check_interval == 0) ? CMS_RES_CHECK_INTERVAL : res->check_interval;
    gcc_res->restart_times = res->restart_times;

    return GS_SUCCESS;
}

static inline status_t cms_import_parse_res_attr(cms_res_t *res, text_t *attr_head, text_t *attr_text)
{
    errno_t ret;

    if (res->res_id == 0 && cm_compare_text_str(attr_head, "RES_ID") == 0) {
        if (attr_text->len == 0) {
            GS_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "%s cannot be empty", T2S(attr_head));
            return GS_ERROR;
        }
        GS_RETURN_IFERR(cms_text2uint32(attr_text, &res->res_id));
    } else if (*res->name == 0 && cm_compare_text_str(attr_head, "NAME") == 0) {
        if (attr_text->len == 0) {
            GS_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "%s cannot be empty", T2S(attr_head));
            return GS_ERROR;
        }
        if (attr_text->len > CMS_MAX_NAME_LEN) {
            GS_THROW_ERROR(ERR_NAME_TOO_LONG, "resource", attr_text->len, CMS_MAX_NAME_LEN);
            return GS_ERROR;
        }
        ret = strncpy_sp(res->name, attr_text->len + 1, attr_text->str, attr_text->len);
        MEMS_RETURN_IFERR(ret);
    } else if (res->grp_id == 0 && cm_compare_text_str(attr_head, "GROUP_ID") == 0) {
        if (attr_text->len == 0) {
            GS_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "%s cannot be empty", T2S(attr_head));
            return GS_ERROR;
        }
        GS_RETURN_IFERR(cms_text2uint32(attr_text, &res->grp_id));
    } else if (*res->type == 0 && cm_compare_text_str(attr_head, "TYPE") == 0) {
        if (attr_text->len == 0) {
            GS_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "%s cannot be empty", T2S(attr_head));
            return GS_ERROR;
        }
        if (attr_text->len > CMS_MAX_NAME_LEN) {
            GS_THROW_ERROR(ERR_NAME_TOO_LONG, "resource type", attr_text->len, CMS_MAX_NAME_LEN);
            return GS_ERROR;
        }
        ret = strncpy_sp(res->type, attr_text->len + 1, attr_text->str, attr_text->len);
        MEMS_RETURN_IFERR(ret);
    } else if (res->level == 0 && cm_compare_text_str(attr_head, "LEVEL") == 0) {
        GS_RETURN_IFERR(cms_text2uint32(attr_text, &res->level));
    } else if (res->auto_start == 0 && cm_compare_text_str(attr_head, "AUTO_START") == 0) {
        GS_RETURN_IFERR(cms_text2uint32(attr_text, &res->auto_start));
        if (res->auto_start > 1) {
            GS_THROW_ERROR(ERR_CMS_GCC_IMPORT, "AUTO_START must be '0' or '1'");
        }
    } else if (res->start_timeout == 0 && cm_compare_text_str(attr_head, "START_TIMEOUT") == 0) {
        GS_RETURN_IFERR(cms_text2uint32(attr_text, &res->start_timeout));
    } else if (res->stop_timeout == 0 && cm_compare_text_str(attr_head, "STOP_TIMEOUT") == 0) {
        GS_RETURN_IFERR(cms_text2uint32(attr_text, &res->stop_timeout));
    } else if (res->check_timeout == 0 && cm_compare_text_str(attr_head, "CHECK_TIMEOUT") == 0) {
        GS_RETURN_IFERR(cms_text2uint32(attr_text, &res->check_timeout));
    } else if (res->hb_timeout == 0 && cm_compare_text_str(attr_head, "HB_TIMEOUT") == 0) {
        GS_RETURN_IFERR(cms_text2uint32(attr_text, &res->hb_timeout));
    } else if (res->check_interval == 0 && cm_compare_text_str(attr_head, "CHECK_INTERVAL") == 0) {
        GS_RETURN_IFERR(cms_text2uint32(attr_text, &res->check_interval));
    } else if (res->restart_times == 0 && cm_compare_text_str(attr_head, "RESTART_TIMES") == 0) {
        GS_RETURN_IFERR(cms_text2int32(attr_text, &res->restart_times));
    } else if (*res->script == 0 && cm_compare_text_str(attr_head, "SCRIPT") == 0) {
        if (attr_text->len > CMS_MAX_FILE_NAME_LEN) {
            GS_THROW_ERROR(ERR_FILE_PATH_TOO_LONG, CMS_MAX_FILE_NAME_LEN);
            return GS_ERROR;
        }
        ret = strncpy_sp(res->script, attr_text->len + 1, attr_text->str, attr_text->len);
        MEMS_RETURN_IFERR(ret);
    } else {
        GS_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "'%s' is an invalid attribute name", T2S(attr_head));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t cms_import_parse_res(cms_gcc_t *gcc, text_t *text, text_t *line, source_location_t *loc)
{
    text_t temp;
    text_t attr_names[CMS_IMP_RES_ATTR_NUM] = { { NULL, 0 } };
    cms_res_t res;
    uint32 imp_attr_count;
    errno_t ret;

    if (cms_import_parse_attr_names(line, attr_names, (uint32)CMS_IMP_RES_ATTR_NUM, &imp_attr_count) != GS_SUCCESS) {
        cm_set_error_loc(*loc);
        return GS_ERROR;
    }

    while (cm_fetch_line(text, line, GS_TRUE)) {
        cm_ltrim_text(line);
        (loc->line)++;
        if (line->len == 0) {
            continue;
        }
        if (line->str[0] == '#') {
            break;
        }

        ret = memset_sp(&res, sizeof(cms_res_t), 0, sizeof(cms_res_t));
        MEMS_RETURN_IFERR(ret);

        uint32 comma_num = 0;
        while (cm_fetch_text(line, ',', '\0', &temp)) {
            cm_trim_text(&temp);
            if (cms_import_parse_res_attr(&res, &attr_names[comma_num], &temp) != GS_SUCCESS) {
                cm_set_error_loc(*loc);
                return GS_ERROR;
            }
            if (line->str != NULL) {
                comma_num++;
            }

            if (comma_num > imp_attr_count - 1) {
                break;
            }
        }
        if (comma_num != imp_attr_count - 1) {
            GS_SRC_THROW_ERROR(*loc, ERR_CMS_GCC_IMPORT, "the number of attributes and attribute names does not match");
            return GS_ERROR;
        }

        if (cms_import_res_attrs(gcc, &res) != GS_SUCCESS) {
            cm_set_error_loc(*loc);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t cms_import_gcc_parse_text(cms_gcc_t *gcc, char *buf, uint32 buf_len)
{
    uint64 magic;
    text_t line = { NULL, 0 };
    text_t text = { buf, buf_len };
    source_location_t loc = { 0, 0 };
    errno_t ret;

    cm_trim_text(&text);
    do {
        if (cm_fetch_line(&text, &line, GS_TRUE)) {
            loc.line++;
        } else {
            GS_THROW_ERROR(ERR_CMS_GCC_IMPORT, "imported file is empty");
            return GS_ERROR;
        }
    } while (line.len == 0);

    gcc->head.magic = CMS_GCC_HEAD_MAGIC;
    gcc->resgrp[0].magic = CMS_GCC_RES_GRP_MAGIC;
    gcc->resgrp[0].grp_id = 0;
    ret = strcpy_sp(gcc->resgrp[0].name, CMS_NAME_BUFFER_SIZE, "default");
    MEMS_RETURN_IFERR(ret);

    do {
        if (line.len == GCC_IMP_OBJ_MAGIC_LEN && line.str[0] == '#' &&
            line.str[GCC_IMP_OBJ_MAGIC_LEN - 1] == '#') {
            magic = *((uint64*)(line.str + 1));
        } else {
            GS_SRC_THROW_ERROR(loc, ERR_CMS_GCC_IMPORT, "gcc object title is invalid");
            return GS_ERROR;
        }

        cm_ltrim_text(&text);
        if (text.len == 0) {
            break;
        }

        do {
            if (cm_fetch_line(&text, &line, GS_TRUE)) {
                cm_ltrim_text(&line);
                loc.line++;
            }
        } while (line.len == 0);

        if (line.str[0] == '#') {
            continue;
        }

        if (magic == CMS_GCC_NODE_MAGIC) {
            GS_RETURN_IFERR(cms_import_parse_node(gcc, &text, &line, &loc));
        } else if (magic == CMS_GCC_VOTEDISK_MAGIC) {
            GS_RETURN_IFERR(cms_import_parse_votedisk(gcc, &text, &line, &loc));
        } else if (magic == CMS_GCC_RES_GRP_MAGIC) {
            GS_RETURN_IFERR(cms_import_parse_resgrp(gcc, &text, &line, &loc));
        } else if (magic == CMS_GCC_RES_MAGIC) {
            GS_RETURN_IFERR(cms_import_parse_res(gcc, &text, &line, &loc));
        } else if (magic == CMS_GCC_HEAD_MAGIC) {
            GS_RETURN_IFERR(cms_import_parse_head(gcc, &text, &line, &loc));
        } else {
            GS_SRC_THROW_ERROR(loc, ERR_CMS_GCC_IMPORT, "unknown gcc object name");
            return GS_ERROR;
        }
    } while (text.len > 0);

    return GS_SUCCESS;
}

static status_t cms_import_gcc_read_file(const char* path, char* buf, int32* buf_size)
{
    int32 file;
    int64 file_size;

    if (cm_open_file(path, O_RDONLY | O_BINARY | O_CLOEXEC, &file) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_OPEN_FILE, path, errno);
        return GS_ERROR;
    }

    file_size = cm_file_size(file);
    if (file_size == -1) {
        cm_close_file(file);
        GS_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_END, errno);
        return GS_ERROR;
    }

    if (file_size > CMS_MAX_IMP_FILE_SIZE) {
        cm_close_file(file);
        GS_THROW_ERROR(ERR_FILE_SIZE_TOO_LARGE, path);
        return GS_ERROR;
    }
    if (cm_seek_file(file, 0, SEEK_SET) != 0) {
        cm_close_file(file);
        GS_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_SET, errno);
        return GS_ERROR;
    }

    if (cm_read_file(file, buf, (int32)file_size, buf_size) != GS_SUCCESS) {
        cm_close_file(file);
        GS_LOG_RUN_ERR("failed to read data from file");
        cms_exec_exit_proc();
        return GS_ERROR;
    }

    cm_close_file(file);
    return GS_SUCCESS;
}

status_t cms_import_gcc(const char* path)
{
    char* buf = NULL;
    int32 buf_len = 0;
    cms_gcc_t* new_gcc = NULL;
    errno_t ret;

    GS_RETURN_IFERR(cms_load_gcc());

    buf = (char *)malloc(CMS_MAX_IMP_FILE_SIZE);
    if (buf == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)CMS_MAX_IMP_FILE_SIZE, "loading import file");
        return GS_ERROR;
    }
    ret = memset_sp(buf, CMS_MAX_IMP_FILE_SIZE, 0, CMS_MAX_IMP_FILE_SIZE);
    if (ret != EOK) {
        CM_FREE_PTR(buf);
        GS_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return GS_ERROR;
    }

    if (cms_import_gcc_read_file(path, buf, &buf_len) != GS_SUCCESS) {
        CM_FREE_PTR(buf);
        CMS_LOG_ERR("read file failed, path:%s, buf_len(%u)", path, buf_len);
        return GS_ERROR;
    }

    new_gcc = (cms_gcc_t *)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_gcc_t));
    if (new_gcc == NULL) {
        CM_FREE_PTR(buf);
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(cms_gcc_t), "loading import file");
        return GS_ERROR;
    }
    ret = memset_sp(new_gcc, sizeof(cms_gcc_t), 0, sizeof(cms_gcc_t));
    if (ret != EOK) {
        CM_FREE_PTR(new_gcc);
        CM_FREE_PTR(buf);
        GS_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return GS_ERROR;
    }

    if (cms_import_gcc_parse_text(new_gcc, buf, (uint32)buf_len) != GS_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        CM_FREE_PTR(buf);
        CMS_LOG_ERR("parse import file failed");
        return GS_ERROR;
    }
    CM_FREE_PTR(buf);

    if (cms_gcc_write_disk(new_gcc) != GS_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        CMS_LOG_ERR("write gcc failed");
        return GS_ERROR;
    }

    CM_FREE_PTR(new_gcc);
    return GS_SUCCESS;
}

static inline bool32 cms_is_export_gcc_file(const char* file_name, uint32 file_name_len)
{
    text_t tail = { ".exp", 4 };
    return cm_text_str_equal(&tail, &file_name[file_name_len - tail.len]);
}

status_t cms_restore_gcc(const char* file_name)
{
    if (cms_is_export_gcc_file(file_name, (uint32)strlen(file_name))) {
        return cms_import_gcc(file_name);
    }

    disk_handle_t handle;
    errno_t ret;
    cms_gcc_t* new_gcc = (cms_gcc_t *)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_gcc_t));
    if (new_gcc == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(cms_gcc_t), "restoring gcc");
        return GS_ERROR;
    }
    ret = memset_sp(new_gcc, sizeof(cms_gcc_t), 0, sizeof(cms_gcc_t));
    if (ret != EOK) {
        CM_FREE_PTR(new_gcc);
        GS_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return GS_ERROR;
    }

    if (cm_open_disk(file_name, &handle) != GS_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        GS_THROW_ERROR(ERR_OPEN_FILE, file_name, errno);
        CMS_LOG_ERR("open disk failed, fileName(%s)", file_name);
        return GS_ERROR;
    }
    if (cm_get_disk_size(handle) != (int64)sizeof(cms_gcc_t)) {
        CMS_LOG_ERR("get size failed, size(%llu), need_size(%u)", cm_get_disk_size(handle), (uint32)sizeof(cms_gcc_t));
        CM_FREE_PTR(new_gcc);
        cm_close_disk(handle);
        GS_THROW_ERROR(ERR_CMS_GCC_VERSION_MISMATCH, "this binary backup file");
        return GS_ERROR;
    }
    if (cm_read_disk(handle, 0, (char *)new_gcc, sizeof(cms_gcc_t)) != GS_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        cm_close_disk(handle);
        CMS_LOG_ERR("read disk failed. fileName(%s)", file_name);
        return GS_ERROR;
    }
    cm_close_disk(handle);
    if (new_gcc->head.magic != CMS_GCC_HEAD_MAGIC) {
        CM_FREE_PTR(new_gcc);
        CMS_LOG_ERR("gcc is invalid.");
        return GS_ERROR;
    }

    if (cms_gcc_write_disk(new_gcc) != GS_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        CMS_LOG_ERR("write disk failed. fileName(%s)", file_name);
        return GS_ERROR;
    }

    CM_FREE_PTR(new_gcc);
    return GS_SUCCESS;
}
