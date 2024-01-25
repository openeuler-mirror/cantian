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
 * cms_gcc_imp.c
 *
 *
 * IDENTIFICATION
 * src/cms/cms/cms_gcc_imp.c
 *
 * -------------------------------------------------------------------------
 */
#include "cms_log_module.h"
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
    if (cm_text2int(text_src, value) != CT_SUCCESS) {
        int err_code = cm_get_error_code();
        if (err_code == ERR_SQL_SYNTAX_ERROR) {
            cm_reset_error();
            CT_THROW_ERROR(ERR_CMS_CONVERT_VALUE, T2S(text_src), "unsigned int");
        }
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t cms_text2uint32(const text_t* text_src, uint32* value)
{
    if (cm_text2uint32(text_src, value) != CT_SUCCESS) {
        int err_code = cm_get_error_code();
        if (err_code == ERR_SQL_SYNTAX_ERROR) {
            cm_reset_error();
            CT_THROW_ERROR(ERR_CMS_CONVERT_VALUE, T2S(text_src), "unsigned int");
        }
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static inline bool32 cms_check_import_attr_names_valid(const char *head, uint32 head_len)
{
    for (uint32 i = 0; i < head_len; i++) {
        if (head[i] != '_' && (head[i] < 'A' || head[i] > 'Z')) {
            return CT_FALSE;
        }
    }

    return CT_TRUE;
}

static status_t cms_import_parse_attr_names(text_t *line, text_t *attr_names, uint32 max_count, uint32 *count)
{
    text_t temp;
    uint32 i = 0;

    while (cm_fetch_text(line, ',', '\0', &temp)) {
        cm_trim_text(&temp);
        if (temp.len == 0) {
            CT_THROW_ERROR(ERR_CMS_GCC_IMPORT, "one attribute name is empty");
            return CT_ERROR;
        }

        if (!cms_check_import_attr_names_valid(temp.str, temp.len)) {
            CT_THROW_ERROR(ERR_CMS_GCC_IMPORT, "one attribute name is invalid or empty");
            return CT_ERROR;
        }
        attr_names[i].str = temp.str;
        attr_names[i].len = temp.len;
        if (line->str != NULL) {
            i++;
        }
        if (i >= max_count) {
            CT_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "too many attribute names (maximum: %u)", max_count);
            return CT_ERROR;
        }
    }
    *count = i + 1;

    return CT_SUCCESS;
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

    return CT_SUCCESS;
}

static inline status_t cms_import_parse_head_attr(cms_gcc_head_t *gcc_head, text_t *attr_head, text_t *attr_text)
{
    if (gcc_head->meta_ver == 0 && cm_compare_text_str(attr_head, "META_VER") == 0) {
        CT_RETURN_IFERR(cms_text2uint32(attr_text, &gcc_head->meta_ver));
    } else if (gcc_head->node_count == 0 && cm_compare_text_str(attr_head, "NODE_COUNT") == 0) {
        if (attr_text->len == 0) {
            CT_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "%s cannot be empty", T2S(attr_head));
            return CT_ERROR;
        }
        CT_RETURN_IFERR(cms_text2uint32(attr_text, &gcc_head->node_count));
        if (gcc_head->node_count > CMS_MAX_NODE_COUNT) {
            CT_THROW_ERROR(ERR_CMS_NUM_EXCEED, "NODE_COUNT", (uint32)CMS_MAX_NODE_COUNT);
            return CT_ERROR;
        }
    } else if (gcc_head->data_ver == 0 && cm_compare_text_str(attr_head, "DATA_VER") == 0) {
        if (attr_text->len == 0) {
            CT_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "%s cannot be empty", T2S(attr_head));
            return CT_ERROR;
        }
        CT_RETURN_IFERR(cms_text2uint32(attr_text, &gcc_head->data_ver));
    } else if (gcc_head->cheksum == 0 && cm_compare_text_str(attr_head, "CHECKSUM") == 0) {
        CT_RETURN_IFERR(cms_text2uint32(attr_text, &gcc_head->cheksum));
    } else {
        CT_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "'%s' is an invalid attribute name", T2S(attr_head));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t cms_import_parse_head(cms_gcc_t *gcc, text_t *text, text_t *line, source_location_t *loc)
{
    text_t temp;
    text_t attr_names[CMS_IMP_NODE_ATTR_NUM] = { { NULL, 0 } };
    cms_gcc_head_t gcc_head;
    uint32 imp_attr_count;
    errno_t ret;

    if (cms_import_parse_attr_names(line, attr_names, (uint32)CMS_IMP_HEAD_ATTR_NUM, &imp_attr_count) != CT_SUCCESS) {
        cm_set_error_loc(*loc);
        return CT_ERROR;
    }

    while (cm_fetch_line(text, line, CT_TRUE)) {
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
            if (cms_import_parse_head_attr(&gcc_head, &attr_names[comma_num], &temp) != CT_SUCCESS) {
                cm_set_error_loc(*loc);
                return CT_ERROR;
            }
            if (line->str != NULL) {
                comma_num++;
            }

            if (comma_num > imp_attr_count - 1) {
                break;
            }
        }
        if (comma_num != imp_attr_count - 1) {
            CT_SRC_THROW_ERROR(*loc, ERR_CMS_GCC_IMPORT, "the number of attributes and attribute names does not match");
            return CT_ERROR;
        }

        if (cms_import_head_attrs(gcc, &gcc_head) != CT_SUCCESS) {
            cm_set_error_loc(*loc);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static inline status_t cms_check_import_node_valid(cms_node_def_t *node_def)
{
    if (node_def->node_id >= CMS_MAX_NODE_COUNT) {
        CT_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "NODE_ID must be less than %u", (uint32)CMS_MAX_NODE_COUNT);
        return CT_ERROR;
    }

    if (!cms_check_name_valid(node_def->name, (uint32)strlen(node_def->name))) {
        CT_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "node name");
        return CT_ERROR;
    }

    if (cm_verify_lsnr_addr(node_def->ip, (uint32)strnlen(node_def->ip, CT_MAX_INST_IP_LEN - 1), NULL) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "node ip");
        return CT_ERROR;
    }

    if (node_def->port == 0 || node_def->port > CT_MAX_UINT16) {
        CT_THROW_ERROR(ERR_CMS_PORT_OUT_RANGE, 1, CT_MAX_UINT16);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t cms_import_node_attrs(cms_gcc_t *gcc, cms_node_def_t *node_def)
{
    cms_node_def_t *gcc_node = NULL;
    errno_t ret;

    if (node_def->node_id >= gcc->head.node_count) {
        CT_THROW_ERROR(ERR_CMS_GCC_IMPORT, "node id must be less than node count in gcc head");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(cms_check_import_node_valid(node_def));

    gcc_node = &gcc->node_def[node_def->node_id];
    if (gcc_node->magic == CMS_GCC_NODE_MAGIC) {
        CT_THROW_ERROR_EX(ERR_CMS_OBJECT_EXISTS, "node_id '%u'", node_def->node_id);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(cms_check_node_exists(gcc, node_def->name, node_def->ip, node_def->port));

    gcc_node->magic = CMS_GCC_NODE_MAGIC;
    gcc_node->node_id = node_def->node_id;
    ret = strncpy_sp(gcc_node->name, CMS_NAME_BUFFER_SIZE, node_def->name, strlen(node_def->name));
    MEMS_RETURN_IFERR(ret);

    ret = strncpy_sp(gcc_node->ip, CT_MAX_INST_IP_LEN, node_def->ip, strlen(node_def->ip));
    MEMS_RETURN_IFERR(ret);

    gcc_node->port = node_def->port;
    gcc->head.node_count = MAX(node_def->node_id + 1, gcc->head.node_count);

    return CT_SUCCESS;
}

static inline status_t cms_import_parse_node_attr(cms_node_def_t *node_def, text_t *attr_head, text_t *attr_text)
{
    errno_t ret;

    if (attr_text->len == 0) {
        CT_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "%s cannot be empty", T2S(attr_head));
        return CT_ERROR;
    }

    if (node_def->node_id == 0 && cm_compare_text_str(attr_head, "NODE_ID") == 0) {
        CT_RETURN_IFERR(cms_text2uint32(attr_text, &node_def->node_id));
    } else if (*node_def->name == 0 && cm_compare_text_str(attr_head, "NAME") == 0) {
        if (attr_text->len > CMS_MAX_NAME_LEN) {
            CT_THROW_ERROR(ERR_NAME_TOO_LONG, "node", attr_text->len, CMS_MAX_NAME_LEN);
            return CT_ERROR;
        }
        ret = strncpy_sp(node_def->name, attr_text->len + 1, attr_text->str, attr_text->len);
        MEMS_RETURN_IFERR(ret);
    } else if (*node_def->ip == 0 && cm_compare_text_str(attr_head, "IP") == 0) {
        if (attr_text->len > CMS_MAX_IP_LEN) {
            CT_THROW_ERROR(ERR_INVALID_IPADDRESS_LENGTH, attr_text->len);
            return CT_ERROR;
        }
        ret = strncpy_sp(node_def->ip, attr_text->len + 1, attr_text->str, attr_text->len);
        MEMS_RETURN_IFERR(ret);
    } else if (node_def->port == 0 && cm_compare_text_str(attr_head, "PORT") == 0) {
        CT_RETURN_IFERR(cms_text2uint32(attr_text, &node_def->port));
    } else {
        CT_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "'%s' is an invalid attribute name", T2S(attr_head));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t cms_import_parse_node(cms_gcc_t *gcc, text_t *text, text_t *line, source_location_t *loc)
{
    text_t temp;
    text_t attr_names[CMS_IMP_NODE_ATTR_NUM] = { { NULL, 0 } };
    cms_node_def_t node_def;
    uint32 imp_attr_count;
    errno_t ret;

    if (cms_import_parse_attr_names(line, attr_names, (uint32)CMS_IMP_NODE_ATTR_NUM, &imp_attr_count) != CT_SUCCESS) {
        cm_set_error_loc(*loc);
        return CT_ERROR;
    }

    while (cm_fetch_line(text, line, CT_TRUE)) {
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
            if (cms_import_parse_node_attr(&node_def, &attr_names[comma_num], &temp) != CT_SUCCESS) {
                cm_set_error_loc(*loc);
                return CT_ERROR;
            }
            if (line->str != NULL) {
                comma_num++;
            }

            if (comma_num > imp_attr_count - 1) {
                break;
            }
        }
        if (comma_num != imp_attr_count - 1) {
            CT_SRC_THROW_ERROR(*loc, ERR_CMS_GCC_IMPORT, "the number of attributes and attribute names does not match");
            return CT_ERROR;
        }

        if (cms_import_node_attrs(gcc, &node_def) != CT_SUCCESS) {
            cm_set_error_loc(*loc);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t cms_import_votedisk_attrs(cms_gcc_t *gcc, cms_votedisk_t *votedisk)
{
    uint32 disk_id;
    cms_votedisk_t* gcc_votedisk = NULL;
    errno_t ret;

    CT_RETURN_IFERR(cms_check_votedisk(votedisk->path));

    for (disk_id = 0; disk_id < CMS_MAX_VOTEDISK_COUNT; disk_id++) {
        if (gcc->votedisks[disk_id].magic == CMS_GCC_VOTEDISK_MAGIC &&
            cm_compare_str(gcc->votedisks[disk_id].path, votedisk->path) == 0) {
            CT_THROW_ERROR(ERR_CMS_OBJECT_EXISTS, "the votedisk");
            return CT_ERROR;
        }
    }

    for (disk_id = 0; disk_id < CMS_MAX_VOTEDISK_COUNT; disk_id++) {
        if (gcc->votedisks[disk_id].magic != CMS_GCC_VOTEDISK_MAGIC) {
            gcc_votedisk = &gcc->votedisks[disk_id];
            break;
        }
    }

    if (disk_id == CMS_MAX_VOTEDISK_COUNT || gcc_votedisk == NULL) {
        CT_THROW_ERROR(ERR_CMS_NUM_EXCEED, "votedisk");
        return CT_ERROR;
    }

    gcc_votedisk->magic = CMS_GCC_VOTEDISK_MAGIC;
    ret = strncpy_sp(gcc_votedisk->path, CMS_FILE_NAME_BUFFER_SIZE, votedisk->path, strlen(votedisk->path));
    MEMS_RETURN_IFERR(ret);

    return CT_SUCCESS;
}

static inline status_t cms_import_parse_votedisk_attr(cms_votedisk_t *votedisk, text_t *attr_head, text_t *attr_text)
{
    errno_t ret;

    if (attr_text->len == 0) {
        CT_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "%s cannot be empty", T2S(attr_head));
        return CT_ERROR;
    }

    if (*votedisk->path == 0 && cm_compare_text_str(attr_head, "PATH") == 0) {
        if (attr_text->len > CMS_MAX_FILE_NAME_LEN) {
            CT_THROW_ERROR(ERR_FILE_PATH_TOO_LONG, CMS_MAX_FILE_NAME_LEN);
            return CT_ERROR;
        }
        if (!cms_check_path_valid(attr_text->str, attr_text->len)) {
            CT_THROW_ERROR(ERR_CMS_INVALID_PATH, "votedisk");
            return CT_ERROR;
        }
        ret = strncpy_sp(votedisk->path, attr_text->len + 1, attr_text->str, attr_text->len);
        MEMS_RETURN_IFERR(ret);
    } else {
        CT_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "'%s' is an invalid attribute name", T2S(attr_head));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t cms_import_parse_votedisk(cms_gcc_t *gcc, text_t *text, text_t *line, source_location_t *loc)
{
    text_t temp;
    text_t attr_names[CMS_IMP_VOIEDISK_ATTR_NUM] = { { NULL, 0 } };
    cms_votedisk_t votedisk;
    uint32 imp_attr_count;
    errno_t ret;

    if (cms_import_parse_attr_names(line, attr_names, (uint32)CMS_IMP_VOIEDISK_ATTR_NUM, &imp_attr_count) != CT_SUCCESS) {
        cm_set_error_loc(*loc);
        return CT_ERROR;
    }

    while (cm_fetch_line(text, line, CT_TRUE)) {
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
            if (cms_import_parse_votedisk_attr(&votedisk, &attr_names[comma_num], &temp) != CT_SUCCESS) {
                cm_set_error_loc(*loc);
                return CT_ERROR;
            }
            if (line->str != NULL) {
                comma_num++;
            }

            if (comma_num > imp_attr_count - 1) {
                break;
            }
        }
        if (comma_num != imp_attr_count - 1) {
            CT_SRC_THROW_ERROR(*loc, ERR_CMS_GCC_IMPORT, "the number of attributes and attribute names does not match");
            return CT_ERROR;
        }

        if (cms_import_votedisk_attrs(gcc, &votedisk) != CT_SUCCESS) {
            cm_set_error_loc(*loc);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t cms_import_resgrp_attrs(cms_gcc_t *gcc, cms_resgrp_t *resgrp)
{
    uint32 grp_id;
    cms_resgrp_t* gcc_resgrp = NULL;
    errno_t ret;

    if (resgrp->grp_id >= CMS_MAX_RESOURCE_GRP_COUNT) {
        CT_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "GROUP_ID must be less than %u", (uint32)CMS_MAX_RESOURCE_GRP_COUNT);
        return CT_ERROR;
    }
    if (!cms_check_name_valid(resgrp->name, (uint32)strlen(resgrp->name))) {
        CT_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "resource group name");
        return CT_ERROR;
    }

    for (grp_id = 0; grp_id < CMS_MAX_RESOURCE_GRP_COUNT; grp_id++) {
        if (gcc->resgrp[grp_id].magic == CMS_GCC_RES_GRP_MAGIC &&
            cm_compare_str(gcc->resgrp[grp_id].name, resgrp->name) == 0) {
            CT_THROW_ERROR(ERR_CMS_OBJECT_EXISTS, "the resource group");
            return CT_ERROR;
        }
    }

    gcc_resgrp = &gcc->resgrp[resgrp->grp_id];

    if (gcc_resgrp->magic == CMS_GCC_RES_GRP_MAGIC) {
        CT_THROW_ERROR(ERR_CMS_OBJECT_EXISTS, "the resource group id");
        return CT_ERROR;
    }

    gcc_resgrp->magic = CMS_GCC_RES_GRP_MAGIC;
    gcc_resgrp->grp_id = resgrp->grp_id;
    ret = strncpy_sp(gcc_resgrp->name, CMS_NAME_BUFFER_SIZE, resgrp->name, strlen(resgrp->name));
    MEMS_RETURN_IFERR(ret);

    return CT_SUCCESS;
}

static inline status_t cms_import_parse_resgrp_attr(cms_resgrp_t *resgrp, text_t *attr_head, text_t *attr_text)
{
    errno_t ret;

    if (attr_text->len == 0) {
        CT_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "%s cannot be empty", T2S(attr_head));
        return CT_ERROR;
    }

    if (resgrp->grp_id == 0 && cm_compare_text_str(attr_head, "GROUP_ID") == 0) {
        CT_RETURN_IFERR(cms_text2uint32(attr_text, &resgrp->grp_id));
    } else if (*resgrp->name == 0 && cm_compare_text_str(attr_head, "NAME") == 0) {
        if (attr_text->len > CMS_MAX_NAME_LEN) {
            CT_THROW_ERROR(ERR_NAME_TOO_LONG, "resource group", attr_text->len, CMS_MAX_NAME_LEN);
            return CT_ERROR;
        }
        ret = strncpy_sp(resgrp->name, attr_text->len + 1, attr_text->str, attr_text->len);
        MEMS_RETURN_IFERR(ret);
    } else {
        CT_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "'%s' is an invalid attribute name", T2S(attr_head));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t cms_import_parse_resgrp(cms_gcc_t *gcc, text_t *text, text_t *line, source_location_t *loc)
{
    text_t temp;
    text_t attr_names[CMS_IMP_RES_GRP_ATTR_NUM] = { { NULL, 0 } };
    cms_resgrp_t resgrp;
    uint32 imp_attr_count;
    errno_t ret;

    if (cms_import_parse_attr_names(line, attr_names, (uint32)CMS_IMP_RES_GRP_ATTR_NUM, &imp_attr_count) != CT_SUCCESS) {
        cm_set_error_loc(*loc);
        return CT_ERROR;
    }

    while (cm_fetch_line(text, line, CT_TRUE)) {
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
            if (cms_import_parse_resgrp_attr(&resgrp, &attr_names[comma_num], &temp) != CT_SUCCESS) {
                cm_set_error_loc(*loc);
                return CT_ERROR;
            }
            if (line->str != NULL) {
                comma_num++;
            }

            if (comma_num > imp_attr_count - 1) {
                break;
            }
        }
        if (comma_num != imp_attr_count - 1) {
            CT_SRC_THROW_ERROR(*loc, ERR_CMS_GCC_IMPORT, "the number of attributes and attribute names does not match");
            return CT_ERROR;
        }

        if (resgrp.grp_id == 0) {
            if (cm_strcmpni(resgrp.name, "default", strlen(resgrp.name)) == 0) {
                continue;
            } else {
                CT_SRC_THROW_ERROR(*loc, ERR_CMS_GCC_IMPORT, "group 0 must be default");
                return CT_ERROR;
            }
        }
        if (cms_import_resgrp_attrs(gcc, &resgrp) != CT_SUCCESS) {
            cm_set_error_loc(*loc);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static inline status_t cms_check_import_res_valid(cms_res_t *res)
{
    if (res->res_id >= CMS_MAX_RESOURCE_COUNT) {
        CT_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "RES_ID must be less than %u", (uint32)CMS_MAX_RESOURCE_COUNT);
        return CT_ERROR;
    }

    if (res->grp_id >= CMS_MAX_RESOURCE_GRP_COUNT) {
        CT_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "GROUP_ID must be less than %u", (uint32)CMS_MAX_RESOURCE_GRP_COUNT);
        return CT_ERROR;
    }

    if (!cms_check_name_valid(res->name, (uint32)strlen(res->name))) {
        CT_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "resource name");
        return CT_ERROR;
    }

    if (!cms_check_name_valid(res->type, (uint32)strlen(res->type))) {
        CT_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "resource type");
        return CT_ERROR;
    }

    if (!cms_check_path_valid(res->script, (uint32)strlen(res->script))) {
        CT_THROW_ERROR(ERR_CMS_INVALID_PATH, "resource script");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t cms_import_res_attrs(cms_gcc_t *gcc, cms_res_t *res)
{
    uint32 res_id;
    cms_res_t* gcc_res = NULL;
    errno_t ret;

    CT_RETURN_IFERR(cms_check_import_res_valid(res));
    if (gcc->resgrp[res->grp_id].magic != CMS_GCC_RES_GRP_MAGIC) {
        CT_THROW_ERROR_EX(ERR_CMS_OBJECT_NOT_FOUND, "the resource group id '%u'", res->grp_id);
        return CT_ERROR;
    }

    for (res_id = 0; res_id < CMS_MAX_RESOURCE_COUNT; res_id++) {
        if (gcc->res[res_id].magic == CMS_GCC_RES_MAGIC &&
            cm_compare_str(gcc->res[res_id].name, res->name) == 0) {
            CT_THROW_ERROR_EX(ERR_CMS_OBJECT_EXISTS, "the resource '%s'", res->name);
            return CT_ERROR;
        }
        if (gcc->res[res_id].magic == CMS_GCC_RES_MAGIC && res->grp_id == gcc->res[res_id].grp_id &&
            cm_compare_str(gcc->res[res_id].type, res->type) == 0) {
            CT_THROW_ERROR(ERR_CMS_SAME_RESOURCE_TYPE, gcc->resgrp[res->grp_id].name);
            return CT_ERROR;
        }
    }
    gcc_res = &gcc->res[res->res_id];

    if (gcc_res->magic == CMS_GCC_RES_MAGIC) {
        CT_THROW_ERROR_EX(ERR_CMS_OBJECT_EXISTS, "the resource %u ", res->res_id);
        return CT_ERROR;
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

    return CT_SUCCESS;
}

static inline status_t cms_import_parse_res_attr(cms_res_t *res, text_t *attr_head, text_t *attr_text)
{
    errno_t ret;

    if (res->res_id == 0 && cm_compare_text_str(attr_head, "RES_ID") == 0) {
        if (attr_text->len == 0) {
            CT_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "%s cannot be empty", T2S(attr_head));
            return CT_ERROR;
        }
        CT_RETURN_IFERR(cms_text2uint32(attr_text, &res->res_id));
    } else if (*res->name == 0 && cm_compare_text_str(attr_head, "NAME") == 0) {
        if (attr_text->len == 0) {
            CT_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "%s cannot be empty", T2S(attr_head));
            return CT_ERROR;
        }
        if (attr_text->len > CMS_MAX_NAME_LEN) {
            CT_THROW_ERROR(ERR_NAME_TOO_LONG, "resource", attr_text->len, CMS_MAX_NAME_LEN);
            return CT_ERROR;
        }
        ret = strncpy_sp(res->name, attr_text->len + 1, attr_text->str, attr_text->len);
        MEMS_RETURN_IFERR(ret);
    } else if (res->grp_id == 0 && cm_compare_text_str(attr_head, "GROUP_ID") == 0) {
        if (attr_text->len == 0) {
            CT_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "%s cannot be empty", T2S(attr_head));
            return CT_ERROR;
        }
        CT_RETURN_IFERR(cms_text2uint32(attr_text, &res->grp_id));
    } else if (*res->type == 0 && cm_compare_text_str(attr_head, "TYPE") == 0) {
        if (attr_text->len == 0) {
            CT_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "%s cannot be empty", T2S(attr_head));
            return CT_ERROR;
        }
        if (attr_text->len > CMS_MAX_NAME_LEN) {
            CT_THROW_ERROR(ERR_NAME_TOO_LONG, "resource type", attr_text->len, CMS_MAX_NAME_LEN);
            return CT_ERROR;
        }
        ret = strncpy_sp(res->type, attr_text->len + 1, attr_text->str, attr_text->len);
        MEMS_RETURN_IFERR(ret);
    } else if (res->level == 0 && cm_compare_text_str(attr_head, "LEVEL") == 0) {
        CT_RETURN_IFERR(cms_text2uint32(attr_text, &res->level));
    } else if (res->auto_start == 0 && cm_compare_text_str(attr_head, "AUTO_START") == 0) {
        CT_RETURN_IFERR(cms_text2uint32(attr_text, &res->auto_start));
        if (res->auto_start > 1) {
            CT_THROW_ERROR(ERR_CMS_GCC_IMPORT, "AUTO_START must be '0' or '1'");
        }
    } else if (res->start_timeout == 0 && cm_compare_text_str(attr_head, "START_TIMEOUT") == 0) {
        CT_RETURN_IFERR(cms_text2uint32(attr_text, &res->start_timeout));
    } else if (res->stop_timeout == 0 && cm_compare_text_str(attr_head, "STOP_TIMEOUT") == 0) {
        CT_RETURN_IFERR(cms_text2uint32(attr_text, &res->stop_timeout));
    } else if (res->check_timeout == 0 && cm_compare_text_str(attr_head, "CHECK_TIMEOUT") == 0) {
        CT_RETURN_IFERR(cms_text2uint32(attr_text, &res->check_timeout));
    } else if (res->hb_timeout == 0 && cm_compare_text_str(attr_head, "HB_TIMEOUT") == 0) {
        CT_RETURN_IFERR(cms_text2uint32(attr_text, &res->hb_timeout));
    } else if (res->check_interval == 0 && cm_compare_text_str(attr_head, "CHECK_INTERVAL") == 0) {
        CT_RETURN_IFERR(cms_text2uint32(attr_text, &res->check_interval));
    } else if (res->restart_times == 0 && cm_compare_text_str(attr_head, "RESTART_TIMES") == 0) {
        CT_RETURN_IFERR(cms_text2int32(attr_text, &res->restart_times));
    } else if (*res->script == 0 && cm_compare_text_str(attr_head, "SCRIPT") == 0) {
        if (attr_text->len > CMS_MAX_FILE_NAME_LEN) {
            CT_THROW_ERROR(ERR_FILE_PATH_TOO_LONG, CMS_MAX_FILE_NAME_LEN);
            return CT_ERROR;
        }
        ret = strncpy_sp(res->script, attr_text->len + 1, attr_text->str, attr_text->len);
        MEMS_RETURN_IFERR(ret);
    } else {
        CT_THROW_ERROR_EX(ERR_CMS_GCC_IMPORT, "'%s' is an invalid attribute name", T2S(attr_head));
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t cms_import_parse_res(cms_gcc_t *gcc, text_t *text, text_t *line, source_location_t *loc)
{
    text_t temp;
    text_t attr_names[CMS_IMP_RES_ATTR_NUM] = { { NULL, 0 } };
    cms_res_t res;
    uint32 imp_attr_count;
    errno_t ret;

    if (cms_import_parse_attr_names(line, attr_names, (uint32)CMS_IMP_RES_ATTR_NUM, &imp_attr_count) != CT_SUCCESS) {
        cm_set_error_loc(*loc);
        return CT_ERROR;
    }

    while (cm_fetch_line(text, line, CT_TRUE)) {
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
            if (cms_import_parse_res_attr(&res, &attr_names[comma_num], &temp) != CT_SUCCESS) {
                cm_set_error_loc(*loc);
                return CT_ERROR;
            }
            if (line->str != NULL) {
                comma_num++;
            }

            if (comma_num > imp_attr_count - 1) {
                break;
            }
        }
        if (comma_num != imp_attr_count - 1) {
            CT_SRC_THROW_ERROR(*loc, ERR_CMS_GCC_IMPORT, "the number of attributes and attribute names does not match");
            return CT_ERROR;
        }

        if (cms_import_res_attrs(gcc, &res) != CT_SUCCESS) {
            cm_set_error_loc(*loc);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
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
        if (cm_fetch_line(&text, &line, CT_TRUE)) {
            loc.line++;
        } else {
            CT_THROW_ERROR(ERR_CMS_GCC_IMPORT, "imported file is empty");
            return CT_ERROR;
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
            CT_SRC_THROW_ERROR(loc, ERR_CMS_GCC_IMPORT, "gcc object title is invalid");
            return CT_ERROR;
        }

        cm_ltrim_text(&text);
        if (text.len == 0) {
            break;
        }

        do {
            if (cm_fetch_line(&text, &line, CT_TRUE)) {
                cm_ltrim_text(&line);
                loc.line++;
            }
        } while (line.len == 0);

        if (line.str[0] == '#') {
            continue;
        }

        if (magic == CMS_GCC_NODE_MAGIC) {
            CT_RETURN_IFERR(cms_import_parse_node(gcc, &text, &line, &loc));
        } else if (magic == CMS_GCC_VOTEDISK_MAGIC) {
            CT_RETURN_IFERR(cms_import_parse_votedisk(gcc, &text, &line, &loc));
        } else if (magic == CMS_GCC_RES_GRP_MAGIC) {
            CT_RETURN_IFERR(cms_import_parse_resgrp(gcc, &text, &line, &loc));
        } else if (magic == CMS_GCC_RES_MAGIC) {
            CT_RETURN_IFERR(cms_import_parse_res(gcc, &text, &line, &loc));
        } else if (magic == CMS_GCC_HEAD_MAGIC) {
            CT_RETURN_IFERR(cms_import_parse_head(gcc, &text, &line, &loc));
        } else {
            CT_SRC_THROW_ERROR(loc, ERR_CMS_GCC_IMPORT, "unknown gcc object name");
            return CT_ERROR;
        }
    } while (text.len > 0);

    return CT_SUCCESS;
}

static status_t cms_import_gcc_read_file(const char* path, char* buf, int32* buf_size)
{
    int32 file;
    int64 file_size;

    if (cm_open_file(path, O_RDONLY | O_BINARY | O_CLOEXEC, &file) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_OPEN_FILE, path, errno);
        return CT_ERROR;
    }

    file_size = cm_file_size(file);
    if (file_size == -1) {
        cm_close_file(file);
        CT_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_END, errno);
        return CT_ERROR;
    }

    if (file_size > CMS_MAX_IMP_FILE_SIZE) {
        cm_close_file(file);
        CT_THROW_ERROR(ERR_FILE_SIZE_TOO_LARGE, path);
        return CT_ERROR;
    }
    if (cm_seek_file(file, 0, SEEK_SET) != 0) {
        cm_close_file(file);
        CT_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_SET, errno);
        return CT_ERROR;
    }

    if (cm_read_file(file, buf, (int32)file_size, buf_size) != CT_SUCCESS) {
        cm_close_file(file);
        CT_LOG_RUN_ERR("failed to read data from file");
        cms_exec_exit_proc();
        return CT_ERROR;
    }

    cm_close_file(file);
    return CT_SUCCESS;
}

status_t cms_import_gcc(const char* path)
{
    char* buf = NULL;
    int32 buf_len = 0;
    cms_gcc_t* new_gcc = NULL;
    errno_t ret;

    CT_RETURN_IFERR(cms_load_gcc());

    buf = (char *)malloc(CMS_MAX_IMP_FILE_SIZE);
    if (buf == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)CMS_MAX_IMP_FILE_SIZE, "loading import file");
        return CT_ERROR;
    }
    ret = memset_sp(buf, CMS_MAX_IMP_FILE_SIZE, 0, CMS_MAX_IMP_FILE_SIZE);
    if (ret != EOK) {
        CM_FREE_PTR(buf);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    if (cms_import_gcc_read_file(path, buf, &buf_len) != CT_SUCCESS) {
        CM_FREE_PTR(buf);
        CMS_LOG_ERR("read file failed, path:%s, buf_len(%u)", path, buf_len);
        return CT_ERROR;
    }

    new_gcc = (cms_gcc_t *)cm_malloc_align(CMS_BLOCK_SIZE, sizeof(cms_gcc_t));
    if (new_gcc == NULL) {
        CM_FREE_PTR(buf);
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(cms_gcc_t), "loading import file");
        return CT_ERROR;
    }
    ret = memset_sp(new_gcc, sizeof(cms_gcc_t), 0, sizeof(cms_gcc_t));
    if (ret != EOK) {
        CM_FREE_PTR(new_gcc);
        CM_FREE_PTR(buf);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    if (cms_import_gcc_parse_text(new_gcc, buf, (uint32)buf_len) != CT_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        CM_FREE_PTR(buf);
        CMS_LOG_ERR("parse import file failed");
        return CT_ERROR;
    }
    CM_FREE_PTR(buf);

    if (cms_gcc_write_disk(new_gcc) != CT_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        CMS_LOG_ERR("write gcc failed");
        return CT_ERROR;
    }

    CM_FREE_PTR(new_gcc);
    return CT_SUCCESS;
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
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(cms_gcc_t), "restoring gcc");
        return CT_ERROR;
    }
    ret = memset_sp(new_gcc, sizeof(cms_gcc_t), 0, sizeof(cms_gcc_t));
    if (ret != EOK) {
        CM_FREE_PTR(new_gcc);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    if (cm_open_disk(file_name, &handle) != CT_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        CT_THROW_ERROR(ERR_OPEN_FILE, file_name, errno);
        CMS_LOG_ERR("open disk failed, fileName(%s)", file_name);
        return CT_ERROR;
    }
    if (cm_get_disk_size(handle) != (int64)sizeof(cms_gcc_t)) {
        CMS_LOG_ERR("get size failed, size(%llu), need_size(%u)", cm_get_disk_size(handle), (uint32)sizeof(cms_gcc_t));
        CM_FREE_PTR(new_gcc);
        cm_close_disk(handle);
        CT_THROW_ERROR(ERR_CMS_GCC_VERSION_MISMATCH, "this binary backup file");
        return CT_ERROR;
    }
    if (cm_read_disk(handle, 0, (char *)new_gcc, sizeof(cms_gcc_t)) != CT_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        cm_close_disk(handle);
        CMS_LOG_ERR("read disk failed. fileName(%s)", file_name);
        return CT_ERROR;
    }
    cm_close_disk(handle);
    if (new_gcc->head.magic != CMS_GCC_HEAD_MAGIC) {
        CM_FREE_PTR(new_gcc);
        CMS_LOG_ERR("gcc is invalid.");
        return CT_ERROR;
    }

    if (cms_gcc_write_disk(new_gcc) != CT_SUCCESS) {
        CM_FREE_PTR(new_gcc);
        CMS_LOG_ERR("write disk failed. fileName(%s)", file_name);
        return CT_ERROR;
    }

    CM_FREE_PTR(new_gcc);
    return CT_SUCCESS;
}
