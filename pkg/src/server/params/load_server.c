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
 * load_server.c
 *
 *
 * IDENTIFICATION
 * src/server/params/load_server.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_module.h"
#include "srv_instance.h"
#include "srv_param_common.h"
#include "load_server.h"
#include "mes_config.h"
#include "dtc_context.h"
#include "dtc_dls.h"
#include "srv_mq.h"
#include "tse_inst.h"
#include "knl_temp.h"
#include "cm_io_record.h"
#include "cm_kmc.h"
#include "cm_log.h"
#include "cm_file_iofence.h"
#include "kmc_init.h"

extern bool32 g_enable_fdsa;
extern bool32 g_crc_verify;
uint32 g_shm_memory_reduction_ratio;
#ifdef __cplusplus
extern "C" {
#endif

void srv_check_file_errno(void)
{
    if (errno == EMFILE || errno == ENFILE) {
        CT_LOG_ALARM(WARN_FILEDESC, "'instance-name':'%s'}", g_instance->kernel.instance_name);
    }
}

static status_t verify_log_path_permission(uint16 permission)
{
    uint16 num = permission;
    uint16 usr_perm;
    uint16 grp_perm;
    uint16 oth_perm;

    usr_perm = (num / 100) % 10;
    grp_perm = (num / 10) % 10;
    oth_perm = num % 10;

    if (usr_perm > CT_MAX_LOG_USER_PERMISSION || grp_perm > CT_MAX_LOG_USER_PERMISSION ||
        oth_perm > CT_MAX_LOG_USER_PERMISSION) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_LOG_PATH_PERMISSIONS");
        return CT_ERROR;
    }

    if (num < CT_DEF_LOG_PATH_PERMISSIONS || num > CT_MAX_LOG_PERMISSIONS) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "_LOG_PATH_PERMISSIONS", (int64)CT_DEF_LOG_PATH_PERMISSIONS,
            (int64)CT_MAX_LOG_PERMISSIONS);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t verify_log_file_permission(uint16 permission)
{
    uint16 num = permission;
    uint16 usr_perm;
    uint16 grp_perm;
    uint16 oth_perm;

    usr_perm = (num / 100) % 10;
    grp_perm = (num / 10) % 10;
    oth_perm = num % 10;

    if (usr_perm > CT_MAX_LOG_USER_PERMISSION || grp_perm > CT_MAX_LOG_USER_PERMISSION ||
        oth_perm > CT_MAX_LOG_USER_PERMISSION) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_LOG_FILE_PERMISSIONS");
        return CT_ERROR;
    }

    if (num < CT_DEF_LOG_FILE_PERMISSIONS || num > CT_MAX_LOG_PERMISSIONS) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "_LOG_FILE_PERMISSIONS", (int64)CT_DEF_LOG_PATH_PERMISSIONS,
            (int64)CT_MAX_LOG_PERMISSIONS);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t srv_init_loggers(void)
{
    char file_name[CT_FILE_NAME_BUFFER_SIZE] = { '\0' };
    cm_log_allinit();
    log_param_t *log_param = cm_log_param_instance();
    log_file_handle_t *log_file_handle = cm_log_logger_file(LOG_ALARM);

    MEMS_RETURN_IFERR(strcpy_sp(log_param->instance_name, CT_MAX_NAME_LEN, g_instance->kernel.instance_name));

    PRTS_RETURN_IFERR(snprintf_s(file_name, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN, "%s/run/%s",
        log_param->log_home, "cantiand.rlog"));
    cm_log_init(LOG_RUN, file_name);

    PRTS_RETURN_IFERR(snprintf_s(file_name, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN, "%s/debug/%s",
        log_param->log_home, "cantiand.dlog"));
    cm_log_init(LOG_DEBUG, file_name);

    PRTS_RETURN_IFERR(snprintf_s(file_name, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN, "%s/audit/%s",
        log_param->log_home, "cantiand.aud"));
    cm_log_init(LOG_AUDIT, file_name);

    PRTS_RETURN_IFERR(snprintf_s(file_name, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN, "%s/%s_alarm.log",
        g_instance->kernel.alarm_log_dir, g_instance->kernel.instance_name));
    cm_log_init(LOG_ALARM, file_name);

    cm_log_open_file(log_file_handle);
    CT_LOG_RUN_FILE_INF(CT_TRUE, "[LOG] file '%s' is added", log_file_handle->file_name);

#ifndef WIN32
    PRTS_RETURN_IFERR(snprintf_s(file_name, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN, "%s/raft/%s",
        log_param->log_home, "cantiand.raft"));
    cm_log_init(LOG_RAFT, file_name);
#endif

    PRTS_RETURN_IFERR(snprintf_s(file_name, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN, "%s/longsql/%s",
        log_param->log_home, "cantiand.lsql"));
    cm_log_init(LOG_LONGSQL, file_name);

    PRTS_RETURN_IFERR(snprintf_s(file_name, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN, "%s/opt/%s",
        log_param->log_home, "cantiand.opt"));
    cm_log_init(LOG_OPTINFO, file_name);

#ifndef WIN32
    PRTS_RETURN_IFERR(snprintf_s(file_name, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN, "%s/blackbox/%s",
        log_param->log_home, "cantiand.blog"));
    cm_log_init(LOG_BLACKBOX, file_name);
#endif

    g_check_file_error = &srv_check_file_errno;

    if (g_instance->sql_style == SQL_STYLE_CT) {
        cm_init_error_handler(cm_set_sql_error);
    }

    log_file_handle = cm_log_logger_file(LOG_TRACE);
    PRTS_RETURN_IFERR(snprintf_s(file_name, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN,
        "%s/trc/cantiand_smon_%05u.trc", g_instance->home, (uint32)SESSION_ID_SMON));

    cm_log_init(LOG_TRACE, file_name);
    cm_log_open_file(log_file_handle);

    sql_auditlog_init(&(log_param->audit_param));

    return CT_SUCCESS;
}

static status_t verify_als_file_dir(char *file_path)
{
    if (!cm_dir_exist(file_path)) {
        CT_THROW_ERROR(ERR_PATH_NOT_EXIST, file_path);
        return CT_ERROR;
    }
    char path[CT_FILE_NAME_BUFFER_SIZE] = { 0x00 };
    CT_RETURN_IFERR(realpath_file(file_path, path, CT_FILE_NAME_BUFFER_SIZE));
    if (access(path, W_OK | R_OK) != 0) {
        CT_THROW_ERROR(ERR_PATH_NOT_ACCESSABLE, file_path);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t srv_get_log_params_core(log_param_t *log_param)
{
    uint16 val_uint16;

    CT_RETURN_IFERR(srv_get_param_uint32("_LOG_BACKUP_FILE_COUNT", &log_param->log_backup_file_count));
    if (log_param->log_backup_file_count > CT_MAX_LOG_FILE_COUNT) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_LOG_BACKUP_FILE_COUNT");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("_AUDIT_BACKUP_FILE_COUNT", &log_param->audit_backup_file_count));
    if (log_param->audit_backup_file_count > CT_MAX_LOG_FILE_COUNT) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_AUDIT_BACKUP_FILE_COUNT");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_size_uint64("_LOG_MAX_FILE_SIZE", &log_param->max_log_file_size));
    if ((log_param->max_log_file_size < CT_MIN_LOG_FILE_SIZE) ||
        (log_param->max_log_file_size > CT_MAX_LOG_FILE_SIZE)) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_LOG_MAX_FILE_SIZE");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_size_uint64("_AUDIT_MAX_FILE_SIZE", &log_param->max_audit_file_size));
    if ((log_param->max_audit_file_size < CT_MIN_LOG_FILE_SIZE) ||
        (log_param->max_audit_file_size > CT_MAX_LOG_FILE_SIZE)) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_AUDIT_MAX_FILE_SIZE");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_size_uint64("MAX_PBL_FILE_SIZE", &log_param->max_pbl_file_size));
    if ((log_param->max_pbl_file_size < CT_MIN_PBL_FILE_SIZE) ||
        (log_param->max_pbl_file_size > CT_MAX_PBL_FILE_SIZE)) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "PBL_MAX_FILE_SIZE");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("_LOG_LEVEL", &log_param->log_level));
    if (log_param->log_level > MAX_LOG_LEVEL && log_param->log_level != LOG_FATAL_LEVEL) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_LOG_LEVEL");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint16("_LOG_FILE_PERMISSIONS", &val_uint16));
    CT_RETURN_IFERR(verify_log_file_permission(val_uint16));
    cm_log_set_file_permissions(val_uint16);

    CT_RETURN_IFERR(srv_get_param_uint16("_LOG_PATH_PERMISSIONS", &val_uint16));
    CT_RETURN_IFERR(verify_log_path_permission(val_uint16));
    cm_log_set_path_permissions(val_uint16);

    // must do it after load all log params, SQL_COMPAT and INSTANCE_NAME
    CT_RETURN_IFERR(srv_init_loggers());

    return CT_SUCCESS;
}

static status_t srv_get_log_params_extra(log_param_t *log_param, bool32 *log_cfg)
{
    char *value = NULL;
    uint32 val_len;

    CT_RETURN_IFERR(srv_get_param_uint32("AUDIT_LEVEL", &log_param->audit_param.audit_level));
    if (log_param->audit_param.audit_level > DDL_AUDIT_ALL) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "AUDIT_LEVEL");
        return CT_ERROR;
    }

    value = srv_get_param("AUDIT_TRAIL_MODE");
    CT_RETURN_IFERR(sql_parse_audit_trail_mode(value, &(log_param->audit_param.audit_trail_mode)));
    value = srv_get_param("AUDIT_SYSLOG_LEVEL");
    CT_RETURN_IFERR(sql_parse_audit_syslog(value, &(log_param->audit_param)));

    value = srv_get_param("LOG_HOME");
    val_len = (uint32)strlen(value);
    if (val_len >= CT_MAX_LOG_HOME_LEN) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "LOG_HOME");
        return CT_ERROR;
    } else if (val_len > 0) {
        MEMS_RETURN_IFERR(strncpy_s(log_param->log_home, CT_MAX_PATH_BUFFER_SIZE, value, CT_MAX_LOG_HOME_LEN));
        *log_cfg = CT_TRUE;
    } else {
        PRTS_RETURN_IFERR(
            snprintf_s(log_param->log_home, CT_MAX_PATH_BUFFER_SIZE, CT_MAX_PATH_LEN, "%s/log", g_instance->home));
    }
    return CT_SUCCESS;
}

static status_t srv_get_log_params(void)
{
    char *value = NULL;
    uint32 val_len;
    bool32 alarm_log_cfg = CT_FALSE;
    bool32 log_cfg = CT_FALSE;
    log_param_t *log_param = cm_log_param_instance();

    CT_RETURN_IFERR(srv_get_param_uint32("_BLACKBOX_STACK_DEPTH", &g_instance->attr.black_box_depth));
    if (g_instance->attr.black_box_depth > CT_MAX_BLACK_BOX_DEPTH) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_BLACKBOX_STACK_DEPTH");
        return CT_ERROR;
    }
    if (g_instance->attr.black_box_depth < CT_INIT_BLACK_BOX_DEPTH) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_BLACKBOX_STACK_DEPTH");
        return CT_ERROR;
    }

    value = srv_get_param("ALARM_LOG_DIR");
    val_len = (uint32)strlen(value);
    if (val_len >= CT_MAX_LOG_HOME_LEN) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "ALARM_LOG_DIR");
        return CT_ERROR;
    }
    if (val_len != 0) {
        MEMS_RETURN_IFERR(
            strncpy_s(g_instance->kernel.alarm_log_dir, CT_MAX_PATH_BUFFER_SIZE, value, CT_MAX_LOG_HOME_LEN));
        alarm_log_cfg = CT_TRUE;
    } else {
        PRTS_RETURN_IFERR(snprintf_s(g_instance->kernel.alarm_log_dir, CT_MAX_PATH_BUFFER_SIZE, CT_MAX_PATH_LEN,
            "%s/log", g_instance->home));
    }

    CT_RETURN_IFERR(srv_get_log_params_extra(log_param, &log_cfg));
    CT_RETURN_IFERR(srv_get_log_params_core(log_param));

    // srv_init_loggers has tryed to create the dir of the LOG_HOME and ALARM_LOG_DIR
    // read LOG_HOME from cfg, check it
    if (log_cfg && verify_als_file_dir(log_param->log_home) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "LOG_HOME");
        printf("%s\n", "Failed to check param:LOG_HOME");
        return CT_ERROR;
    }
    // read ALARM_LOG_DIR from cfg, check it
    if (alarm_log_cfg && verify_als_file_dir(g_instance->kernel.alarm_log_dir) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "ALARM_LOG_DIR");
        printf("%s\n", "Failed to check param:ALARM_LOG_DIR");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t srv_load_max_allowed_packet(void)
{
    int64 max_allowed_packet_size = 0;
    if (cm_str2size(srv_get_param("MAX_ALLOWED_PACKET"), &max_allowed_packet_size) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "MAX_ALLOWED_PACKET");
        return CT_ERROR;
    }
    if (max_allowed_packet_size < CT_MAX_PACKET_SIZE || max_allowed_packet_size > CT_MAX_ALLOWED_PACKET_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "MAX_ALLOWED_PACKET", SIZE_K(96), SIZE_M(64));
        return CT_ERROR;
    }
    g_instance->attr.max_allowed_packet = (uint32)max_allowed_packet_size;
    return CT_SUCCESS;
}

static status_t srv_get_param_dbtimezone(timezone_info_t *dbtimezone)
{
    char *value = srv_get_param("DB_TIMEZONE");
    text_t text;
    timezone_info_t tz;

    text.str = value;
    text.len = (uint32)strlen(value);
    if (cm_text2tzoffset(&text, &tz) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "DB_TIMEZONE");
        return CT_ERROR;
    }

    *dbtimezone = tz;
    return CT_SUCCESS;
}

static status_t srv_keyfile_config_prepare(knl_attr_t *attr)
{
    text_t name;
    uint32 idx = 0;

    errno_t ret = snprintf_s(attr->kmc_key_files[idx].name, CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1,
        "%s/protect/%s", g_instance->home, CT_KMC_FILENAMEA);
    knl_securec_check_ss(ret);
    cm_str2text(attr->kmc_key_files[idx].name, &name);
    cm_convert_os_path(&name);
    idx++;

    if (idx > CT_KMC_MAX_KEYFILE_NUM) {
        CT_LOG_RUN_ERR("[LOAD KMC KEYFILES ERROR]key idx more than CT_MAX_KEYFILE_NUM.");
        return CT_ERROR;
    }
    ret = snprintf_s(attr->kmc_key_files[idx].name, CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1,
        "%s/protect/%s", g_instance->home, CT_KMC_FILENAMEB);
    knl_securec_check_ss(ret);
    cm_str2text(attr->kmc_key_files[idx].name, &name);
    cm_convert_os_path(&name);
    return CT_SUCCESS;
}

static status_t srv_parse_keyfiles(text_t *value, char **files)
{
    text_t name;
    uint32 idx = 0;
    errno_t ret;
    while (CT_TRUE) {
        if (!cm_fetch_text(value, ',', '\0', &name)) {
            break;
        }

        if (idx == CT_KMC_MAX_KEYFILE_NUM) {
            CT_THROW_ERROR(ERR_INVALID_PARAMETER, "KMC_KEY_FILES");
            return CT_ERROR;
        }

        cm_trim_text(&name);
        if (name.str[0] == '\'') {
            name.str++;
            name.len -= CM_SINGLE_QUOTE_LEN;
            cm_trim_text(&name);
        }

        cm_convert_os_path(&name);
        ret = snprintf_s(files[idx], CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1, "%s", T2S(&name));
        knl_securec_check_ss(ret);
        idx++;
    }

    return CT_SUCCESS;
}

static status_t srv_update_keyfiles_config(knl_attr_t *attr)
{
    char buf[CT_MAX_CONFIG_LINE_SIZE] = { 0 };
    text_t file_list = {
        .len = 0,
        .str = buf
    };
    text_t file_name;

    if (cm_concat_string(&file_list, CT_MAX_CONFIG_LINE_SIZE, "(") != CT_SUCCESS) {
        return CT_ERROR;
    }

    for (uint32 i = 0; i < CT_KMC_MAX_KEYFILE_NUM; i++) {
        cm_str2text(attr->kmc_key_files[i].name, &file_name);
        cm_concat_text(&file_list, CT_MAX_CONFIG_LINE_SIZE, &file_name);
        if (i != CT_KMC_MAX_KEYFILE_NUM - 1) {
            if (cm_concat_string(&file_list, CT_MAX_CONFIG_LINE_SIZE, ", ") != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }

    if (cm_concat_string(&file_list, CT_MAX_CONFIG_LINE_SIZE, ")\0") != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cm_alter_config(&g_instance->config, "KMC_KEY_FILES", buf, CONFIG_SCOPE_MEMORY, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t srv_init_kmc(void)
{
    uint32 domain;
    CT_RETURN_IFERR(kmc_init_lib());
    CT_RETURN_IFERR(sdp_init_lib());
    knl_attr_t *attr = &g_instance->kernel.attr;
    if (cm_kmc_init(CT_SERVER, attr->kmc_key_files[0].name, attr->kmc_key_files[1].name) != CT_SUCCESS) {
        return CT_ERROR;
    }

    for (domain = CT_KMC_DOMAIN_BEGIN + 1; domain < CT_KMC_DOMAIN_END; domain++) {
        if (cm_kmc_init_domain(domain) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t srv_create_keyfiles_path(void)
{
    knl_attr_t *attr = &g_instance->kernel.attr;
    char path[CT_MAX_FILE_PATH_LENGH];
    uint32 idx;

    for (idx = 0; idx < CT_KMC_MAX_KEYFILE_NUM; idx++) {
        cm_trim_filename(attr->kmc_key_files[idx].name, CT_MAX_FILE_PATH_LENGH, path);
        if (!cm_dir_exist(path)) {
            if (cm_create_dir(path) != CT_SUCCESS) {
                CT_LOG_RUN_ERR("failed to create keyfile dir %s,check if parent dir exist.error code %d", path, errno);
                return CT_ERROR;
            }
        }
    }

    return srv_init_kmc();
}

static status_t srv_load_keyfiles(void)
{
    uint32 idx;
    text_t files;
    knl_attr_t *attr = &g_instance->kernel.attr;
    char *value = srv_get_param("KMC_KEY_FILES");
    char *key_files[CT_KMC_MAX_KEYFILE_NUM];

    if (CM_IS_EMPTY_STR(value)) {
        if (srv_keyfile_config_prepare(attr) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        cm_str2text(value, &files);
        cm_remove_brackets(&files);

        for (idx = 0; idx < CT_KMC_MAX_KEYFILE_NUM; idx++) {
            key_files[idx] = attr->kmc_key_files[idx].name;
        }

        if (srv_parse_keyfiles(&files, key_files) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (srv_update_keyfiles_config(attr) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return srv_create_keyfiles_path();
}

static status_t srv_generate_factor_key(char *file_name1, char *file_name2, char *factor_key, uint32 flen)
{
    char *value = srv_get_param("_FACTOR_KEY");
    if (value[0] == '\0') {
        char rand_buf[CT_AESBLOCKSIZE + 1];
        uint32 rand_len = CT_AESBLOCKSIZE;
        /* generate 128bit rand_buf and then base64 encode */
        CT_RETURN_IFERR(cm_rand((uchar *)rand_buf, rand_len));
        CT_RETURN_IFERR(cm_base64_encode((uchar *)rand_buf, rand_len, factor_key, &flen));
    } else {
        MEMS_RETURN_IFERR(strncpy_s(factor_key, CT_MAX_FACTOR_KEY_STR_LEN + 1, value, strlen(value)));
    }
    CT_RETURN_IFERR(srv_save_factor_key_file(file_name1, factor_key));
    CT_RETURN_IFERR(srv_save_factor_key_file(file_name2, factor_key));
    return CT_SUCCESS;
}

static status_t srv_load_factor_key_file(const char *file_name, char *key_buf, uint32 key_len)
{
    status_t ret;
    int32 handle, file_size;
    uchar file_buf[CT_AESBLOCKSIZE + CT_HMAC256MAXSIZE + 4];
    uchar cipher[CT_HMAC256MAXSTRSIZE + 4];
    uint32 cipher_len;

    CT_RETURN_IFERR(cm_open_file_ex(file_name, O_SYNC | O_RDONLY | O_BINARY, S_IRUSR, &handle));
    ret = cm_read_file(handle, file_buf, sizeof(file_buf), &file_size);
    cm_close_file(handle);
    CT_RETURN_IFERR(ret);

    if (file_size < CT_AESBLOCKSIZE + CT_HMAC256MAXSIZE) {
        CT_LOG_RUN_ERR("key file is invalid");
        return CT_ERROR;
    }
    file_size -= CT_AESBLOCKSIZE;

    // verify hmac
    cipher_len = sizeof(cipher);
    CT_RETURN_IFERR(
        cm_encrypt_HMAC(file_buf, CT_AESBLOCKSIZE, file_buf, CT_AESBLOCKSIZE, (uchar *)cipher, &cipher_len));

    if ((uint32)file_size != cipher_len || 0 != memcmp(cipher, (file_buf + CT_AESBLOCKSIZE), cipher_len)) {
        CT_LOG_RUN_ERR("verify key failed");
        return CT_ERROR;
    }
    return cm_base64_encode((uchar *)file_buf, CT_AESBLOCKSIZE, key_buf, &key_len);
}

static status_t srv_load_factor_key(void)
{
    char *value = NULL;
    char file_name1[CT_FILE_NAME_BUFFER_SIZE];
    char file_name2[CT_FILE_NAME_BUFFER_SIZE];
    char dbs_dir[CT_FILE_NAME_BUFFER_SIZE];
    char factor_key[CT_MAX_FACTOR_KEY_STR_LEN + 1];
    char work_key[CT_MAX_LOCAL_KEY_STR_LEN_DOUBLE + 1];

    PRTS_RETURN_IFERR(
        snprintf_s(dbs_dir, CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1, "%s/dbs/", g_instance->home));
    PRTS_RETURN_IFERR(snprintf_s(file_name1, CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1, "%s/dbs/%s",
        g_instance->home, CT_FKEY_FILENAME1));
    PRTS_RETURN_IFERR(snprintf_s(file_name2, CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1, "%s/dbs/%s",
        g_instance->home, CT_FKEY_FILENAME2));

    if (!cm_dir_exist(dbs_dir)) {
        if (cm_create_dir(dbs_dir) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("unable to create directory %s", dbs_dir);
            return CT_ERROR;
        }
    }

    if (access(file_name1, R_OK | F_OK) == 0) {
        if (CT_SUCCESS != srv_load_factor_key_file(file_name1, factor_key, sizeof(factor_key))) {
            CT_RETURN_IFERR(srv_load_factor_key_file(file_name2, factor_key, sizeof(factor_key)));
            CT_RETURN_IFERR(srv_save_factor_key_file(file_name1, factor_key));
        }
    } else if (access(file_name2, R_OK | F_OK) == 0) {
        CT_RETURN_IFERR(srv_load_factor_key_file(file_name2, factor_key, sizeof(factor_key)));
        CT_RETURN_IFERR(srv_save_factor_key_file(file_name1, factor_key));
    } else {
        // generate factor key
        CT_RETURN_IFERR(srv_generate_factor_key(file_name1, file_name2, factor_key, CT_MAX_FACTOR_KEY_STR_LEN + 1));
    }
    CT_RETURN_IFERR(cm_alter_config(&g_instance->config, "_FACTOR_KEY", factor_key, CONFIG_SCOPE_MEMORY, CT_TRUE));

    // verify local key
    value = srv_get_param("LOCAL_KEY");
    if (value[0] == '\0') {
        CT_RETURN_IFERR(cm_generate_work_key(factor_key, work_key, sizeof(work_key)));
        CT_RETURN_IFERR(cm_alter_config(&g_instance->config, "LOCAL_KEY", work_key, CONFIG_SCOPE_BOTH, CT_TRUE));
    } else if (strlen(value) != CT_MAX_LOCAL_KEY_STR_LEN_DOUBLE) {
        CT_LOG_RUN_ERR("LOCAL_KEY is invalid");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}
void shm_set_thread_cool_time(uint32_t time_us);
static status_t srv_get_mq_cfg(mq_cfg_s *cfg)
{
    uint32_t msg_thd_num;
    CT_RETURN_IFERR(srv_get_param_uint32("SHM_MQ_MSG_RECV_THD_NUM", &msg_thd_num));
    if (msg_thd_num > (uint32_t)CT_MQ_MAX_THD_NUM || msg_thd_num < (uint32_t)CT_MQ_MIN_THD_NUM) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "SHM_MQ_MSG_RECV_THD_NUM", (long long)CT_MQ_MIN_THD_NUM,
            (long long)CT_MQ_MAX_THD_NUM);
        return CT_ERROR;
    };
    cfg->num_msg_recv_thd = msg_thd_num;

    uint32_t msg_queue_num;
    CT_RETURN_IFERR(srv_get_param_uint32("SHM_MQ_MSG_QUEUE_NUM", &msg_queue_num));
    if (msg_queue_num > (uint32_t)CT_MQ_MAX_QUEUE_NUM || msg_queue_num < (uint32_t)CT_MQ_MIN_QUEUE_NUM) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "SHM_MQ_MSG_QUEUE_NUM", (long long)CT_MQ_MIN_QUEUE_NUM,
            (long long)CT_MQ_MAX_QUEUE_NUM);
        return CT_ERROR;
    };
    cfg->num_msg_queue = msg_queue_num;

    uint32_t cool_time = 0;
    CT_RETURN_IFERR(srv_get_param_uint32("SHM_MQ_MSG_THD_COOL_TIME_US", &cool_time));
    if (cool_time > (uint32_t)CT_MQ_MAX_COOL_TIME || cool_time < (uint32_t)CT_MQ_MIN_COOL_TIME) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "SHM_MQ_MSG_THD_COOL_TIME_US", (long long)CT_MQ_MIN_COOL_TIME,
            (long long)CT_MQ_MAX_COOL_TIME);
        return CT_ERROR;
    };
    shm_set_thread_cool_time(cool_time);

    uint32_t mysql_deploy_group_id;
    CT_RETURN_IFERR(srv_get_param_uint32("MYSQL_DEPLOY_GROUP_ID", &mysql_deploy_group_id));
    cfg->mysql_deploy_group_id = mysql_deploy_group_id;

    return CT_SUCCESS;
}

status_t srv_load_server_params(void)
{
    session_pool_t *session_pool = NULL;
    reactor_pool_t *reactor_pool = NULL;
    sql_emerg_pool_t *emerg_pool = NULL;
    uint16 job_process_count;
    timezone_info_t dbtimezone = TIMEZONE_OFFSET_DEFAULT;
    log_param_t *log_param = cm_log_param_instance();
    mq_cfg_s *mq_cfg = get_global_mq_cfg();
    char *cpu_info = get_global_mq_cpu_info();
    char *mysql_cpu_info = get_global_mq_mysql_cpu_info();
    uint32_t *ctc_max_inst_num = get_ctc_max_inst_num();

    // only support the ctdb engine
    g_instance->sql_style = SQL_STYLE_CT;
    dls_init_spinlock(&g_instance->dblink_lock, DR_TYPE_DATABASE, DR_ID_DATABASE_LINK, 0);

    const char *value = srv_get_param("INSTANCE_NAME");
    session_pool = &g_instance->session_pool;
    reactor_pool = &g_instance->reactor_pool;
    emerg_pool = &g_instance->sql_emerg_pool;

    MEMS_RETURN_IFERR(strncpy_s(g_instance->kernel.instance_name, CT_MAX_NAME_LEN, value, strlen(value)));

    CT_RETURN_IFERR(srv_get_mq_cfg(mq_cfg));
    char *cpu_info_param = srv_get_param("SHM_CPU_GROUP_INFO");
    CT_PRINT_IFERR(memcpy_s(cpu_info, CPU_INFO_STR_SIZE, cpu_info_param, strlen(cpu_info_param) + 1),
                   "SHM_CPU_GROUP_INFO", CPU_INFO_STR_SIZE - 1);
    char *mysql_cpu_info_param = srv_get_param("SHM_MYSQL_CPU_GROUP_INFO");
    CT_PRINT_IFERR(memcpy_s(mysql_cpu_info, CPU_INFO_STR_SIZE, mysql_cpu_info_param, strlen(mysql_cpu_info_param) + 1),
                   "SHM_MYSQL_CPU_GROUP_INFO", CPU_INFO_STR_SIZE - 1);

    uint32_t max_inst_num = 0;
    CT_RETURN_IFERR(srv_get_param_uint32("CTC_MAX_INST_PER_NODE", &max_inst_num));
    if (max_inst_num > (uint32_t)CT_CTC_MAX_INST_NUM || max_inst_num < (uint32_t)CT_CTC_MIN_INST_NUM) {
        CT_THROW_ERROR(ERR_PARAMETER_OVER_RANGE, "CTC_MAX_INST_PER_NODE", (long long)CT_CTC_MIN_INST_NUM,
            (long long)CT_CTC_MAX_INST_NUM);
        return CT_ERROR;
    };
    *ctc_max_inst_num = max_inst_num;

    CT_RETURN_IFERR(srv_get_log_params());

    log_param->log_instance_startup = CT_TRUE;
    g_instance->kernel.reserved_sessions = CT_SYS_SESSIONS;

    value = srv_get_param("LSNR_ADDR");
    if (cm_verify_lsnr_addr(value, (uint32)strlen(value), NULL) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "LSNR_ADDR");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(cm_split_host_ip(g_instance->lsnr.tcp_service.host, value));

    value = srv_get_param("REPL_ADDR");
    if (strlen(value) > 0) {
        // if REPL_ADDR is configured, use it
        if (cm_verify_lsnr_addr(value, (uint32)strlen(value), NULL) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_INVALID_PARAMETER, "REPL_ADDR");
            return CT_ERROR;
        }

        CT_RETURN_IFERR(cm_split_host_ip(g_instance->lsnr.tcp_replica.host, value));
    } else {
        // else use LSNR_ADDR
        value = srv_get_param("LSNR_ADDR");
        CT_RETURN_IFERR(cm_split_host_ip(g_instance->lsnr.tcp_replica.host, value));
    }

    CT_RETURN_IFERR(srv_get_param_uint16("LSNR_PORT", &g_instance->lsnr.tcp_service.port));
    if (g_instance->lsnr.tcp_service.port < CT_MIN_PORT) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "LSNR_PORT", (int64)CT_MIN_PORT);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint16("REPL_PORT", &g_instance->lsnr.tcp_replica.port));
    if ((g_instance->lsnr.tcp_replica.port < CT_MIN_PORT) && (g_instance->lsnr.tcp_replica.port != 0)) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "REPL_PORT");
        return CT_ERROR;
    }

    /* uds communication mode, g_instance->lsnr.uds_service.names[0] for emerg session */
    PRTS_RETURN_IFERR(snprintf_s(g_instance->lsnr.uds_service.names[0], CT_UNIX_PATH_MAX, CT_UNIX_PATH_MAX - 1,
        "%s/protect/%s", g_instance->home, CTDB_UDS_EMERG_SERVER));

    char protect_dir[CT_FILE_NAME_BUFFER_SIZE];
    PRTS_RETURN_IFERR(snprintf_s(protect_dir, CT_FILE_NAME_BUFFER_SIZE, CT_FILE_NAME_BUFFER_SIZE - 1, "%s/protect/",
        g_instance->home));

    if (!cm_dir_exist(protect_dir)) {
        if (cm_create_dir(protect_dir) != CT_SUCCESS) {
            CT_LOG_RUN_ERR("[Privilege] failed to create dir %s", protect_dir);
            return CT_ERROR;
        }
    }

    char realfile[CT_UNIX_PATH_MAX];
    CT_RETURN_IFERR(realpath_file(g_instance->lsnr.uds_service.names[0], realfile, CT_UNIX_PATH_MAX));
    if (cm_file_exist((const char *)realfile)) {
        CT_RETURN_IFERR(cm_remove_file((const char *)realfile));
    }

    value = srv_get_param("UDS_FILE_PATH");
    if (strlen(value) != 0) {
        if (strlen(value) >= CT_UNIX_PATH_MAX) {
            CT_THROW_ERROR(ERR_INVALID_FILE_NAME, value, CT_UNIX_PATH_MAX);
            return CT_ERROR;
        }

        CT_RETURN_IFERR(realpath_file(value, realfile, CT_UNIX_PATH_MAX));
        if (cm_file_exist((const char *)realfile)) {
            CT_RETURN_IFERR(cm_remove_file((const char *)realfile));
        }

        CT_RETURN_IFERR(verify_uds_file_path(value));
        PRTS_RETURN_IFERR(
            snprintf_s(g_instance->lsnr.uds_service.names[1], CT_UNIX_PATH_MAX, CT_UNIX_PATH_MAX - 1, value));
    }
    uint16 file_perm = 0;
    CT_RETURN_IFERR(srv_get_param_uint16("UDS_FILE_PERMISSIONS", &file_perm));
    if (verify_uds_file_permission(file_perm) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "UDS_FILE_PERMISSIONS");
        return CT_ERROR;
    }

    g_instance->lsnr.uds_service.permissions = cm_file_permissions(file_perm);

    CT_RETURN_IFERR(srv_get_param_uint32("OPTIMIZED_WORKER_THREADS", &g_instance->attr.optimized_worker_count));
    if (g_instance->attr.optimized_worker_count > CT_MAX_OPTIMIZED_WORKER_COUNT ||
        g_instance->attr.optimized_worker_count < CT_MIN_OPTIMIZED_WORKER_COUNT) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "OPTIMIZED_WORKER_COUNT");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("MAX_WORKER_THREADS", &g_instance->attr.max_worker_count));
    if (g_instance->attr.max_worker_count > CT_MAX_OPTIMIZED_WORKER_COUNT) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "MAX_WORKER_THREADS");
        return CT_ERROR;
    }

    if (g_instance->attr.max_worker_count < g_instance->attr.optimized_worker_count) {
        g_instance->attr.max_worker_count = g_instance->attr.optimized_worker_count;
        char new_value[CT_PARAM_BUFFER_SIZE] = { 0 };
        PRTS_RETURN_IFERR(snprintf_s(new_value, CT_PARAM_BUFFER_SIZE, CT_PARAM_BUFFER_SIZE - 1, "%u",
            g_instance->attr.max_worker_count));
        CT_RETURN_IFERR(
            cm_alter_config(&g_instance->config, "MAX_WORKER_THREADS", new_value, CONFIG_SCOPE_BOTH, CT_TRUE));
        CT_RETURN_IFERR(cm_modify_runtimevalue(&g_instance->config, "MAX_WORKER_THREADS", new_value));
    }

    CT_RETURN_IFERR(srv_get_param_dbtimezone(&dbtimezone));
    cm_set_db_timezone(dbtimezone);
    CT_RETURN_IFERR(srv_get_param_uint32("REACTOR_THREADS", &reactor_pool->reactor_count));
    if (reactor_pool->reactor_count == 0 || reactor_pool->reactor_count > CT_MAX_REACTOR_POOL_COUNT) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "REACTOR_THREADS");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("WORKER_THREADS_SHRINK_THRESHOLD", &reactor_pool->agents_shrink_threshold));
    if (g_instance->attr.optimized_worker_count < reactor_pool->reactor_count ||
        g_instance->attr.max_worker_count < reactor_pool->reactor_count) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "REACTOR_THREADS");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("SUPER_USER_RESERVED_SESSIONS", &emerg_pool->max_sessions));
    if (emerg_pool->max_sessions < 1) {
        emerg_pool->max_sessions = 1;
    } else if (emerg_pool->max_sessions >= CT_MAX_EMERG_SESSIONS) {
        emerg_pool->max_sessions = CT_MAX_EMERG_SESSIONS;
    }

    CT_RETURN_IFERR(srv_get_param_double("NORMAL_USER_RESERVED_SESSIONS_FACTOR",
        &g_instance->kernel.attr.normal_emerge_sess_factor));
    if (g_instance->kernel.attr.normal_emerge_sess_factor < 0 ||
        g_instance->kernel.attr.normal_emerge_sess_factor > 1) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "NORMAL_USER_RESERVED_SESSIONS_FACTOR");
        return CT_ERROR;
    }
    CT_RETURN_IFERR(srv_get_param_uint32("SHM_MEMORY_REDUCTION_RATIO", &g_shm_memory_reduction_ratio));
    if (g_shm_memory_reduction_ratio > CT_MAX_SHM_MEMORY_REDUCTION_RATIO || g_shm_memory_reduction_ratio < CT_MIN_SHM_MEMORY_REDUCTION_RATIO) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "SHM_MEMORY_REDUCTION_RATIO");
        return CT_ERROR;
    }
    CT_RETURN_IFERR(srv_get_param_uint32("SESSIONS", &session_pool->max_sessions));
    if (session_pool->max_sessions > CT_MAX_SESSIONS) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "SESSIONS", CT_MAX_SESSIONS);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("PARALLEL_MAX_THREADS", &g_instance->sql_par_pool.max_sessions));
    if (g_instance->sql_par_pool.max_sessions > CT_PARALLEL_MAX_THREADS) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "PARALLEL_MAX_THREADS", CT_PARALLEL_MAX_THREADS);
        return CT_ERROR;
    }

    session_pool->expanded_max_sessions = MIN(CT_MAX_SESSIONS, EXPANDED_SESSIONS(session_pool->max_sessions));
    CT_RETURN_IFERR(srv_get_param_uint32("_PREFETCH_ROWS", &g_instance->sql.prefetch_rows));
    if (g_instance->sql.prefetch_rows < 1) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_PREFETCH_ROWS");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_bool32("ARRAY_STORAGE_OPTIMIZATION", &g_instance->sql.enable_arr_store_opt));
    CT_RETURN_IFERR(
        srv_get_param_size_uint64("_MAX_JSON_DYNAMIC_BUFFER_SIZE", &g_instance->sql.json_mpool.max_json_dyn_buf));
    if (g_instance->sql.json_mpool.max_json_dyn_buf < CT_JSON_MIN_DYN_BUF_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_SMALL, "_MAX_JSON_DYNAMIC_BUFFER_SIZE", CT_JSON_MIN_DYN_BUF_SIZE);
        return CT_ERROR;
    }

    if (g_instance->sql.json_mpool.max_json_dyn_buf > CT_JSON_MAX_DYN_BUF_SIZE) {
        CT_THROW_ERROR(ERR_PARAMETER_TOO_LARGE, "_MAX_JSON_DYNAMIC_BUFFER_SIZE", CT_JSON_MAX_DYN_BUF_SIZE);
        return CT_ERROR;
    }

    value = srv_get_param("_ENCRYPTION_ALG");
    if (cm_str_equal_ins(value, "PBKDF2")) {
        CT_LOG_RUN_WAR("The PBKDF2 encryption algorithm is insecure and has been deprecated, "
            "please use SCRAM_SHA256 instead");

        MEMS_RETURN_IFERR(strncpy_s(g_instance->kernel.attr.pwd_alg, CT_NAME_BUFFER_SIZE, value, strlen(value)));
    } else if (cm_str_equal_ins(value, "SCRAM_SHA256")) {
        MEMS_RETURN_IFERR(strncpy_s(g_instance->kernel.attr.pwd_alg, CT_NAME_BUFFER_SIZE, value, strlen(value)));
    } else {
        CT_LOG_RUN_ERR("_ENCRYPTION_ALG is invalid");
        return CT_ERROR;
    }

    value = srv_get_param("_SYS_PASSWORD");
    if (strlen(value) == CT_KDF2MAXSTRSIZE) {
        if (cm_convert_kdf2_scram_sha256(value, g_instance->kernel.attr.sys_pwd, CT_PASSWORD_BUFFER_SIZE) !=
            CT_SUCCESS) {
            CT_LOG_RUN_ERR("_SYS_PASSWORD is invalid");
            return CT_ERROR;
        }
    } else if (cm_is_password_valid(value)) {
        MEMS_RETURN_IFERR(strcpy_s(g_instance->kernel.attr.sys_pwd, CT_PASSWORD_BUFFER_SIZE, value));
    } else {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_SYS_PASSWORD");
        CT_LOG_RUN_ERR("_SYS_PASSWORD is invalid");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("_ENCRYPTION_ITERATION", &g_instance->kernel.attr.alg_iter));
    if (g_instance->kernel.attr.alg_iter > CT_KDF2MAXITERATION ||
        g_instance->kernel.attr.alg_iter < CT_KDF2MINITERATION) {
        CT_LOG_RUN_ERR("_ENCRYPTION_ITERATION must between %u and %u", CT_KDF2MINITERATION, CT_KDF2MAXITERATION);
        return CT_ERROR;
    }

    if (srv_load_factor_key() != CT_SUCCESS) {
        CT_LOG_RUN_ERR("load or save _FACTOR_KEY failed");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_bool32("ENABLE_SYSDBA_LOGIN", &g_instance->session_pool.enable_sysdba_login));
    CT_RETURN_IFERR(srv_get_param_bool32("ENABLE_SYS_REMOTE_LOGIN", &g_instance->session_pool.enable_sys_remote_login));
    CT_RETURN_IFERR(
        srv_get_param_bool32("ENABLE_SYSDBA_REMOTE_LOGIN", &g_instance->session_pool.enable_sysdba_remote_login));
    CT_RETURN_IFERR(srv_get_param_bool32("COMMIT_ON_DISCONNECT", &g_instance->sql.commit_on_disconn));
    CT_RETURN_IFERR(srv_get_param_uint32("_MAX_CONNECT_BY_LEVEL", &g_instance->sql.max_connect_by_level));
    CT_RETURN_IFERR(srv_get_param_uint32("_INDEX_SCAN_RANGE_CACHE", &g_instance->sql.index_scan_range_cache));
    CT_RETURN_IFERR(srv_get_param_bool32("_OPTIM_VM_VIEW_ENABLED", &g_instance->sql.vm_view_enabled));
    CT_RETURN_IFERR(srv_get_param_bool32("ENABLE_PASSWORD_CIPHER", &g_instance->sql.enable_password_cipher));
    CT_RETURN_IFERR(srv_get_param_uint32("_OPTIM_INDEX_SCAN_MAX_PARTS", &g_instance->sql.optim_index_scan_max_parts));
    CT_RETURN_IFERR(srv_load_max_allowed_packet());
    CT_RETURN_IFERR(srv_get_param_uint32("INTERACTIVE_TIMEOUT", &g_instance->sql.interactive_timeout));
    CT_RETURN_IFERR(srv_get_param_onoff("PARALLEL_POLICY", &g_instance->sql.parallel_policy));
    CT_RETURN_IFERR(srv_get_param_bool32("ZERO_DIVISOR_ACCEPTED", &g_opr_options.div0_accepted));
    CT_RETURN_IFERR(srv_get_param_bool32("STRING_AS_HEX_FOR_BINARY", &g_instance->sql.string_as_hex_binary));
    CT_RETURN_IFERR(
        srv_get_param_uint32("UNAUTH_SESSION_EXPIRE_TIME", &g_instance->session_pool.unauth_session_expire_time));
    CT_RETURN_IFERR(srv_get_param_bool32("ENABLE_ERR_SUPERPOSED", &g_enable_err_superposed));
    CT_RETURN_IFERR(srv_get_param_bool32("EMPTY_STRING_AS_NULL", &g_instance->sql.enable_empty_string_null));

    uint32 temp_difftime = 0;
    CT_RETURN_IFERR(srv_get_param_uint32("MASTER_SLAVE_DIFFTIME", &temp_difftime));
    g_instance->attr.master_slave_difftime = temp_difftime * MILLISECS_PER_SECOND * MICROSECS_PER_MILLISEC;
    value = srv_get_param("TYPE_MAP_FILE");
    g_instance->sql.type_map.do_typemap = CT_FALSE;
    if (strlen(value) != 0) {
        g_instance->sql.type_map.do_typemap = CT_TRUE;
        MEMS_RETURN_IFERR(
            strncpy_s(g_instance->sql.type_map.file_name, CT_FILE_NAME_BUFFER_SIZE, value, strlen(value)));
    }

    CT_RETURN_IFERR(srv_get_param_uint32("_SGA_CORE_DUMP_CONFIG", &g_instance->attr.core_dump_config));
    if (g_instance->attr.core_dump_config > CT_MAX_SGA_CORE_DUMP_CONFIG) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_SGA_CORE_DUMP_CONFIG");
        return CT_ERROR;
    }

    /* Check JOB_QUEUE_PROCESSES is valid */
    CT_RETURN_IFERR(srv_get_param_uint16("JOB_THREADS", &job_process_count));
    if (job_process_count > CT_MAX_JOB_THREADS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "JOB_THREADS");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint64("XA_FORMAT_ID", &g_instance->attr.xa_fmt_id));
    if (g_instance->attr.xa_fmt_id > CT_MAX_INT64) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "XA_FORMAT_ID");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(
        srv_get_param_uint32("_DEADLOCK_DETECT_INTERVAL", &g_instance->kernel.attr.deadlock_detect_interval));
    if (!IS_DEADLOCK_INTERVAL_PARAM_VALID(g_instance->kernel.attr.deadlock_detect_interval)) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_DEADLOCK_DETECT_INTERVAL");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("_AUTO_UNDO_RETENTION", &g_instance->kernel.attr.auto_undo_retention));

    CT_RETURN_IFERR(srv_get_param_uint32("COMPATIBLE_MYSQL", &g_instance->kernel.attr.compatible_mysql));
    CT_RETURN_IFERR(srv_get_param_bool32("ENABLE_HWN_CHANGE", &g_instance->kernel.attr.enable_hwm_change));
    temp_set_compative_config(g_instance->kernel.attr.compatible_mysql == 1 ? CT_TRUE : CT_FALSE);

    bool32 enable_dbstor = CT_FALSE;
    CT_RETURN_IFERR(srv_get_param_bool32("ENABLE_DBSTOR", &enable_dbstor));
    if (enable_dbstor) {
        CT_RETURN_IFERR(srv_load_keyfiles());
    }

    CT_RETURN_IFERR(srv_get_param_bool32("ENABLE_LOCAL_INFILE", &g_instance->attr.enable_local_infile));
    CT_RETURN_IFERR(srv_get_param_bool32("_STRICT_CASE_DATATYPE", &g_instance->sql.strict_case_datatype));
    return CT_SUCCESS;
}

static status_t srv_get_interconnect_type_param(cs_pipe_type_t *type)
{
    char *value;

    value = srv_get_param("INTERCONNECT_TYPE");
    if (cm_str_equal_ins(value, "TCP")) {
        *type = CS_TYPE_TCP;
    } else if (cm_str_equal_ins(value, "UC")) {
        *type = CS_TYPE_UC;
    } else if (cm_str_equal_ins(value, "UC_RDMA")) {
        *type = CS_TYPE_UC_RDMA;
    } else {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "INTERCONNECT_TYPE");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t srv_load_gdv_params(void)
{
    CT_RETURN_IFERR(srv_get_param_uint32("CT_GDV_SQL_SESS_TMOUT", &g_dtc->profile.gdv_sql_sess_tmout));

    return CT_SUCCESS;
}

static status_t srv_get_dbs_cfg(void)
{
    char *value = NULL;
    bool32 enable = CT_FALSE;
    knl_attr_t *attr = &g_instance->kernel.attr;
    uint32 partition_num = attr->dbwr_processes; // partition_num same with dbwr count
    bool32 enable_batch_flush = CT_FALSE;
    CT_RETURN_IFERR(srv_get_param_bool32("ENABLE_DBSTOR", &enable));
    CT_RETURN_IFERR(srv_get_param_bool32("ENABLE_DBSTOR_BATCH_FLUSH", &enable_batch_flush));
    value = srv_get_param("DBSTOR_NAMESPACE");
    return cm_dbs_set_cfg(enable, attr->page_size, CT_DFLT_CTRL_BLOCK_SIZE, value, partition_num, enable_batch_flush);
}

status_t srv_load_cluster_params(void)
{
    knl_attr_t *attr = &g_instance->kernel.attr;
    dtc_attr_t *dtc_attr = &g_instance->kernel.dtc_attr;
    const char *value = NULL;

    CT_RETURN_IFERR(srv_get_param_bool32("CLUSTER_DATABASE", &attr->clustered));

    if (!attr->clustered) {
        dtc_attr->inst_id = 0;
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(srv_get_dbs_cfg());

    value = srv_get_param("INTERCONNECT_ADDR");
    if (cm_verify_lsnr_addr(value, (uint32)strlen(value), NULL) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "INTERCONNECT_ADDR");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(cm_split_node_ip(g_dtc->profile.nodes, value));

    value = srv_get_param("INTERCONNECT_PORT");
    CT_RETURN_IFERR(cm_split_host_port(g_dtc->profile.ports, value));

    CT_RETURN_IFERR(srv_get_interconnect_type_param(&g_dtc->profile.pipe_type));

    CT_RETURN_IFERR(srv_get_param_uint32("INTERCONNECT_CHANNEL_NUM", &g_dtc->profile.channel_num));
    if ((g_dtc->profile.channel_num == 0) || (g_dtc->profile.channel_num > CT_MES_MAX_CHANNEL_NUM)) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "INTERCONNECT_CHANNEL_NUM");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("REACTOR_THREAD_NUM", &g_dtc->profile.reactor_thread_num));
    if ((g_dtc->profile.reactor_thread_num == 0) ||
        (g_dtc->profile.reactor_thread_num > CT_MES_MAX_REACTOR_THREAD_NUM)) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "REACTOR_THREAD_NUM");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("DAAC_TASK_NUM", &g_dtc->profile.task_num));
    if ((g_dtc->profile.task_num < CT_DTC_MIN_TASK_NUM) || (CT_DTC_MAX_TASK_NUM < g_dtc->profile.task_num)) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "DAAC_TASK_NUM");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_uint32("INSTANCE_ID", &dtc_attr->inst_id));
    if (dtc_attr->inst_id > CT_MES_MAX_INSTANCE_ID) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "INSTANCE_ID");
        return CT_ERROR;
    }
    g_instance->id = dtc_attr->inst_id;

    CT_RETURN_IFERR(srv_get_param_uint32("MES_POOL_SIZE", &g_dtc->profile.mes_pool_size));
    if ((g_dtc->profile.mes_pool_size < CT_MES_MIN_POOL_SIZE) ||
        (CT_MES_MAX_POOL_SIZE < g_dtc->profile.mes_pool_size)) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "MES_POOL_SIZE");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_bool32("INTERCONNECT_BY_PROFILE", &g_dtc->profile.conn_by_profile));

    bool32 mes_elapsed_switch = CT_FALSE;
    CT_RETURN_IFERR(srv_get_param_bool32("MES_ELAPSED_SWITCH", &mes_elapsed_switch));
    mes_set_elapsed_switch(mes_elapsed_switch);

    bool32 mes_crc_check_switch = CT_FALSE;
    CT_RETURN_IFERR(srv_get_param_bool32("MES_CRC_CHECK_SWITCH", &mes_crc_check_switch));
    mes_set_crc_check_switch(mes_crc_check_switch);

    /* mes use ssl */
    bool32 mes_use_ssl_switch = CT_FALSE;
    CT_RETURN_IFERR(srv_get_param_bool32("MES_SSL_SWITCH", &mes_use_ssl_switch));
    mes_set_ssl_switch(mes_use_ssl_switch);

    if (mes_use_ssl_switch) {
        char *mes_ssl_crt_path = srv_get_param("MES_SSL_CRT_KEY_PATH");
        if (mes_ssl_crt_path == NULL) {
            return CT_ERROR;
        }
        char cert_dir_path[CT_FILE_NAME_BUFFER_SIZE];
        PRTS_RETURN_IFERR(snprintf_s(cert_dir_path, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN, mes_ssl_crt_path));
        char ca_file_path[CT_FILE_NAME_BUFFER_SIZE];
        PRTS_RETURN_IFERR(snprintf_s(ca_file_path, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN, "%s/ca.crt", mes_ssl_crt_path));
        char cert_file_path[CT_FILE_NAME_BUFFER_SIZE];
        PRTS_RETURN_IFERR(snprintf_s(cert_file_path, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN, "%s/mes.crt", mes_ssl_crt_path));
        char key_file_path[CT_FILE_NAME_BUFFER_SIZE];
        PRTS_RETURN_IFERR(snprintf_s(key_file_path, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN, "%s/mes.key", mes_ssl_crt_path));
        char crl_file_path[CT_FILE_NAME_BUFFER_SIZE];
        PRTS_RETURN_IFERR(snprintf_s(crl_file_path, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN, "%s/mes.crl", mes_ssl_crt_path));
        char mes_pass_path[CT_FILE_NAME_BUFFER_SIZE];
        PRTS_RETURN_IFERR(snprintf_s(mes_pass_path, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN, "%s/mes.pass", mes_ssl_crt_path));
        CT_RETURN_IFERR(mes_set_ssl_crt_file(cert_dir_path, ca_file_path, cert_file_path, key_file_path, crl_file_path, mes_pass_path));
        mes_set_ssl_verify_peer(CT_TRUE);
        char *enc_pwd = srv_get_param("MES_SSL_KEY_PWD");
        CT_RETURN_IFERR(mes_set_ssl_key_pwd(enc_pwd));
    }

    bool32 enable_dbstor = CT_FALSE;
    CT_RETURN_IFERR(srv_get_param_bool32("ENABLE_DBSTOR", &enable_dbstor));
    mes_set_dbstor_enable(enable_dbstor);

    CT_RETURN_IFERR(srv_get_param_bool32("ENABLE_FDSA", &g_enable_fdsa));

    CT_RETURN_IFERR(srv_get_param_bool32("ENABLE_BROADCAST_ON_COMMIT", &attr->enable_boc));

    CT_RETURN_IFERR(srv_get_param_bool32("ENABLE_CHECK_SECURITY_LOG", &g_filter_enable));

    CT_RETURN_IFERR(srv_get_param_bool32("ENABLE_SYS_CRC_CHECK", &g_crc_verify));

    CT_RETURN_IFERR(srv_get_param_uint32("MES_CHANNEL_UPGRADE_TIME_MS", &g_dtc->profile.upgrade_time_ms));

    CT_RETURN_IFERR(srv_get_param_uint32("MES_CHANNEL_DEGRADE_TIME_MS", &g_dtc->profile.degrade_time_ms));

    uint16 cluster_id;
    CT_RETURN_IFERR(srv_get_param_uint16("CLUSTER_ID", &cluster_id));

    if (g_dtc->profile.pipe_type == CS_TYPE_UC || g_dtc->profile.pipe_type == CS_TYPE_UC_RDMA || enable_dbstor) {
        CT_RETURN_IFERR(set_all_inst_lsid(cluster_id, 0));
    }

    if (!enable_dbstor) {
        value = srv_get_param("SHARED_PATH");
        if (value == NULL) {
            CT_THROW_ERROR(ERR_CTSTORE_INVALID_PARAM, "invalid parameter value of 'SHARED_PATH'");
            return CT_ERROR;
        }
        CT_RETURN_IFERR(cm_set_file_iof_cfg(cluster_id, 0, value));
    }

    CT_RETURN_IFERR(srv_get_param_bool32("_ENABLE_RMO_CR", &g_dtc->profile.enable_rmo_cr));

    CT_RETURN_IFERR(srv_get_param_uint32("_REMOTE_ACCESS_LIMIT", &g_dtc->profile.remote_access_limit));
    if (g_dtc->profile.remote_access_limit > CT_REMOTE_ACCESS_LIMIT) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "_REMOTE_ACCESS_LIMIT");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_double("DTC_CKPT_NOTIFY_TASK_RATIO", &g_dtc->profile.ckpt_notify_task_ratio));
    if ((g_dtc->profile.ckpt_notify_task_ratio < CT_MES_MIN_TASK_RATIO) ||
        (g_dtc->profile.ckpt_notify_task_ratio > CT_MES_MAX_TASK_RATIO)) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "DTC_CKPT_NOTIFY_TASK_RATIO");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_double("DTC_CLEAN_EDP_TASK_RATIO", &g_dtc->profile.clean_edp_task_ratio));
    if ((g_dtc->profile.clean_edp_task_ratio < CT_MES_MIN_TASK_RATIO) ||
        (g_dtc->profile.clean_edp_task_ratio > CT_MES_MAX_TASK_RATIO)) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "DTC_CLEAN_EDP_TASK_RATIO");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(srv_get_param_double("DTC_TXN_INFO_TASK_RATIO", &g_dtc->profile.txn_info_task_ratio));
    if ((g_dtc->profile.txn_info_task_ratio < CT_MES_MIN_TASK_RATIO) ||
        (g_dtc->profile.txn_info_task_ratio > CT_MES_MAX_TASK_RATIO)) {
        CT_THROW_ERROR(ERR_INVALID_PARAMETER, "DTC_TXN_INFO_TASK_RATIO");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
