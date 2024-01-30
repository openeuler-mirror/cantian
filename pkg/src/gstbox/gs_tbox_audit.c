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
 * gs_tbox_audit.c
 *
 *
 * IDENTIFICATION
 * src/gstbox/gs_tbox_audit.c
 *
 * -------------------------------------------------------------------------
 */
#include "gs_tbox_module.h"
#include "gs_tbox_audit.h"
#include "cm_timer.h"

#ifdef WIN32
#include <direct.h>
#define GET_CWD _getcwd
#else
#include "unistd.h"
#include "pwd.h"
#include <utmp.h>

#define GET_CWD getcwd
#endif

#define TBOX_MAX_CMD_BUFFER_SIZE 1024

typedef struct st_tbox_audit_assist {
    char date[CT_MAX_TIME_STRLEN];
    char db_user[CT_NAME_BUFFER_SIZE];
    char host_ip[CM_MAX_IP_LEN];
    char cmd_text[CT_PARAM_BUFFER_SIZE];
    char return_code_buf[CT_MAX_NUMBER_LEN];

    int32 code;
    int32 tz;
} tbox_audit_assist_t;

static inline void tbox_init_audit_assist(tbox_audit_assist_t *assist, int32 err_code)
{
    assist->date[0] = '\0';
    assist->db_user[0] = '\0';
    assist->host_ip[0] = '\0';
    assist->cmd_text[0] = '\0';
    assist->return_code_buf[0] = '\0';
    assist->code = err_code;
    assist->tz = 0;
    return;
}

status_t tbox_verify_log_path(const char *input_path, repair_page_def_t *page_input)
{
    char *path = NULL;

    // 0, get user input
    if (input_path != NULL) {
        if (strlen(input_path) >= CT_MAX_PATH_BUFFER_SIZE) {
            printf("log path must be less than %u", CT_MAX_PATH_BUFFER_SIZE);
        }
        if (cm_dir_exist(input_path) == CT_TRUE) {
            PRTS_PRINT_RETURN_IFERR(snprintf_s(page_input->log_path, CT_FILE_NAME_BUFFER_SIZE, CT_MAX_FILE_NAME_LEN,
                                               "%s/ctbox_audit_log/ctbox.aud", input_path));
            return CT_SUCCESS;
        }
        printf("invaild log path");
        return CT_ERROR;
    }

    // 1 get $CANTIANLOG
    if (input_path == NULL) {
        path = getenv("CANTIANLOG");
    }

    // 2 get $CTDB_HOME
    if (path == NULL) {
        path = getenv(CT_ENV_HOME);
    }

    // get something from 1 or 2, verify
    if (path != NULL) {
        if (cm_dir_exist(path) == CT_TRUE) {
            PRTS_PRINT_RETURN_IFERR(snprintf_s(page_input->log_path, CT_FILE_NAME_BUFFER_SIZE,
                CT_MAX_FILE_NAME_LEN, "%s/log/ctbox_audit/ctbox.aud", path));
            return CT_SUCCESS;
        }
    }

    // 3 default is current dir
    char *ret __attribute__((unused)) = GET_CWD(page_input->log_path, CT_MAX_PATH_BUFFER_SIZE);
    MEMS_PRINT_RETURN_IFERR(strcat_s(page_input->log_path, CT_MAX_FILE_NAME_LEN, "/ctbox_audit/ctbox.aud"));
    return CT_SUCCESS;
}

status_t tbox_init_audit_log(const char *path)
{
    log_file_handle_t *log_file = cm_log_logger_file(LOG_AUDIT);
    MEMS_PRINT_RETURN_IFERR(strncpy_s(log_file->file_name, CT_FILE_NAME_BUFFER_SIZE,
        path, (size_t)CT_MAX_FILE_NAME_LEN));
    // lock is no used
    CT_INIT_SPIN_LOCK(log_file->lock);
    log_file->file_handle = -1;
    log_file->file_inode = 0;
    log_file->log_id = LOG_AUDIT;

    log_param_t *log_param = cm_log_param_instance();
    log_param->log_level = 0;

    log_param->log_backup_file_count = TBOX_LOG_BACKUP_FILE_COUNT;
    log_param->audit_backup_file_count = TBOX_LOG_BACKUP_FILE_COUNT;

    log_param->max_log_file_size = TBOX_LOG_MAX_SIZE;
    log_param->max_audit_file_size = TBOX_LOG_MAX_SIZE;

    cm_log_set_file_permissions(TBOX_LOG_FILE_PERMISSIONS_640);
    cm_log_set_path_permissions(TBOX_LOG_PATH_PERMISSIONS_750);

    return CT_SUCCESS;
}

#ifndef WIN32
void tbox_exec_cmd(const char *cmd, char *output, uint32 output_len)
{
    FILE *file = popen(cmd, "r");
    if (file == NULL) {
        return;
    }
    char *ret __attribute__((unused)) = fgets(output, output_len, file);
    (void)pclose(file);
    return;
}
#endif

void tbox_audit_get_host(tbox_audit_assist_t *assist)
{
#ifdef WIN32
    return;
#else
    char cmd[] = "who am i| awk '{print $1, $NF}'";
    char res[TBOX_MAX_CMD_BUFFER_SIZE] = { 0 };
    text_t output_text;
    text_t user_text;

    tbox_exec_cmd(cmd, res, TBOX_MAX_CMD_BUFFER_SIZE);

    output_text.str = res;
    output_text.len = (uint32)strlen(res);
    if (output_text.len == 0) {
        return;
    }

    if (!cm_fetch_text(&output_text, ' ', 0, &user_text)) {
        return;
    }
    output_text.len--; // remove \n
    cm_remove_brackets(&output_text); // remove bracket
    MEMS_PRINT_RETVOID_IFERR(strncpy_s(assist->db_user, CT_NAME_BUFFER_SIZE, user_text.str, user_text.len));
    MEMS_PRINT_RETVOID_IFERR(strncpy_s(assist->host_ip, CM_MAX_IP_LEN, output_text.str, output_text.len));

    return;
#endif
}

void tbox_audit_create_message(tbox_audit_assist_t *assist, char *log_msg, uint32 *log_msg_len)
{
    PRTS_PRINT_RETVOID_IFERR(snprintf_s(assist->return_code_buf, CT_MAX_NUMBER_LEN, CT_MAX_NUMBER_LEN - 1,
        "CT-%05d", assist->code));

    tbox_audit_get_host(assist);
    size_t cmd_len = strlen(assist->cmd_text);
    int32 iret_snprintf = snprintf_s(log_msg, CT_T2S_LARGER_BUFFER_SIZE, CT_T2S_LARGER_BUFFER_SIZE - 1,
        "USER:[%u] \"%s\" "
        "HOST:[%u] \"%s\" "
        "RETURNCODE:[%u] \"%s\" "
        "CMDTEXT:[%u] \"",
        (uint32)strlen(assist->db_user), assist->db_user,  // USER
        (uint32)strlen(assist->host_ip), assist->host_ip,  // HOST
        (uint32)strlen(assist->return_code_buf), assist->return_code_buf,  // RETURNCODE
        (uint32)cmd_len);  // CMDTEXT
    if (iret_snprintf == -1) {
        printf("[Audit log]system error occured, snprintf error, exit.\n");
        CT_THROW_ERROR(ERR_SYSTEM_CALL, iret_snprintf);
        return;
    }

    if (iret_snprintf > CT_T2S_LARGER_BUFFER_SIZE - 1) {
        *log_msg_len = CT_T2S_LARGER_BUFFER_SIZE - 1;
        log_msg[CT_T2S_LARGER_BUFFER_SIZE - 1] = '\0';
        return;
    }

    *log_msg_len = (uint32)iret_snprintf + (uint32)cmd_len + 1;
    if (*log_msg_len > CT_T2S_LARGER_BUFFER_SIZE - 1) {
        *log_msg_len = CT_T2S_LARGER_BUFFER_SIZE - 1;
    }
    if (*log_msg_len > (uint32)iret_snprintf + 1) {
        MEMS_PRINT_RETVOID_IFERR(memcpy_s(log_msg + iret_snprintf, *log_msg_len - (uint32)iret_snprintf,
            assist->cmd_text, MIN(*log_msg_len - (uint32)iret_snprintf, cmd_len)));
    }
    log_msg[*log_msg_len - 1] = '\"';
    log_msg[*log_msg_len] = '\0';

    return;
}

static inline void tbox_get_input_cmd(tbox_audit_assist_t *assist, int argc, char *argv[])
{
    assist->cmd_text[0] = '\0';
    for (int i = 1; i < argc; i++) {
        if (strlen(assist->cmd_text) + strlen(argv[i]) + 1 >= CT_PARAM_BUFFER_SIZE - 1) {
            printf("[Audit log] invalid parameter length (cannot exceeds %u).\n", CT_PARAM_BUFFER_SIZE);
            exit(EXIT_FAILURE);
        }
        MEMS_PRINT_RETVOID_IFERR(strcat_s(assist->cmd_text, CT_PARAM_BUFFER_SIZE, " "));
        MEMS_PRINT_RETVOID_IFERR(strcat_s(assist->cmd_text, CT_PARAM_BUFFER_SIZE, argv[i]));
    }
    return;
}

void tbox_write_audit_log(int argc, char *argv[], int32 err_code)
{
    int iret_snprintf, tz_hour, tz_min;
    tbox_audit_assist_t assist;
    char *log_msg = cm_get_t2s_addr();
    uint32 log_msg_len;

    tbox_init_audit_assist(&assist, err_code);

    if (cm_start_timer(g_timer()) != CT_SUCCESS) {
        printf("[Audit log]aborted due to starting timer thread.\n");
        exit(EXIT_FAILURE);
    }

    assist.tz = g_timer()->tz;
    tz_hour = TIMEZONE_GET_HOUR(assist.tz);
    tz_min = TIMEZONE_GET_MINUTE(assist.tz);
    if (tz_hour >= 0) {
        iret_snprintf = snprintf_s(assist.date, CT_MAX_TIME_STRLEN, CT_MAX_TIME_STRLEN - 1, "UTC+%02d:%02d ", tz_hour, tz_min);
    } else {
        iret_snprintf = snprintf_s(assist.date, CT_MAX_TIME_STRLEN, CT_MAX_TIME_STRLEN - 1, "UTC%02d:%02d ", tz_hour, tz_min);
    }

    if (iret_snprintf == -1) {
        printf("[Audit log]system error occured, snprintf error, exit.\n");
        CT_THROW_ERROR(ERR_SYSTEM_CALL, iret_snprintf);
        cm_close_timer(g_timer());
        return;
    }

    (void)cm_date2str(g_timer()->now, "yyyy-mm-dd hh24:mi:ss.ff3", assist.date + iret_snprintf,
                      CT_MAX_TIME_STRLEN - iret_snprintf);

    tbox_get_input_cmd(&assist, argc, argv);
    tbox_audit_create_message(&assist, log_msg, &log_msg_len);

    TBOX_LOG_AUDIT("%s\nLENGTH: \"%u\"\n%s\n", assist.date, log_msg_len, log_msg);
    cm_close_timer(g_timer());
    return;
}