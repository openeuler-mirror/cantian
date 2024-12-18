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
 * cms_cbb.h
 *
 *
 * IDENTIFICATION
 * src/cms/cbb/cms_cbb.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CMS_CBB_H__
#define __CMS_CBB_H__

typedef void (*cm_notify_func_t)(void);

int CmInit(unsigned int instance_id, const char *res_name, cm_notify_func_t func);
char* CmGetResStats(void);
void CmFreeResStats(char *res_stat);
int CmResLock(const char *lock_name);
int CmResUnlock(const char *lock_name);
int CmResGetLockOwner(const char *lock_name, unsigned int *inst_id);
int CmResTransLock(const char *lock_name, unsigned int inst_id);

#endif