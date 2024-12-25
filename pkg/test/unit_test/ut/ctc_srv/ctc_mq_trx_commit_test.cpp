#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <mockcpp/mockcpp.hpp>
#include <iostream>
#include <cstdlib>

extern "C" {
#include "ctc_srv_util.h"
#include "ctc_srv.h"
#include "ctc_ddl.h"
#include "ctsql_statistics.h"
#include "ctsql_stmt.h"
#include "cm_log.h"
#include "ostat_load.h"
#include "knl_defs.h"
#include "knl_session.h"
#include "knl_database.h"
#include "knl_interface.h"
#include "srv_session.h"
#include "knl_heap.h"
#include "xact_defs.h"
#include "srv_instance.h"
#include "/home/regress/cantian-connector-mysql/mysql-source/storage/ctc/message_queue/dsw_message.h"
#include "srv_mq.h"
#include "srv_mq_msg.h"
}

extern "C" {
    int ctc_mq_trx_commit(dsw_message_block_t *message_block);
    static int ctc_check_cursor_num(int32_t cursor_num){
        return CT_SUCCESS;
    };
}

class TestCtcMqTrxCommit : public testing::Test {
protected:
    dsw_message_block_t message_block; // 模拟消息块
    trx_commit_request mock_req;       // 模拟事务提交请求

    void SetUp() override {
        // 初始化模拟对象
        memset(&message_block, 0, sizeof(message_block));
        memset(&mock_req, 0, sizeof(mock_req));

        mock_req.csize = 1;
        mock_req.result = 0;
        mock_req.is_ddl_commit = false;
        strncpy(mock_req.sql_str, "SELECT * FROM test", sizeof(mock_req.sql_str) - 1);
        mock_req.sql_str[sizeof(mock_req.sql_str) - 1] = '\0'; // 确保字符串以空字符结尾
        // 使用 malloc 为 mock_req.cursors 分配内存
        mock_req.cursors = static_cast<uint64_t*>(malloc(sizeof(uint64_t) * mock_req.csize));
        if (mock_req.cursors == nullptr) {
            FAIL() << "Failed to allocate " << (sizeof(uint64_t) * mock_req.csize) 
                  << " bytes for cursors";
            return;
        }

        // 初始化 seg_buf 并关联 mock_req
        message_block.seg_buf[0] = &mock_req;
    }

    void TearDown() override {
        // 释放内存
        free(mock_req.cursors);
        GlobalMockObject::reset();
    }

    static int MockCtcTrxCommit(ctc_handler_t *tch, uint64_t *cursors, int32_t csize, bool *is_ddl_commit, char *sql_str) {
        return CT_SUCCESS; // 返回模拟值
    }
};

TEST_F(TestCtcMqTrxCommit, CommitSuccess) {
    // 模拟 ctc_check_cursor_num 和 ctc_trx_commit 的行为
    MOCKER(ctc_check_cursor_num)
        .stubs()
        .will(returnValue(CT_SUCCESS));
    MOCKER(ctc_trx_commit)
        .stubs()
        .will(invoke(MockCtcTrxCommit));

    // 调用待测试函数
    int ret = ctc_mq_trx_commit(&message_block);

    // 验证返回值
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(mock_req.result, 0);
}