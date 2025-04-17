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
    int ctc_mq_statistic_commit(dsw_message_block_t *message_block);
    static int ctc_check_cursor_num(int32_t cursor_num){
        return CT_SUCCESS;
    };
}

class TestCtcMqstatisticCommit : public testing::Test {
protected:
    dsw_message_block_t message_block; // 模拟消息块
    trx_commit_request mock_req;       // 模拟事务提交请求

    void SetUp() override {
        // 初始化模拟对象
        memset(&message_block, 0, sizeof(message_block));
        memset(&mock_req, 0, sizeof(mock_req));

        mock_req.result = 0;
        strncpy(mock_req.sql_str, "SELECT * FROM test", sizeof(mock_req.sql_str) - 1);
        mock_req.sql_str[sizeof(mock_req.sql_str) - 1] = '\0'; // 确保字符串以空字符结尾
        // 初始化 seg_buf 并关联 mock_req
        message_block.seg_buf[0] = &mock_req;
    }

    void TearDown() override {
        // 释放内存
        free(mock_req.cursors);
        GlobalMockObject::reset();
    }

    static int MockCtcstatisticCommit(ctc_handler_t *tch,  char *sql_str) {
        return CT_SUCCESS; // 返回模拟值
    }
};

TEST_F(TestCtcMqstatisticCommit, CommitSuccess) {
    // 模拟 ctc_check_cursor_num 和 ctc_trx_commit 的行为
    MOCKER(ctc_check_cursor_num)
        .stubs()
        .will(returnValue(CT_SUCCESS));
    MOCKER(ctc_statistic_commit)
        .stubs()
        .will(invoke(MockCtcstatisticCommit));

    // 调用待测试函数
    int ret = ctc_mq_statistic_commit(&message_block);

    // 验证返回值
    EXPECT_EQ(ret, CT_SUCCESS);
    EXPECT_EQ(mock_req.result, CT_SUCCESS);
}