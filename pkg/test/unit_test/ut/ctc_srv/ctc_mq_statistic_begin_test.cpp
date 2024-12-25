#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <mockcpp/mockcpp.hpp>
#include <sys/time.h>
#include <iostream>

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
    int ctc_mq_statistic_begin(dsw_message_block_t *message_block);
}

using namespace std;

class TestCtcMqStatisticBegin : public testing::Test {
protected:
    dsw_message_block_t message_block; // 模拟消息块
    trx_begin_request mock_req;        // 模拟事务开始请求
    timeval begin_time;

    void SetUp() override {
        // 初始化 begin_time
        gettimeofday(&begin_time, nullptr);

        // 初始化 mock_req
        memset(&mock_req, 0, sizeof(mock_req));
        mock_req.begin_time = begin_time; // 设置事务开始时间

        // 初始化 message_block 并关联 mock_req
        memset(&message_block, 0, sizeof(message_block));
        message_block.seg_buf[0] = &mock_req; // 将 mock_req 绑定到消息块的缓冲区
    }

    static int MockCtcStatisticBegin(ctc_handler_t *tch, timeval_t begin_time, bool *enable_stat) {
        *enable_stat = true; // 模拟 enable_stat 被正确设置
        return CT_SUCCESS;          // 返回模拟值
    }
};

TEST_F(TestCtcMqStatisticBegin, Should_return_status_true_when_ctc_mq_statistic_begin)
{
    // 模拟 ctc_trx_begin 的行为
    MOCKER(ctc_statistic_begin)
        .stubs()
        .will(invoke(MockCtcStatisticBegin));

    // 调用待测试函数
    int ret = ctc_mq_statistic_begin(&message_block);

    // 验证返回值
    EXPECT_EQ(ret, 0) << "ctc_mq_trx_begin failed: expected 123, but got " << ret;

    // 验证 enable_stat 是否正确设置
    EXPECT_TRUE(mock_req.enable_stat) << "enable_stat should be set to true, but it is false";

    // 验证 Mock 调用
    GlobalMockObject::verify();
}
