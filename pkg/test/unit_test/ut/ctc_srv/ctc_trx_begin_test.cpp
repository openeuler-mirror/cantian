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
}

using namespace std;
// static ctc_handler_t *tch = NULL;
// static ctc_trx_context_t trx_context = NULL;

extern instance_t* g_instance;
static session_t mock_session;
class TestCtcTrxBegin : public testing::Test {
protected:
    instance_t mock_instance;
    sql_stmt_t mock_stmt;
    ctc_handler_t mock_tch;
    ctc_trx_context_t trx_context;
    ctx_prev_stat_t mock_ctx_stat;
    knl_rm_t mock_rm;
    knl_instance_t mock_kernel;
    timeval begin_time ;

    bool is_new_session;

    void SetUp() override {
        // 初始化模拟对象
        memset(&mock_instance, 0, sizeof(mock_instance));
        g_instance = &mock_instance; // 将全局变量指向模拟对象

        memset(&mock_session, 0, sizeof(mock_session));
        memset(&mock_stmt, 0, sizeof(mock_stmt));
        memset(&mock_ctx_stat, 0, sizeof(mock_ctx_stat));
        memset(&mock_rm, 0, sizeof(mock_rm));
        memset(&mock_kernel, 0, sizeof(mock_kernel));
        
        mock_tch.sess_addr = (uint64)&mock_session;
        mock_stmt.param_info.paramset_size = 0;
        mock_stmt.session = &mock_session;
        mock_session.current_stmt = &mock_stmt;
        mock_session.ctx_prev_stat = mock_ctx_stat;
        mock_session.knl_session.rm = &mock_rm;
        mock_session.knl_session.kernel =&mock_kernel;

        gettimeofday(&begin_time, nullptr);
    }

    void TearDown() override {
        g_instance = nullptr; // 清理全局变量
    }
    static int MockSessionGetter(session_t **session, ctc_handler_t*, bool, bool, bool*) {
        *session = &mock_session;
        return CT_SUCCESS;
    }

    static int Mockknlsetsessiontrans1(knl_handle_t session, isolation_level_t level, bool32 is_select) {
        return CT_SUCCESS;
    }
    static int Mockknlsetsessiontrans2(knl_handle_t session, isolation_level_t level, bool32 is_select) {
        return CT_ERROR;
    }
    

};

TEST_F(TestCtcTrxBegin, Should_return_status_true_when_ctc_trx_begin1)
{
    mock_instance.sql.enable_sql_statistic_stat = true;
    bool enable_stat = true;
    MOCKER(ctc_get_or_new_session)
            .stubs()
            .will(invoke(MockSessionGetter));
    MOCKER(ctc_alloc_stmt_context).stubs().will(returnValue(CT_TRUE));
    MOCKER(knl_db_is_primary).stubs().will(returnValue(CT_TRUE));
    MOCKER(knl_set_session_trans)
            .stubs()
            .will(invoke(Mockknlsetsessiontrans1));
    MOCKER(knl_set_session_trans).stubs().will(returnValue(static_cast<int>(CT_TRUE)));
    int ret = ctc_trx_begin(&mock_tch, trx_context, true, begin_time, &enable_stat);
    EXPECT_EQ(ret, 0) << "ctc_trx_begin failed: expected CT_SUCCESS (0), but got " << ret;

    GlobalMockObject::verify();
    EXPECT_TRUE(enable_stat) << "enable_stat should be set to true, but it is false";
    //g_instance = nullptr;
}



TEST_F(TestCtcTrxBegin, Should_return_status_true_when_ctc_trx_begin2)
{
    mock_instance.sql.enable_sql_statistic_stat = true;
    bool enable_stat = true;
    MOCKER(ctc_get_or_new_session)
            .stubs()
            .will(invoke(MockSessionGetter));
    MOCKER(ctc_alloc_stmt_context).stubs().will(returnValue(CT_TRUE));
    MOCKER(knl_db_is_primary).stubs().will(returnValue(CT_FALSE));
    MOCKER(knl_set_session_trans)
            .stubs()
            .will(invoke(Mockknlsetsessiontrans1));
    MOCKER(knl_set_session_trans).stubs().will(returnValue(static_cast<int>(CT_TRUE)));
    int ret = ctc_trx_begin(&mock_tch, trx_context, true, begin_time, &enable_stat);
    EXPECT_EQ(ret, 0) << "ctc_trx_begin failed: expected CT_SUCCESS (0), but got " << ret;

    GlobalMockObject::verify();
    EXPECT_TRUE(enable_stat) << "enable_stat should be set to true, but it is false";
    //g_instance = nullptr;
}

TEST_F(TestCtcTrxBegin, Should_return_status_true_when_ctc_trx_begin3)
{
    mock_instance.sql.enable_sql_statistic_stat = true;
    bool enable_stat = true;
    MOCKER(ctc_get_or_new_session)
            .stubs()
            .will(invoke(MockSessionGetter));
    MOCKER(ctc_alloc_stmt_context).stubs().will(returnValue(CT_TRUE));
    MOCKER(knl_db_is_primary).stubs().will(returnValue(CT_TRUE));
    MOCKER(knl_set_session_trans)
            .stubs()
            .will(invoke(Mockknlsetsessiontrans2));
    MOCKER(knl_set_session_trans).stubs().will(returnValue(static_cast<int>(CT_TRUE)));
    int ret = ctc_trx_begin(&mock_tch, trx_context, true, begin_time, &enable_stat);
    EXPECT_EQ(ret, -1) << "ctc_trx_begin failed: expected CT_SUCCESS (0), but got " << ret;

    GlobalMockObject::verify();
    EXPECT_TRUE(enable_stat) << "enable_stat should be set to true, but it is false";
    //g_instance = nullptr;
}

TEST_F(TestCtcTrxBegin, Should_return_status_true_when_ctc_trx_begin4)
{
    mock_instance.sql.enable_sql_statistic_stat = CT_TRUE;
    mock_session.knl_session.kernel->db.is_readonly = CT_TRUE;
    bool enable_stat = true;
    MOCKER(ctc_get_or_new_session)
            .stubs()
            .will(invoke(MockSessionGetter));
    MOCKER(ctc_alloc_stmt_context).stubs().will(returnValue(CT_TRUE));
    MOCKER(knl_db_is_primary).stubs().will(returnValue(CT_TRUE));
    MOCKER(knl_set_session_trans)
            .stubs()
            .will(invoke(Mockknlsetsessiontrans1));
    MOCKER(knl_set_session_trans).stubs().will(returnValue(static_cast<int>(CT_TRUE)));
    int ret = ctc_trx_begin(&mock_tch, trx_context, true, begin_time, &enable_stat);
    EXPECT_EQ(ret, 0) << "ctc_trx_begin failed: expected CT_SUCCESS (0), but got " << ret;

    GlobalMockObject::verify();
    EXPECT_TRUE(enable_stat) << "enable_stat should be set to true, but it is false";
    //g_instance = nullptr;
}

TEST_F(TestCtcTrxBegin, Should_return_status_true_when_ctc_trx_begin5)
{
    mock_instance.sql.enable_sql_statistic_stat = CT_TRUE;
    st_txn mock_txn;
    memset(&mock_txn, 0, sizeof(mock_txn));
    mock_session.knl_session.rm->txn=&mock_txn;
    bool enable_stat = true;
    MOCKER(ctc_get_or_new_session)
            .stubs()
            .will(invoke(MockSessionGetter));
    MOCKER(ctc_alloc_stmt_context).stubs().will(returnValue(CT_TRUE));
    MOCKER(knl_db_is_primary).stubs().will(returnValue(CT_TRUE));
    MOCKER(knl_set_session_trans)
            .stubs()
            .will(invoke(Mockknlsetsessiontrans1));
    MOCKER(knl_set_session_trans).stubs().will(returnValue(static_cast<int>(CT_TRUE)));
    int ret = ctc_trx_begin(&mock_tch, trx_context, true, begin_time, &enable_stat);
    EXPECT_EQ(ret, 0) << "ctc_trx_begin failed: expected CT_SUCCESS (0), but got " << ret;

    GlobalMockObject::verify();
    EXPECT_TRUE(enable_stat) << "enable_stat should be set to true, but it is false";
    //g_instance = nullptr;
}

TEST_F(TestCtcTrxBegin, Should_return_status_true_when_ctc_trx_begin6)
{
    mock_instance.sql.enable_sql_statistic_stat = CT_TRUE;
    st_txn mock_txn;
    memset(&mock_txn, 0, sizeof(mock_txn));
    mock_session.knl_session.rm->txn=&mock_txn;
    bool enable_stat = true;
    MOCKER(ctc_get_or_new_session)
            .stubs()
            .will(invoke(MockSessionGetter));
    MOCKER(ctc_alloc_stmt_context).stubs().will(returnValue(CT_FALSE));
    MOCKER(knl_db_is_primary).stubs().will(returnValue(CT_TRUE));
    MOCKER(knl_set_session_trans)
            .stubs()
            .will(invoke(Mockknlsetsessiontrans1));
    MOCKER(knl_set_session_trans).stubs().will(returnValue(static_cast<int>(CT_TRUE)));
    int ret = ctc_trx_begin(&mock_tch, trx_context, true, begin_time, &enable_stat);
    EXPECT_EQ(ret, -1) << "ctc_trx_begin failed: expected CT_SUCCESS (0), but got " << ret;

    GlobalMockObject::verify();
    EXPECT_TRUE(enable_stat) << "enable_stat should be set to true, but it is false";
    //g_instance = nullptr;
}