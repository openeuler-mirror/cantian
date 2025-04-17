#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <mockcpp/mockcpp.hpp>
#include <iostream>
#include <cstdlib>

extern "C" {
#include "srv_session.h"
#include "ctc_srv_util.h"
#include "ctc_srv.h"
#include "ctc_ddl.h"
#include "ctsql_statistics.h"
#include "ctsql_stmt.h"
#include "cm_log.h"
#include "knl_defs.h"
#include "knl_session.h"
#include "knl_database.h"
#include "knl_interface.h"
#include "srv_instance.h"
#include "srv_mq.h"
#include "srv_mq_msg.h"
#include "cm_text.h"
#include "dml_parser.h"
#include "types.h"
#include "cm_timer.h"
}

extern "C" {
    void sql_enrich_context_for_cached(sql_stmt_t *mock_, timeval_t *tv_begin, ctx_stat_t *herit_stat);
}

class TestSqlEnrichContextForCached : public testing::Test {
protected:
    timeval_t tv_begin;
    ctx_stat_t herit_stat;
    sql_context_t mock_context;
    session_t mock_session;
    sql_stmt_t mock_stmt;
    instance_t mock_instance;
    lex_t mock_lex;
    sql_text_t mock_text;
    knl_instance_t mock_kernel;
    context_pool_t mock_sql_pool;
    
    void SetUp() override {
        memset(&mock_kernel, 0, sizeof(mock_kernel));
        memset(&mock_instance, 0, sizeof(mock_instance));
        memset(&mock_session, 0, sizeof(mock_session));
        memset(&mock_stmt, 0, sizeof(mock_stmt));
        memset(&mock_lex, 0, sizeof(mock_lex));
        memset(&mock_context, 0, sizeof(mock_context));
        memset(&mock_text, 0, sizeof(mock_text));
        memset(&mock_session.knl_session, 0, sizeof(mock_session.knl_session));
        mock_stmt.param_info.paramset_size = 0;
        mock_session.lex = &mock_lex;
        mock_lex.text = mock_text;
        mock_stmt.session = &mock_session;
        mock_session.current_stmt = &mock_stmt;
        mock_stmt.context = &mock_context;
    }

    void TearDown() override {
    }

    static int MockCmGetTimeOfDay(timeval_t *tv) {
        tv->tv_sec = 1000;
        tv->tv_usec = 0;
        return 0;
    }

    static uint64 MockGTimerNow() {
        return 2000;
    }

    static void MockSqlInitContextStat(ctx_stat_t *stat) {
        memset(stat, 0, sizeof(ctx_stat_t));
    }

    static void MockSqlParseSetContextProcInfo(sql_stmt_t *stmt) {}
};

struct MockTimer {
    uint64 (*now)();
};

TEST_F(TestSqlEnrichContextForCached, EnrichContext) {
    MOCKER(gettimeofday)
        .stubs()
        .will(invoke(MockCmGetTimeOfDay));
    MOCKER(sql_init_context_stat)
        .stubs()
        .will(invoke(MockSqlInitContextStat));
    MOCKER(sql_parse_set_context_procinfo)
        .stubs()
        .will(invoke(MockSqlParseSetContextProcInfo));

    herit_stat.last_load_time = 500;
    tv_begin.tv_sec = 999;
    tv_begin.tv_usec = 0;
    sql_enrich_context_for_cached(&mock_stmt, &tv_begin, &herit_stat);

    // 验证结果
    EXPECT_EQ(mock_stmt.context->stat.last_load_time, g_timer()->now);
    EXPECT_EQ(mock_stmt.context->stat.parse_time, 1000000);
    EXPECT_EQ(mock_stmt.context->stat.parse_calls, 1);
    EXPECT_EQ(mock_stmt.context->module_kind, SESSION_CLIENT_KIND(mock_stmt.session));
}