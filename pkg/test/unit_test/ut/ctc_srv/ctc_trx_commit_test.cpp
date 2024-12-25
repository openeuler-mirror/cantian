#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <mockcpp/mockcpp.hpp>
#include <iostream>
#include <cstdlib>

extern "C" {
#include "srv_session.h"
#include "ctc_srv_util.h"
#include "ctc_srv.h"
// #include "ctc_srv.c"
#include "ctc_ddl.h"
#include "ctc_ddl_list.h"
#include "ctsql_statistics.h"
#include "ctsql_stmt.h"
#include "cm_log.h"
#include "ostat_load.h"
#include "knl_defs.h"
#include "knl_session.h"
#include "knl_database.h"
#include "knl_interface.h"
#include "cm_stack.h"
#include "knl_heap.h"
#include "xact_defs.h"
#include "srv_instance.h"
#include "srv_mq.h"
#include "srv_mq_msg.h"
#include "cm_text.h"
#include "dml_parser.h"
#include "types.h"
}

extern "C" {
    int ctc_trx_commit(ctc_handler_t *tch, uint64_t *cursors, int32_t csize, bool *is_ddl_commit, char *sql_str);
    int ctc_ddl_commit_log_put(knl_session_t *session, sql_stmt_t *stmt, ctc_ddl_def_node_t *def_node, ctc_ddl_dc_array_t *dc_node);
    void ctc_ddl_table_after_commit_list(bilist_t *def_list, ctc_ddl_dc_array_t *dc_array, knl_session_t *session, bool *unlock_tables);
}

extern instance_t* g_instance;

class TestCtcTrxCommit : public testing::Test {
protected:
    ctc_handler_t mock_tch;
    session_t mock_session;
    sql_stmt_t mock_stmt;
    knl_session_t mock_knl_session;
    instance_t mock_instance;
    lex_t mock_lex;
    sql_text_t mock_text;
    sql_context_t mock_context;
    bilist_t mock_def_list;
    bilist_node_t mock_node;
    ctc_ddl_def_node_t mock_def_node;
    cm_stack_t mock_stack;
    void* mock_stack_memory;
    knl_instance_t mock_kernel;
    
    void SetUp() override {
        memset(&mock_kernel, 0, sizeof(mock_kernel));
        memset(&mock_instance, 0, sizeof(mock_instance));
        memset(&mock_tch, 0, sizeof(mock_tch));
        memset(&mock_session, 0, sizeof(mock_session));
        memset(&mock_stmt, 0, sizeof(mock_stmt));
        memset(&mock_lex, 0, sizeof(mock_lex));
        memset(&mock_context, 0, sizeof(mock_context));
        memset(&mock_text, 0, sizeof(mock_text));
        memset(&mock_def_list, 0, sizeof(mock_def_list));
        memset(&mock_node, 0, sizeof(mock_node));
        memset(&mock_def_node, 0, sizeof(mock_def_node));
        memset(&mock_stack, 0, sizeof(mock_stack));
        memset(&mock_session.knl_session, 0, sizeof(mock_session.knl_session));

        mock_tch.sess_addr = (uint64)&mock_session;
        mock_tch.sql_command == SQLCOM_DROP_TABLE;
        mock_stmt.param_info.paramset_size = 0;
        mock_session.lex = &mock_lex;
        mock_lex.text = mock_text;
        mock_stmt.session = &mock_session;
        mock_session.current_stmt = &mock_stmt;
        mock_stmt.context = &mock_context;
        g_instance = &mock_instance;
        g_instance->sql.enable_sql_statistic_stat = true;
        mock_tch.pre_sess_addr == 0;
        mock_stmt.ddl_def_list = mock_def_list;
        mock_stmt.ddl_def_list.head = &mock_node;
        mock_node.next = nullptr;
        mock_def_node.bilist_node = mock_node;
        mock_session.knl_session.stack = &mock_stack;
        mock_session.knl_session.kernel = &mock_kernel;
        mock_kernel.attr.mysql_metadata_in_cantian = true;
        mock_def_list.count = 1;

        mock_stack_memory = malloc(1024);
        if (mock_stack_memory == nullptr) {
            ADD_FAILURE() << "Failed to allocate 1024 bytes for stack memory";
            return;  
        }
        mock_stack.buf = (uint8*)mock_stack_memory;
        mock_stack.push_offset = 0;

    }

    void TearDown() override {
        g_instance = nullptr;
        free(mock_stack_memory);
        GlobalMockObject::reset();
    }

    static session_t* MockCtcGetSessionByAddr(uint64_t sess_addr) {
        return reinterpret_cast<session_t*>(sess_addr);
    }

    static void MockCtcSetNoUseOtherSess4Thd(session_t *session) {}

    static void MockCtcFreeCursors(session_t *session, uint64_t *cursors, int32_t csize) {}

    static bool32 MockCtcAllocStmtContext(session_t *session) {
        return CT_TRUE;
    }

    static void MockKnlCommit(knl_handle_t handle) {}

    static void MockKnlCommit4Mysql(knl_handle_t session) {}

    static void MockCtcDdlClearStmt(sql_stmt_t *stmt) {}

    static void MockCtcTrxRollback(ctc_handler_t *tch, uint64_t *cursors, int32_t csize) {}

    static void MockCtcDdlTableAfterCommitList(bilist_t *def_list, ctc_ddl_dc_array_t *dc_array, knl_session_t *session, bool *unlock_tables) {}
    static bool32 MockSqlGetContextCache(sql_stmt_t *stmt, text_t *sql, uint32 *sql_id, context_bucket_t **bid, ctx_stat_t *herit_stat) {
        return CT_FALSE;
    }

    static int MockCtxWriteText(context_ctrl_t *ctrl, text_t *text) {
        return CT_SUCCESS;
    }

    static void MockSqlPrepareContextCtrl(sql_stmt_t *stmt, uint32 hash_value, context_bucket_t *bucket) {}

    static void MockSqlEnrichContextForCached(sql_stmt_t *stmt, timeval_t *tv_begin, ctx_stat_t *herit_stat) {}

    static status_t MockSqlCacheContext(sql_stmt_t *stmt, context_bucket_t *bucket, sql_text_t *sql, uint32 hash_value) {
        return CT_SUCCESS;
    }

    static void MockSqlEndCtxStat(void *handle) {}

    static bool MockCtcIsDefListEmpty(bilist_t *def_list) {
        return false;
    }

    static int MockCtcDdlCommitLogPut(knl_session_t *session, sql_stmt_t *stmt, ctc_ddl_def_node_t *def_node, ctc_ddl_dc_array_t *dc_node) {
        return CT_SUCCESS;
    }
    static void MockCtcDdlUnlockTable(knl_session_t *session, bool unlock_tables) {}

    static void MockSqlDdlClearStmt(sql_stmt_t *stmt){}

    static void* MockCmPush(cm_stack_t *stack, size_t size) {
        uint8 *ptr = stack->buf + stack->push_offset;
        stack->push_offset += size;
        memset(ptr, 0, size);
        return ptr;
    }
};

TEST_F(TestCtcTrxCommit, CommitSuccess) {
    // 模拟函数行为
    MOCKER(ctc_get_session_by_addr)
        .stubs()
        .will(invoke(MockCtcGetSessionByAddr));
    MOCKER(ctc_set_no_use_other_sess4thd)
        .stubs()
        .will(invoke(MockCtcSetNoUseOtherSess4Thd));
    MOCKER(ctc_free_cursors)
        .stubs()
        .will(invoke(MockCtcFreeCursors));
    MOCKER(ctc_alloc_stmt_context)
        .stubs()
        .will(invoke(MockCtcAllocStmtContext));
    MOCKER(knl_commit)
        .stubs()
        .will(invoke(MockKnlCommit));
    MOCKER(knl_commit4mysql)
        .stubs()
        .will(invoke(MockKnlCommit4Mysql));
    MOCKER(ctc_ddl_clear_stmt)
        .stubs()
        .will(invoke(MockCtcDdlClearStmt));
    MOCKER(ctc_trx_rollback)
        .stubs()
        .will(invoke(MockCtcTrxRollback));
    MOCKER(ctc_is_def_list_empty)
        .stubs()
        .will(invoke(MockCtcIsDefListEmpty));
    MOCKER(ctc_ddl_commit_log_put)
        .stubs()
        .will(invoke(MockCtcDdlCommitLogPut));
    MOCKER(ctc_ddl_table_after_commit_list)
        .stubs()
        .will(invoke(MockCtcDdlTableAfterCommitList));
    MOCKER(ctc_ddl_unlock_table)
        .stubs()
        .will(invoke(MockCtcDdlUnlockTable));
    MOCKER(sql_get_context_cache)
        .stubs()
        .will(invoke(MockSqlGetContextCache));
    MOCKER(ctx_write_text)
        .stubs()
        .will(invoke(MockCtxWriteText));
    MOCKER(sql_prepare_context_ctrl)
        .stubs()
        .will(invoke(MockSqlPrepareContextCtrl));
    MOCKER(sql_enrich_context_for_cached)
        .stubs()
        .will(invoke(MockSqlEnrichContextForCached));
    MOCKER(sql_cache_context)
        .stubs()
        .will(invoke(MockSqlCacheContext));
    MOCKER(sql_end_ctx_stat)
        .stubs()
        .will(invoke(MockSqlEndCtxStat));
    MOCKER(ctc_ddl_clear_stmt)
        .stubs()
        .will(invoke(MockSqlDdlClearStmt));
    MOCKER(cm_push)
        .stubs()
        .will(invoke(MockCmPush));

    bool is_ddl_commit = false;
    char *sql_str = {"SELECT * FROM test"};
    int32_t csize = 1;
    uint64_t *cursors = malloc(sizeof(uint64_t) * csize);
    if (cursors == nullptr) {
        ADD_FAILURE() << "Failed to allocate " << (sizeof(uint64_t) * csize) 
                      << " bytes for cursors";
        return;  
    }
    int ret = ctc_trx_commit(&mock_tch, cursors, csize, &is_ddl_commit, sql_str);
    EXPECT_EQ(ret, CT_SUCCESS);
}
