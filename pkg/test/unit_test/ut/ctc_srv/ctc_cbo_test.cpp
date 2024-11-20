#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <mockcpp/mockcpp.hpp>

extern "C" {
#include "ctc_srv_util.h"
#include "ctc_srv.h"
#include "ctc_cbo.h"
#include "ostat_load.h"
#include "knl_defs.h"
#include "srv_session.h"
#include "knl_heap.h"
}

extern "C" {
    status_t fill_part_table_cbo_stats_index(knl_handle_t handle, dc_entity_t *entity, ctc_cbo_stats_t *stats);
}

using namespace std;
static cbo_stats_table_t *table_stats = NULL;
static ctc_cbo_stats_t *stats = NULL;
static cbo_stats_column_t *column = NULL;
static dc_entity_t *entity = NULL;

const int COLUMN_NUMS = 10;

class TestCtcCbo : public testing::Test {
protected: 
    
    void SetUp() override
    {
        if (table_stats == NULL) {
            table_stats = (cbo_stats_table_t *)malloc(sizeof(cbo_stats_table_t));
            table_stats->rows = 1;
            table_stats->blocks = 1;
            table_stats->max_part_no = 1;
            table_stats->max_col_id = 0;
        }
        if (column == NULL) {
            column = (cbo_stats_column_t *)malloc(sizeof(cbo_stats_column_t));
            column->num_distinct = COLUMN_NUMS;
        }
        if (entity == NULL) {
            entity = (dc_entity_t *)malloc(sizeof(dc_entity_t));
            entity->table.part_table = (st_part_table *)malloc(sizeof(st_part_table));
            entity->table.part_table->desc.partcnt = 1;
        }
        if (stats == NULL) {
            stats = (ctc_cbo_stats_t *)malloc(sizeof(ctc_cbo_stats_t) + sizeof(uint32_t) * 2);
            stats->ctc_cbo_stats_table = 
                (ctc_cbo_stats_table_t *)malloc(sizeof(ctc_cbo_stats_table_t));
            stats->ctc_cbo_stats_table->columns = 
                (ctc_cbo_stats_column_t *)malloc(sizeof(ctc_cbo_stats_column_t));
            stats->ctc_cbo_stats_table->estimate_rows = 1;
        }
    }

    void TearDown() override
    {
        if (table_stats != NULL) {
            free(table_stats);
            table_stats = nullptr;
        }
        if (stats != NULL) {
            free(stats->ctc_cbo_stats_table->columns);
            free(stats);
            stats = nullptr;
        }
        if (column != NULL) {
            free(column);
            column = nullptr;
        }
        if (entity != NULL) {
            free(entity);
            entity = nullptr;
        }
    }
    
    knl_handle_t handle;
};

TEST_F(TestCtcCbo, Should_return_status_true_when_get_cbo_stats)
{
    stats->is_updated = false;
    MOCKER(knl_is_part_table).stubs().will(returnValue(CT_TRUE));
    MOCKER(knl_get_cbo_part_table).stubs().will(returnValue(table_stats));
    MOCKER(knl_is_compart_table).stubs().will(returnValue(CT_FALSE));
    MOCKER(fill_part_table_cbo_stats_index).stubs().will(returnValue(CT_ERROR));
    status_t ret = get_cbo_stats(handle, entity, stats, stats->ctc_cbo_stats_table, 0, 0);
    EXPECT_EQ(ret, CT_ERROR);
    GlobalMockObject::verify();
}
