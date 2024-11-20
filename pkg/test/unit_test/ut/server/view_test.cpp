#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <mockcpp/mockcpp.hpp>

extern "C" {
#include "cm_io_record.h"
#include "ctc_srv.h"
#include "knl_interface.h"
#include "cse_stats.h"
}

#ifdef __cplusplus
extern "C" {
#endif
status_t vw_syncpoint_stat_open(knl_handle_t se, knl_cursor_t *cursor);
status_t vw_syncpoint_stat_fetch(knl_handle_t session, knl_cursor_t *cursor);
status_t vw_ctc_io_fetch(knl_handle_t session, knl_cursor_t *cursor);
#ifdef __cplusplus
}
#endif


class view_test : public testing::Test
{
protected:
    void SetUp() override
    {
    }
    void TearDown() override
    {
    }
};

TEST(view_test, test1)
{
    knl_handle_t se = 0;
    knl_cursor_t cursor;
    status_t ret = vw_syncpoint_stat_open(se, &cursor);
    EXPECT_EQ(ret, CT_SUCCESS);
}