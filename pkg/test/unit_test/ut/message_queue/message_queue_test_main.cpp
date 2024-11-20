#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <mockcpp/mockcpp.hpp>
#include "message_queue/dsw_list.h"
#include "message_queue/shm_thread_pool.h"
#include "message_queue/dsw_shm_pri.h"
#include "message_queue/dsw_shm.h"

struct key_map_s {
    shm_key_t key;
    unsigned long addr;
};

extern "C"
{
    int shm_get_shm_type_and_addr(char *tokens[], struct key_map_s *key_map, int n, int lineno, int *count,
        int *is_count);
}

class TestShm : public testing::Test {
protected: 
    
    static void SetUpTestCase()
    {
    }

    static void TearDownTestCase()
    {
    }
  
};

TEST_F(TestShm, shm_get_shm_type_and_addr_should_return_ok_when_normal)
{
    char *tokens[] = {"mmap", "test1", "test2"};
    struct key_map_s *key_map = (key_map_s *)malloc(sizeof(key_map_s));
    int *count;
    int *is_count;
    MOCKER(strcpy_s).stubs().will(returnValue(0));
    int ret = shm_get_shm_type_and_addr(tokens, key_map, 0, 0, count, is_count);
    EXPECT_EQ(ret, -1);
    free(key_map);
}

int main(int argc, char **argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}