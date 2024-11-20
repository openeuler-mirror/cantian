#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <mockcpp/mockcpp.hpp>


#ifdef __cplusplus
extern "C" {
#endif 

char *cantiand_get_dbversion()
{
    return "NONE";
}

#ifdef __cplusplus
}
#endif

int main(int argc, char **argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}