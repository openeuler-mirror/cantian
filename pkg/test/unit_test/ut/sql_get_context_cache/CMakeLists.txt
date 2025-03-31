message(STATUS "build sql_get_context_cache_ut...")

include_directories(${CMAKE_SOURCE_DIR}/pkg/src/rc)
include_directories(${CMAKE_SOURCE_DIR}/pkg/src/common)
include_directories(${CMAKE_SOURCE_DIR}/pkg/src/ctc)
include_directories(${CMAKE_SOURCE_DIR}/library/protobuf)
set(sql_get_context_cache_UT_SOURCE ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/sql_get_context_cache/sql_get_context_cache_test_main.cpp
                ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/sql_get_context_cache/sql_get_context_cache_test.cpp)


#add_compile_options(-fno-common)
add_compile_options(-Wall -fpermissive)

#add_link_options(-Wl, -Bsymbolic)
add_link_options(-rdynamic)

add_executable(sql_get_context_cache_test ${sql_get_context_cache_UT_SOURCE})
set_target_properties(sql_get_context_cache_test PROPERTIES LINKER_LANGUAGE "CXX")

target_link_libraries(sql_get_context_cache_test 
                     -Wl,--start-group 
                     gtest mockcpp gmock zetms zecms zeprotocol m rt dl z zstd lz4
                     zecmssrc zeclient zerc zecommon zemes zefdsa zectc zecluster
                     zeserver zekernel zesql pthread  z 
                     -Wl,--end-group)
target_compile_definitions(sql_get_context_cache_test PRIVATE -DCT_LIB_VERSION=${DD_CT_LIB_VERSION})
target_compile_definitions(sql_get_context_cache_test PRIVATE -DGETDBVERSION=${DD_GETDBVERSION})
