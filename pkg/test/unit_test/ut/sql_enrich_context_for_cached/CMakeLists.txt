message(STATUS "build sql_enrich_context_for_cached_ut...")

include_directories(${CMAKE_SOURCE_DIR}/pkg/src/rc)
include_directories(${CMAKE_SOURCE_DIR}/pkg/src/common)
include_directories(${CMAKE_SOURCE_DIR}/pkg/src/ctc)
include_directories(${CMAKE_SOURCE_DIR}/library/protobuf)
set(sql_enrich_context_for_cached_UT_SOURCE ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/sql_enrich_context_for_cached/sql_enrich_context_for_cached_test_main.cpp
                ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/sql_enrich_context_for_cached/sql_enrich_context_for_cached_test.cpp)


#add_compile_options(-fno-common)
add_compile_options(-Wall -fpermissive)

#add_link_options(-Wl, -Bsymbolic)
add_link_options(-rdynamic)

add_executable(sql_enrich_context_for_cached_test ${sql_enrich_context_for_cached_UT_SOURCE})
set_target_properties(sql_enrich_context_for_cached_test PROPERTIES LINKER_LANGUAGE "CXX")

target_link_libraries(sql_enrich_context_for_cached_test 
                     -Wl,--start-group 
                     gtest mockcpp gmock zetms zecms zeprotocol m rt dl z zstd lz4
                     zecmssrc zeclient zerc zecommon zemes zefdsa zectc zecluster
                     zeserver zekernel zesql pthread  z 
                     -Wl,--end-group)
target_compile_definitions(sql_enrich_context_for_cached_test PRIVATE -DCT_LIB_VERSION=${DD_CT_LIB_VERSION})
target_compile_definitions(sql_enrich_context_for_cached_test PRIVATE -DGETDBVERSION=${DD_GETDBVERSION})
