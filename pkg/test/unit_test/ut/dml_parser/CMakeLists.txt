message(STATUS "build dml_parser_ut...")

include_directories(${CMAKE_SOURCE_DIR}/pkg/src/ctc)
include_directories(${CMAKE_SOURCE_DIR}/pkg/src/ctsql/parser)
include_directories(${CMAKE_SOURCE_DIR}/pkg/src/ctsql)
include_directories(${CMAKE_SOURCE_DIR}/library/protobuf)
include_directories(${CMAKE_SOURCE_DIR}/pkg/src/rc)
include_directories(${CMAKE_SOURCE_DIR}/pkg/src/common)
set(DML_PARSER_UT_SOURCE ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/dml_parser/dml_parser_test_main.cpp
                ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/dml_parser/sql_cache_context_test.cpp
                )

#add_compile_options(-fno-common)
add_compile_options(-Wall -fpermissive)

#add_link_options(-Wl, -Bsymbolic)
add_link_options(-rdynamic)

add_executable(dml_parser_test ${DML_PARSER_UT_SOURCE})
set_target_properties(dml_parser_test PROPERTIES LINKER_LANGUAGE "CXX")

target_link_libraries(dml_parser_test 
                     -Wl,--start-group 
                     gtest mockcpp gmock zetms zecms zeprotocol m rt dl z zstd lz4
                     zecmssrc zeclient zerc zecommon zemes zefdsa zectc zecluster
                     zeserver zekernel zesql pthread  z 
                     -Wl,--end-group)
target_compile_definitions(dml_parser_test PRIVATE -DCT_LIB_VERSION=${DD_CT_LIB_VERSION})
target_compile_definitions(dml_parser_test PRIVATE -DGETDBVERSION=${DD_GETDBVERSION})