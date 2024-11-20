message(STATUS "build ctbackup_ut...")

aux_source_directory(${CMAKE_SOURCE_DIR}/pkg/src/utils/ctbackup ctbackup_SRC)
set(CTBAKUP_UT_SOURCE ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/ctbackup/ctbackup_test_main.cpp
                ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/ctbackup/ctbackup_example_test.cpp)
list(REMOVE_ITEM ctbackup_SRC ${CMAKE_SOURCE_DIR}/pkg/src/utils/ctbackup/ctbackup_main.c)

#add_compile_options(-fno-common)
add_compile_options(-Wall -fpermissive)

#add_link_options(-Wl, -Bsymbolic)
add_link_options(-rdynamic)

add_executable(ctbackup_test ${CTBAKUP_UT_SOURCE} ${ctbackup_SRC})
set_target_properties(ctbackup_test PROPERTIES LINKER_LANGUAGE "CXX")

target_link_libraries(ctbackup_test 
                     -Wl,--start-group 
                     gtest mockcpp gmock zetms zecms zeprotocol m rt dl z zstd lz4
                     zecmssrc zeclient zerc zecommon zemes zefdsa zectc zecluster
                     zeserver zekernel zesql pthread  z 
                     -Wl,--end-group)
target_compile_definitions(ctbackup_test PRIVATE -DCT_LIB_VERSION=${DD_CT_LIB_VERSION})
target_compile_definitions(ctbackup_test PRIVATE -DGETDBVERSION=${DD_GETDBVERSION})