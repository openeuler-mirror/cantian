message(STATUS "build cms_ut...")

include_directories(${CMAKE_SOURCE_DIR}/pkg/src/cms/cms)
include_directories(${CMAKE_SOURCE_DIR}/pkg/src/cms/interface)
set(CMS_UT_SOURCE ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/cms/cms_test_main.cpp
                ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/cms/cms_disk_lock_test.cpp)

#add_compile_options(-fno-common)
add_compile_options(-Wall -fpermissive)

#add_link_options(-Wl, -Bsymbolic)
add_link_options(-rdynamic)

add_executable(cms_test ${CMS_UT_SOURCE})
set_target_properties(cms_test PROPERTIES LINKER_LANGUAGE "CXX")

target_link_libraries(cms_test 
                     -Wl,--start-group 
                     gtest mockcpp gmock zetms zecms zeprotocol m rt dl z zstd lz4
                     zecmssrc zeclient zerc zecommon zemes zefdsa zectc zecluster
                     zeserver zekernel zesql pthread  z 
                     -Wl,--end-group)
target_compile_definitions(cms_test PRIVATE -DCT_LIB_VERSION=${DD_CT_LIB_VERSION})
target_compile_definitions(cms_test PRIVATE -DGETDBVERSION=${DD_GETDBVERSION})