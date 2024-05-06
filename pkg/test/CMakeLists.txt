include_directories(
	"${CANTIANDB_SRC}/cms/interface"
        "${CANTIANDB_SRC}/upgrade_check"
#        "${CMAKE_CURRENT_SOURCE_DIR}/concurrency_test"
#        "${CMAKE_CURRENT_SOURCE_DIR}/shard_concurrency_test"
#        "${CMAKE_CURRENT_SOURCE_DIR}/zperf_test"
)

set(EXECUTABLE_OUTPUT_PATH ${CANTIANDB_BIN})

#cmake predefinitions
add_compile_definitions(CT_LIB_VERSION=${DD_CT_LIB_VERSION})
add_compile_definitions(GETDBVERSION=${DD_CT_LIB_VER_APINAME})

add_subdirectory(ct_regress)
#add_subdirectory(sharding_regress)
#add_subdirectory(concurrency_test)
#add_subdirectory(shard_concurrency_test)
#add_subdirectory(zbak_agent)
#add_subdirectory(odbc_demo)
#add_subdirectory(zperf_test)
#add_subdirectory(unit_test)
#add_subdirectory(cluster_test)
#add_subdirectory(cantian_fuzz_test)
#add_subdirectory(cms_fuzz_test)