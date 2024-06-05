##### ctrst ####
set(CTRST_ALL_SRC
        ctrst_main.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ctsql/ctsql.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ctsql/ctsql_wsr.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ctsql/ctsql_common.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ctsql/ctsql_dump.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ctsql/ctsql_exp_bin.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ctsql/ctsql_export.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ctsql/ctsql_import.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ctsql/ctsql_input_bind_param.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ctsql/ctsql_load.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ctsql/ctsql_option.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ctsql/ctsql_wsr_analyse.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ctsql/ctsql_wsr_common.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ctsql/ctsql_wsr_head.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ctsql/ctsql_wsr_monitor.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ctsql/ctsql_wsr_parameter.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ctsql/ctsql_wsr_segment.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ctsql/ctsql_wsr_session.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ctsql/ctsql_wsr_snap.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ctsql/ctsql_wsr_sql.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ctsql/ctsql_wsr_buffer.c
        )

ADD_EXECUTABLE(ctrst ${CTRST_ALL_SRC} ${VERSION_SRC})
target_include_directories(ctrst PUBLIC
	"${PROJECT_SOURCE_DIR}/src/utils"
	"${PROJECT_SOURCE_DIR}/src/driver/gsc"
  "${CANTIANDB_SRC}/cms/interface")
if (USE_FUZZASAN)
    target_link_libraries(ctrst PRIVATE zeserver zesql zemes zeprotocol zekernel zeclient zecommon m rt pthread dl z zstd lz4 Secodefuzz) 
else()
    target_link_libraries(ctrst PRIVATE zeserver zesql zemes zeprotocol zekernel zeclient zecommon m rt pthread dl z zstd lz4)
endif(USE_FUZZASAN)
target_compile_definitions(ctrst PRIVATE -DCT_LIB_VERSION=${DD_CT_LIB_VERSION})
target_compile_definitions(ctrst PRIVATE -DGETDBVERSION=${DD_GETDBVERSION})
