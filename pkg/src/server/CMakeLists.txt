include_directories(
    "${CANTIANDB_SRC}/cms/interface"
	"${CANTIANDB_SRC}/cluster"
	"${CANTIANDB_SRC}/rc"
	"${CANTIANDB_SRC}/zenfs"
    "${CANTIANDB_SRC}/tse"
	"${CANTIANDB_SRC}/ctsql/gdv"
    "${CANTIANDB_SRC}/upgrade_check"
    "${CANTIANDB_SRC}/fdsa"
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/params"
)

option(NO_SHM OFF)
if (NO_SHM)
    add_compile_definitions(WITH_DAAC)
    message(STATUS "Toolchain: Build use -DWITH_DAAC")
endif (NO_SHM)

link_directories(${CANTIANDB_LIB} "${CANTIANDB_LIBRARY}/protobuf/lib" ${PCRE_LIB_PATH})

aux_source_directory(. SERVER_SRC)
aux_source_directory(./params SERVER_PARAMS_SRC)
aux_source_directory(${CMAKE_SOURCE_DIR}/pkg/src/shard SHARD_SRC)
aux_source_directory(${CMAKE_SOURCE_DIR}/pkg/src/shard/rebalance SHD_REBALANCE_SRC)
aux_source_directory(${CMAKE_SOURCE_DIR}/pkg/src/shard/ddl SHD_DDL_SRC)
aux_source_directory(${CMAKE_SOURCE_DIR}/pkg/src/shard/dml SHD_DML_SRC)
aux_source_directory(${CMAKE_SOURCE_DIR}/pkg/src/shard/route SHD_ROUTE_SRC)
aux_source_directory(${CMAKE_SOURCE_DIR}/pkg/src/shard/adapter SHD_ADAPTER_SRC)
set(SHARD_TOTAL_SRC ${SHARD_SRC} ${SHD_REBALANCE_SRC} ${SHD_DDL_SRC} ${SHD_DML_SRC} ${SHD_ROUTE_SRC} ${SHD_ADAPTER_SRC})

add_library(zeserver STATIC ${SERVER_SRC} ${SERVER_PARAMS_SRC}  ${SHARD_TOTAL_SRC})
if (USE_FUZZASAN)
target_link_libraries(zeserver PRIVATE zecluster zecms Secodefuzz zesql zemes)
else ()
target_link_libraries(zeserver PRIVATE zecluster zecms)
endif(USE_FUZZASAN)

#### cantiand ####
# Precompiled options
option(USE_FUZZASAN OFF)
if (USE_FUZZASAN)
    add_compile_options(-fsanitize-coverage=trace-pc)
    ADD_EXECUTABLE(cantiand ${VERSION_SRC})
    target_link_libraries(cantiand PRIVATE
                          -Wl,--start-group
                          zeserver zectc zesql zekernel zemes zeprotocol zecommon zeclient
                          zecluster zecms zerc m rt pthread dl z zstd lz4 Secodefuzz
                          -Wl,--end-group)
else ()
    ADD_EXECUTABLE(cantiand ${VERSION_SRC})
    target_link_libraries(cantiand PRIVATE
                          -Wl,--start-group
                          zeserver zectc zesql zekernel zemes zeprotocol zecommon zeclient
                          zecluster zecms zerc m rt pthread dl z zstd lz4
                          -Wl,--end-group)
endif(USE_FUZZASAN)
target_compile_definitions(cantiand PRIVATE -DCT_LIB_VERSION=${DD_CT_LIB_VERSION})
target_compile_definitions(cantiand PRIVATE -DGETDBVERSION=${DD_GETDBVERSION})
