include_directories(
    "${CTDB_SRC}/cms/interface"
	"${CTDB_SRC}/cluster"
	"${CTDB_SRC}/rc"
	"${CTDB_SRC}/zenfs"
    "${CTDB_SRC}/tse"
	"${CTDB_SRC}/sql/gdv"
    "${CTDB_SRC}/upgrade_check"
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/params"
)

option(NO_SHM OFF)
if (NO_SHM)
    add_compile_definitions(WITH_DAAC)
    message(STATUS "Toolchain: Build use -DWITH_DAAC")
endif (NO_SHM)

link_directories(${CTDB_LIB} "${CTDB_LIBRARY}/protobuf/lib" ${PCRE_LIB_PATH})

aux_source_directory(. SERVER_SRC)
aux_source_directory(./params SERVER_PARAMS_SRC)

add_library(zeserver STATIC ${SERVER_SRC} ${SERVER_PARAMS_SRC})
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
target_compile_definitions(cantiand PRIVATE -DGS_LIB_VERSION=${DD_GS_LIB_VERSION})
target_compile_definitions(cantiand PRIVATE -DGETDBVERSION=${DD_GETDBVERSION})
