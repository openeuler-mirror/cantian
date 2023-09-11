include_directories(
	"${CTDB_SRC}/cluster"
	"${CTDB_SRC}/rc"
        "${CTDB_SRC}/cms/interface"
)

#### gstbox ####
aux_source_directory(. GSTBOX_SRC)
add_executable(ztbox ${GSTBOX_SRC} ${VERSION_SRC})
if (USE_FUZZASAN)
    target_link_libraries(ztbox PRIVATE
                         -Wl,--start-group
                         zeserver zesql zemes zeprotocol zekernel zeclient zecommon zecluster zecms zerc m rt pthread dl z zstd lz4 Secodefuzz
                         -Wl,--end-group)
else()
    target_link_libraries(ztbox PRIVATE
                         -Wl,--start-group
                         zeserver zesql zemes zeprotocol zekernel zeclient zecommon zecluster zecms zerc m rt pthread dl z zstd lz4
                         -Wl,--end-group)
endif(USE_FUZZASAN)
target_compile_definitions(ztbox PRIVATE -DGS_LIB_VERSION=${DD_GS_LIB_VERSION})
target_compile_definitions(ztbox PRIVATE -DGETDBVERSION=${DD_GETDBVERSION})
