include_directories(
	"${CANTIANDB_SRC}/cluster"
	"${CANTIANDB_SRC}/rc"
        "${CANTIANDB_SRC}/cms/interface"
)

#### ctbox ####
aux_source_directory(. CTBOX_SRC)
add_executable(ctbox ${CTBOX_SRC} ${VERSION_SRC})
if (USE_FUZZASAN)
    target_link_libraries(ctbox PRIVATE -Wl,--start-group zeserver zesql zemes zeprotocol zekernel zeclient zecommon zecluster zecms zerc m rt pthread dl z zstd lz4 Secodefuzz -Wl,--end-group)
else()
    target_link_libraries(ctbox PRIVATE -Wl,--start-group zeserver zesql zemes zeprotocol zekernel zeclient zecommon zecluster zecms zerc m rt pthread dl z zstd lz4 -Wl,--end-group)
endif(USE_FUZZASAN)
target_compile_definitions(ctbox PRIVATE -DCT_LIB_VERSION=${DD_CT_LIB_VERSION})
target_compile_definitions(ctbox PRIVATE -DGETDBVERSION=${DD_GETDBVERSION})
