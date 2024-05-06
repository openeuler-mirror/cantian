## ct_regress ##
add_executable(ct_regress ct_regress_main.c)
set_target_properties(ct_regress PROPERTIES LINKER_LANGUAGE "C")
set_target_properties(ct_regress PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CANTIANDB_BIN})
if (USE_FUZZASAN)
     target_link_libraries(ct_regress PRIVATE zeclient zeprotocol zesql zekernel zecommon dl m rt pthread z zstd lz4 Secodefuzz)
else ()
     target_link_libraries(ct_regress PRIVATE zeclient zeprotocol zesql zekernel zecommon dl m rt pthread z zstd lz4)
endif(USE_FUZZASAN)
