#### ctbackup ####
aux_source_directory(. ctbackup_SRC)

if (USE_FUZZASAN)
    add_compile_options(-fsanitize-coverage=trace-pc)
    ADD_EXECUTABLE(ctbackup ${ctbackup_SRC} ${VERSION_SRC})
    target_link_libraries(ctbackup PRIVATE zecommon Secodefuzz)
else ()
    ADD_EXECUTABLE(ctbackup ${ctbackup_SRC} ${VERSION_SRC})
    target_link_libraries(ctbackup PRIVATE zecommon zeclient)
endif(USE_FUZZASAN)
target_compile_definitions(ctbackup PRIVATE -DCT_LIB_VERSION=${DD_CT_LIB_VERSION})
target_compile_definitions(ctbackup PRIVATE -DGETDBVERSION=${DD_GETDBVERSION})
