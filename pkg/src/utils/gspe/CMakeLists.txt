#### ctencrypt ####
aux_source_directory(. CTENCRYPT_SRC)
add_executable(ctencrypt ${CTENCRYPT_SRC} ${VERSION_SRC})
if (USE_FUZZASAN)
    target_link_libraries(ctencrypt PRIVATE zecommon Secodefuzz)
else()
    target_link_libraries(ctencrypt PRIVATE zecommon)
endif(USE_FUZZASAN)
target_compile_definitions(ctencrypt PRIVATE -DCT_LIB_VERSION=${DD_CT_LIB_VERSION})
target_compile_definitions(ctencrypt PRIVATE -DGETDBVERSION=${DD_GETENCRYVERSION})
