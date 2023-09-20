include_directories(
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/variant"
)

aux_source_directory(. COMMON_SRC)
aux_source_directory(./variant COMMON_VARIANT_SRC)


set(COMMON_ALL_SRC
        ${COMMON_VARIANT_SRC}
        ${COMMON_SRC}
        )

# KMC need additional compiling macro:
add_compile_definitions(WSEC_COMPILE_CAC_OPENSSL)
add_compile_definitions(WSEC_USE_OPENSSL_110)
add_compile_definitions(WSEC_AES_GCM_SUPPORT)
add_compile_definitions(WSEC_ERR_CODE_BASE=0x10000000)
add_compile_definitions(WSEC_DEBUG)
add_compile_definitions(WSEC_TRACE_MEMORY)
add_compile_definitions(WSEC_COMPILE_MIP_OTHER)
option(USE_FUZZASAN OFF)
if (USE_FUZZASAN)
    add_compile_options(-fsanitize-coverage=trace-pc)
endif(USE_FUZZASAN)
# generate static library
add_library(zecommon_static STATIC ${COMMON_ALL_SRC})
# generate dynamic library
add_library(zecommon SHARED ${COMMON_ALL_SRC})
# dynamic libraries and static libraries exist at the same time
set_target_properties(zecommon PROPERTIES OUTPUT_NAME zecommon
        CLEAN_DIRECT_OUTPUT 1
        ARCHIVE_OUTPUT_DIRECTORY ${CTDB_LIB}
        )
set_target_properties(zecommon_static PROPERTIES OUTPUT_NAME zecommon
        CLEAN_DIRECT_OUTPUT 1
        ARCHIVE_OUTPUT_DIRECTORY ${CTDB_LIB}
        )
if (USE_FUZZASAN)
    target_link_libraries(zecommon PRIVATE -Wl,--whole-archive ${vpp_libipsi_crypto} ${vpp_libipsi_ssl} -Wl,--no-whole-archive pthread dl m rt pcre2-8 Secodefuzz)
else ()
target_link_libraries(zecommon PRIVATE -Wl,--whole-archive ${vpp_libipsi_crypto} ${vpp_libipsi_ssl} -Wl,--no-whole-archive pthread dl m rt pcre2-8)
endif(USE_FUZZASAN)

target_link_libraries(zecommon PUBLIC
    ${vpp_libsecurec})