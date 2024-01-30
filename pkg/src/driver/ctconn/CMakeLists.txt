include_directories(
        "${CMAKE_CURRENT_SOURCE_DIR}"
)

link_directories(${CANTIANDB_LIB} ${PCRE_LIB_PATH} ${VPP_LIB_PATH} ${Z_LIB_PATH})
set(M_EXP_SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/m.exp)

aux_source_directory(. CTCONN_SRC)
aux_source_directory(${CMAKE_SOURCE_DIR}/pkg/src/protocol PROTOCOL_SRC)
set(CLIENT_SRC
        ${CTCONN_SRC}
        ${PROTOCOL_SRC}
        ${DRIVER_VERSION_SRC}
        )

# Precompiled options
add_compile_definitions(CT_DRIVER_VERSION=${DD_CT_DRIVER_VERSION})
add_compile_definitions(GET_DRIVER_VERSION=${DD_CT_LIB_VER_APINAME})

add_compile_options(-Wl,-z,now)

# generate static library
add_library(zeclient_static STATIC ${CLIENT_SRC})
# generate dynamic library
add_library(zeclient SHARED ${CLIENT_SRC})

set_target_properties(zeclient PROPERTIES OUTPUT_NAME zeclient
        CLEAN_DIRECT_OUTPUT 1
        ARCHIVE_OUTPUT_DIRECTORY ${CANTIANDB_LIB}
        )
set_target_properties(zeclient_static PROPERTIES OUTPUT_NAME zeclient
        CLEAN_DIRECT_OUTPUT 1
        ARCHIVE_OUTPUT_DIRECTORY ${CANTIANDB_LIB}
        )

if (USE32BIT)
    MESSAGE(STATUS "Build Libclient in 32 bits")
    set_target_properties(zeclient PROPERTIES
            COMPILE_FLAGS "-m32" LINK_FLAGS "-m32"
            )
    set_target_properties(zeclient_static PROPERTIES
            COMPILE_FLAGS "-m32" LINK_FLAGS "-m32"
            )
else ()
    MESSAGE(STATUS "Build Libclient in 64 bits")
endif (USE32BIT)

option(USE_FUZZASAN OFF)
if (USE_FUZZASAN)
    target_link_libraries(zeclient PRIVATE zecommon -Wl,--version-script=${M_EXP_SCRIPT} -Wl,--whole-archive ${vpp_libsecurec} ${vpp_libipsi_crypto} ${vpp_libipsi_ssl} ${hw_kmc_lib} ${hw_sdp_lib} -Wl,--no-whole-archive pthread dl m rt pcre2-8 Secodefuzz)
else ()
    target_link_libraries(zeclient PRIVATE zecommon -Wl,--version-script=${M_EXP_SCRIPT} -Wl,--whole-archive ${vpp_libsecurec} ${vpp_libipsi_crypto} ${vpp_libipsi_ssl} ${hw_kmc_lib} ${hw_sdp_lib} -Wl,--no-whole-archive pthread dl m rt pcre2-8)
endif(USE_FUZZASAN)
