add_compile_options(-Werror)
add_compile_options(-Wno-psabi)
add_compile_options(-Wno-stringop-overflow)

execute_process(
        COMMAND uname -p
        OUTPUT_VARIABLE OS_ARCH
        OUTPUT_STRIP_TRAILING_WHITESPACE
)
if (OS_ARCH STREQUAL "aarch64")
    add_compile_options(-march=armv8.2-a+crc+lse -mno-outline-atomics)
endif()
add_subdirectory(common)
add_subdirectory(driver)
add_subdirectory(kernel)
add_subdirectory(server)
add_subdirectory(cmd)
add_subdirectory(protocol)
add_subdirectory(rc)
add_subdirectory(mec)
add_subdirectory(utils)
add_subdirectory(cms)
add_subdirectory(cluster)
add_subdirectory(tse)

if(NOT USE_OSS_BUILD)
    #    add_subdirectory(raft)
    #add_subdirectory(ztioa)
    add_subdirectory(gstbox)
    #add_subdirectory(gbp)
    # add_subdirectory(ctbox)
endif()
