include_directories(
        "${CANTIANDB_SRC}/cms/interface"
	"${CANTIANDB_SRC}/cluster"
	"${CANTIANDB_SRC}/rc"
        "${CANTIANDB_SRC}/kernel/statistics"
	"${CANTIANDB_SRC}/zenfs"
        "${CANTIANDB_SRC}/tse"
        "${CANTIANDB_LIBRARY}/protobuf/"
	"${CANTIANDB_SRC}/ctsql/gdv"
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/protobuf"
        "${CMAKE_CURRENT_SOURCE_DIR}/message_queue"
)
link_directories(${CANTIANDB_LIB} "${CANTIANDB_LIBRARY}/protobuf/lib")
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-pointer-sign -Wno-unused-but-set-variable -Wno-int-to-pointer-cast -Wno-unused-variable -Wno-discarded-qualifiers -Wno-implicit-function-declaration -Wno-format -Wno-switch -Wno-incompatible-pointer-types -Wno-unused-function -Wno-pointer-to-int-cast")
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-pointer-sign -Wno-unused-but-set-variable -Wno-int-to-pointer-cast -Wno-unused-variable -Wno-discarded-qualifiers -Wno-format -Wno-switch -Wno-incompatible-pointer-types -Wno-unused-function -Wno-pointer-to-int-cast")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-variable -Wno-unused-function -Wno-discarded-qualifiers -Wno-format -Wno-switch -Wno-unused-but-set-variable -Wno-incompatible-pointer-types -Wno-pointer-to-int-cast -Wno-int-to-pointer-cast")
aux_source_directory(. TSE_SRC)
aux_source_directory(./message_queue TSE_MQ_SRC)
aux_source_directory(./protobuf TSE_PB_SRC)

add_library(zectc STATIC ${TSE_SRC} ${TSE_MQ_SRC}  ${TSE_PB_SRC})
if (USE_FUZZASAN)
        add_compile_options(-fsanitize-coverage=trace-pc)
        target_link_libraries(zectc PRIVATE zeserver libprotobuf-c.a rt Secodefuzz)
else ()
        target_link_libraries(zectc PRIVATE zeserver libprotobuf-c.a rt)
endif(USE_FUZZASAN)