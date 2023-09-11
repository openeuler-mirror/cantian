include_directories(
	"${CTDB_SRC}/cluster"
	"${CTDB_SRC}/cms/interface"
	"${CTDB_SRC}/rc"
        "${CTDB_SRC}/zenfs"
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/backup"
        "${CMAKE_CURRENT_SOURCE_DIR}/buffer"
        "${CMAKE_CURRENT_SOURCE_DIR}/catalog"
        "${CMAKE_CURRENT_SOURCE_DIR}/common/variant"
        "${CMAKE_CURRENT_SOURCE_DIR}/common"
        "${CMAKE_CURRENT_SOURCE_DIR}/daemon"
        "${CMAKE_CURRENT_SOURCE_DIR}/flashback"
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/index"
        "${CMAKE_CURRENT_SOURCE_DIR}/lob"
        "${CMAKE_CURRENT_SOURCE_DIR}/persist"
        "${CMAKE_CURRENT_SOURCE_DIR}/replication"
        "${CMAKE_CURRENT_SOURCE_DIR}/sequence"
        "${CMAKE_CURRENT_SOURCE_DIR}/statistics"
        "${CMAKE_CURRENT_SOURCE_DIR}/table"
        "${CMAKE_CURRENT_SOURCE_DIR}/tablespace"
        "${CMAKE_CURRENT_SOURCE_DIR}/xact"
)

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR} KERNEL_SRC)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/backup KERNEL_BAK_SRC)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/buffer KERNEL_BUF_SRC)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/catalog KERNEL_CATA_SRC)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/common KERNEL_CM_SRC)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/daemon KERNEL_DAE_SRC)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/flashback KERNEL_FLASH_SRC)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/include KERNEL_INCLUDE_SRC)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/index KERNEL_IDX_SRC)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/lob KERNEL_LOB_SRC)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/persist KERNEL_PER_SRC)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/replication KERNEL_REP_SRC)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/sequence KERNEL_SEQ_SRC)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/statistics KERNEL_STAT_SRC)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/table KERNEL_TBL_SRC)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/tablespace KERNEL_TBLSP_SRC)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/xact KERNEL_XACT_SRC)


set(KERNEL_TOTAL_SRC ${KERNEL_BAK_SRC} ${KERNEL_BUF_SRC} ${KERNEL_CATA_SRC} ${KERNEL_CM_SRC} ${KERNEL_DAE_SRC}
        ${KERNEL_FLASH_SRC} ${KERNEL_INCLUDE_SRC} ${KERNEL_IDX_SRC} ${KERNEL_LOB_SRC} ${KERNEL_PER_SRC} ${KERNEL_REP_SRC}
        ${KERNEL_SEQ_SRC} ${KERNEL_STAT_SRC} ${KERNEL_TBL_SRC} ${KERNEL_TBLSP_SRC} ${KERNEL_XACT_SRC} ${KERNEL_SRC})

link_directories(${CTDB_LIB})

add_library(zekernel STATIC ${KERNEL_TOTAL_SRC})

