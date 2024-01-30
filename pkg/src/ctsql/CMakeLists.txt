include_directories(
	"${CANTIANDB_SRC}/cluster"
	"${CANTIANDB_SRC}/rc"
	"${CANTIANDB_SRC}/cms/interface"
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/catalog"
        "${CMAKE_CURRENT_SOURCE_DIR}/executor"
        "${CMAKE_CURRENT_SOURCE_DIR}/json"
        "${CMAKE_CURRENT_SOURCE_DIR}/node"
        "${CMAKE_CURRENT_SOURCE_DIR}/function"
        "${CMAKE_CURRENT_SOURCE_DIR}/optimizer"
        "${CMAKE_CURRENT_SOURCE_DIR}/parser"
        "${CMAKE_CURRENT_SOURCE_DIR}/parser_ddl"
        "${CMAKE_CURRENT_SOURCE_DIR}/plan"
        "${CMAKE_CURRENT_SOURCE_DIR}/pl"
        "${CMAKE_CURRENT_SOURCE_DIR}/pl/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/pl/type"
        "${CMAKE_CURRENT_SOURCE_DIR}/verifier"
        "${CMAKE_CURRENT_SOURCE_DIR}/gdv"

)

set(LIBRARY_OUTPUT_PATH ${CANTIANDB_LIB})

aux_source_directory(. SQL_SRC)
aux_source_directory(./catalog SQL_CATALOG_SRC)
aux_source_directory(./executor SQL_EXECUTOR_SRC)
aux_source_directory(./json SQL_JSON_SRC)
aux_source_directory(./node SQL_NODE_SRC)
aux_source_directory(./function SQL_FUNCTION_SRC)
aux_source_directory(./optimizer SQL_OPTIMIZER_SRC)
aux_source_directory(./parser SQL_PARSER_SRC)
aux_source_directory(./parser_ddl SQL_DDL_PARSER_SRC)
aux_source_directory(./verifier SQL_VERIFIER_SRC)
aux_source_directory(./plan SQL_PLAN_SRC)
aux_source_directory(./gdv SQL_GDV_SRC)
aux_source_directory(./pl SQL_PL_SRC)
aux_source_directory(./pl/include SQL_PL_INC_SRC)
aux_source_directory(./pl/type SQL_PL_TYPE_SRC)
#aux_source_directory(./pl/clang SQL_PL_CLANG_SRC)
aux_source_directory(./pl/debug SQL_PL_DEBUG_SRC)
aux_source_directory(./pl/meta SQL_PL_META_SRC)
aux_source_directory(./pl/persist SQL_PL_PERSIST_SRC)
aux_source_directory(./pl/parser SQL_PL_PARSER_SRC)
aux_source_directory(./pl/ast SQL_PL_AST_SRC)
aux_source_directory(./pl/executor SQL_PL_EXECUTOR_SRC)
aux_source_directory(./pl/common SQL_PL_COMMON_SRC)
set(PL_TOTAL_SRC ${SQL_PL_SRC} ${SQL_PL_INC_SRC} ${SQL_PL_TYPE_SRC} ${SQL_PL_CLANG_SRC} ${SQL_PL_DEBUG_SRC} ${SQL_PL_META_SRC} ${SQL_PL_PERSIST_SRC} ${SQL_PL_PARSER_SRC} ${SQL_PL_AST_SRC} ${SQL_PL_EXECUTOR_SRC} ${SQL_PL_COMMON_SRC})
set(SQL_ALL_SRC
        ${SQL_SRC}
        ${SQL_CATALOG_SRC}
        ${SQL_EXECUTOR_SRC}
        ${SQL_NODE_SRC}
        ${SQL_FUNCTION_SRC}
        ${SQL_JSON_SRC}
        ${SQL_OPTIMIZER_SRC}
        ${SQL_PARSER_SRC}
        ${SQL_DDL_PARSER_SRC}
        ${SQL_VERIFIER_SRC}
        ${SQL_PLAN_SRC}
	${SQL_GDV_SRC}
        )

link_directories(${CANTIANDB_LIB} ${PCRE_LIB_PATH} ${VPP_LIB_PATH} ${Z_LIB_PATH})

add_library(zesql STATIC ${SQL_ALL_SRC} ${PL_TOTAL_SRC})
if (USE_FUZZASAN)
target_link_libraries(zesql PRIVATE zekernel)
endif(USE_FUZZASAN)
