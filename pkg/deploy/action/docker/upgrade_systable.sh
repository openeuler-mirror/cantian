#!/bin/bash

# usage:
# sh upgrade_systable.sh node_ip py_path old_initdb_path new_initdb_path sqls_path
# e.g.sh ./upgrade_systable.sh 0 ../../../install/ ../initdb.sql ./initdb_upgrade_sample.sql .
# sqls_path is where you stored upgrade and degrade sql file
CURRENT_PATH=$(dirname $(readlink -f $0))
echo "upgrade systable..."
export CANTIAND_PORT0=1611
node_ip=$1
py_path=$2
old_initdb=$3
new_initdb=$4
sqls_path=$5

echo "step1: upgrade systable check initdb..."
initdb=$(python ${py_path}/sql_process.py -t check-initdb --old-initdb=${old_initdb} --new-initdb=${new_initdb})

while read -r line; do
  if [ "$line" != "'TABLESPACE' is not in list" ]; then
      echo "upgrade systable check initdb failed"
      echo $line
      exit 1
  fi
done <<< "$initdb"

echo "step2: upgrade systable check white list..."
check_white_list=$(python ${py_path}/sql_process.py -t check-whitelist --sqls-path=${sqls_path})
if [ "${check_white_list}" ]; then
    echo "upgrade systable check white list failed"
    echo ${check_white_list}
    exit 1
fi

echo "step3: upgrade systable generate upgrade sqls..."
generate_sql=$(python ${py_path}/sql_process.py -t generate --old-initdb=${old_initdb} --new-initdb=${new_initdb} --outdir=${sqls_path} --sqls-path=${sqls_path})
if [ "${generate_sql}" ]; then
    echo "upgrade systable generate upgrade sqls failed"
    echo ${generate_sql}
    exit 1
fi

if [ ! -r "${sqls_path}/upgradeFile.sql" ]; then
    echo "upgrade systable generate upgrade sqls failed"
    echo ${generate_sql}
    exit 1
fi

echo "step4: upgrade systable execute upgrade sqls..."
read -s -p "Please Input SYS_PassWord: " user_pwd
echo ""
new_mark="/"
exec_result=$(echo -e "${sqls_path}\n${node_ip}\n${CANTIAND_PORT0}" | python3 -B ${CURRENT_PATH}/resolve_pwd.py run_upgrade_modify_sys_tables_ctsql ${user_pwd})

if [ $? -ne 0 ];then
    echo "upgrade systable excute upgrade sql: $sql failed"
    echo $exec_result
    exit 1
fi
echo "upgrade systable success"