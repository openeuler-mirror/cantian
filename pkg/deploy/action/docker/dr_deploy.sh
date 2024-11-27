#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
ld_path_src=${LD_LIBRARY_PATH}
export LD_LIBRARY_PATH=/opt/cantian/dbstor/lib:${LD_LIBRARY_PATH}
read -s -p "Please input mysql login passwd:" mysql_pwd
echo ""
echo -e "${mysql_pwd}" | python3 "${CURRENT_PATH}"/dr_deploy.py
if [[ $? -ne 0 ]];then
  echo "executing dr_deploy failed."
  export LD_LIBRARY_PATH=${ld_path_src}
  exit 1
fi
export LD_LIBRARY_PATH=${ld_path_src}