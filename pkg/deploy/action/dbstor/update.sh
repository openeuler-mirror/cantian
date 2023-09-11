#!/bin/bash
# --NAMESPACE_FSNAME: namespace file system name
#    --DPU_UUID:         dpu uuid
#    --LINK_TYPE:        link type
#    --LOCAL_IP:         local ip address
#    --REMOTE_IP:        remote ip
CURRENT_PATH=$(dirname $(readlink -f $0))
NAMESPACE_FSNAME=""
DPU_UUID=""
LINK_TYPE=""
LOCAL_IP=""
REMOTE_IP=""

usage() {
  echo "# -n  --NAMESPACE_FSNAME: namespace file system name"
  echo "# -d  --DPU_UUID:         dpu uuid"
  echo "# -t --LINK_TYPE:        link type"
  echo "# -i --LOCAL_IP:         local ip address"
  echo "# -r  --REMOTE_IP:        remote ip"
  echo "# The account and password are changed by default"
  exit 0
}
echo $1
if [ "$1" = "--help" ]; then
    usage
fi

while getopts n:d:t:i:r: option; do
    case ${option} in
    n)
      NAMESPACE_FSNAME=${OPTARG}
      echo "NAMESPACE_FSNAME=${OPTARG}"
      ;;
    d)
      DPU_UUID=${OPTARG}
      echo "DPU_UUID=${OPTARG}"
      ;;
    t)
      LINK_TYPE=${OPTARG}
      echo "LINK_TYPE=${OPTARG}"
      ;;
    i)
      LOCAL_IP=${OPTARG}
      echo "LOCAL_IP=${OPTARG}"
      ;;
    r)
      REMOTE_IP=${OPTARG}
      echo "REMOTE_IP=${OPTARG}"
      ;;
    :)
      usage
      ;;
    *)
      usage
      ;;
    esac
done

user=$(python3 ${CURRENT_PATH}/../cantian/get_config_info.py "deploy_user")
current_user=$(whoami)

if [[ ${user} != ${current_user} ]]; then
    echo "please switch the current user to ${user}"
    exit 1
fi

local_path=$LD_LIBRARY_PATH
export LD_LIBRARY_PATH=/opt/cantian/dbstor/lib/:$LD_LIBRARY_PATH
python update_dbstor_config.py --NAMESPACE_FSNAME=${NAMESPACE_FSNAME} --DPU_UUID=${DPU_UUID} --LINK_TYPE=${LINK_TYPE} --LOCAL_IP=${LOCAL_IP} --REMOTE_IP=${REMOTE_IP}
ret=$?
export LD_LIBRARY_PATH=$local_path
if [ "${ret}" != 0 ]; then
    echo "update failed!"
    exit 1
fi
echo "update success"