#!/bin/bash
export CANTIAND_PORT0=1611
echo "make full checkpoint..."
node_ip=$1
read -s -p "Please Input SYS_PassWord: " user_pwd
ctclient sys/${user_pwd}@${node_ip}:${CANTIAND_PORT0} -q -c "alter system checkpoint global;"

if [[ $? = 0 ]]
then
        echo "make full checkpoint success"
else
        echo "make full checkpoint failed"
        exit 1
fi