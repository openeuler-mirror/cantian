#!/bin/bash
set +x

sh /opt/cantian/image/cantian_connector/for_mysql_official/patch.sh
cp -arf /opt/cantian/image/cantian_connector/for_mysql_official/mf_connector_mount_dir/ /opt/cantian/mysql/server/