FROM {{ .Values.images.cantian_base_arm }}
RUN useradd -m ctdba -u 5000
WORKDIR /ctdb/cantian_install
RUN rm -rf *
COPY Cantian_.aarch64_RELEASE.tgz .
COPY DBStor_Clientaarch64_RELEASE.tgz .
COPY Cantian_connector_mysql_aarch64_RELEASE.tgz .
RUN tar -zxf Cantian.aarch64_RELEASE.tgz && rm -rf Cantian.aarch64_RELEASE.tgz &&
cp DBStor_Clientaarch64_RELEASE.tgz cantian_connector/repo &&
rm -rf DBStor_Client*_aarch64_RELEASE.tgz &&
sed -i 's/"cantian_in_container": "0"/"cantian_in_container": "1"/' cantian_connector/action/config_params.json &&
cd cantian_connector/action && sh appctl.sh install config_params.json
RUN cd /opt/cantian/image/cantian_connector/cantian-connector-mysql/mysql_bin/ &&
tar -zxf /ctdb/cantian_install/Cantian_connector_mysql_aarch64_RELEASE.tgz &&
cp -arf mysql/lib/plugin/meta/ha_ctc.so Cantian_connector_mysql/mysql/lib/plugin/ &&
rm -rf mysql && mv Cantian_connector_mysql/mysql . &&
cp -arf mysql /opt/cantian/mysql/install/ &&
chown 5000:5000 /opt/cantian/mysql/install/mysql -R &&
cp -pf /opt/cantian/mysql/install/mysql/bin/mysql /usr/bin/ &&
cp -prf /opt/cantian/mysql/install/mysql /usr/local/
RUN systemctl enable cantian_initer.service