FROM {{ .Values.images.cantian_base_x86 }}
RUN useradd -m ctdba -u 5000
WORKDIR /ctdb/cantian_install
RUN rm -rf *
COPY Cantian_.x86_64_RELEASE.tgz .
COPY DBStor_Clientx86_64_RELEASE.tgz .
COPY mysql_release_8.0.26x86_64.tar.gz .
RUN tar -zxf Cantian_.x86_64_RELEASE.tgz && rm -rf Cantian.x86_64_RELEASE.tgz &&
cp DBStor_Clientx86_64_RELEASE.tgz cantian_connector/repo &&
rm -rf DBStor_Clientx86_64_RELEASE.tgz &&
sed -i 's/"cantian_in_container": "0"/"cantian_in_container": "1"/' cantian_connector/action/config_params.json &&
cd cantian_connector/action && sh appctl.sh install config_params.json
RUN cd /opt/cantian/image/cantian_connector/cantian-connector-mysql/mysql_bin/ &&
tar -zxf /ctdb/cantian_install/mysql_release_8.0.26x86_64.tar.gz &&
tar -zxf /ctdb/cantian_install/mysql_release_8.0.26_x86_64*.tar.gz -C /opt/cantian/mysql/install/ &&
chown 5000:5000 /opt/cantian/mysql/install/mysql -R &&
cp -pf /opt/cantian/mysql/install/mysql/bin/mysql /usr/bin/ &&
cp -prf /opt/cantian/mysql/install/mysql /usr/local/
RUN systemctl enable cantian_initer.service