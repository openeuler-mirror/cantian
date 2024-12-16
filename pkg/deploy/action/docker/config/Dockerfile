FROM {{ .Values.images.cantian_base }}

ARG user=ctdba
RUN useradd -m ${user} -u 5000
WORKDIR /ctdb/cantian_install
RUN rm -rf *

COPY Cantian_2*_RELEASE.tgz .
COPY DBStor_Client_*_RELEASE.tgz .
COPY Cantian_connector_*_RELEASE.tgz .
COPY Mysql_server_*_RELEASE.tgz .

RUN tar -zxf Cantian_2*_RELEASE.tgz && rm -rf Cantian_2*_RELEASE.tgz && \
    cp DBStor_Client_*_RELEASE.tgz cantian_connector/repo && \
    rm -rf DBStor_Client_*_RELEASE.tgz && \
    jq '. + {"cantian_in_container": "1", "link_type": "1"} ' cantian_connector/action/config_params.json > temp && mv temp cantian_connector/action/config_params.json && \
    sed -i "s/\"deploy_user\": \"ctdba:ctdba\"/\"deploy_user\": \"${user}:${user}\"/" cantian_connector/action/config_params.json && \
    cd cantian_connector/action && sh appctl.sh install config_params.json

RUN cd /opt/cantian/image/cantian_connector/cantian-connector-mysql/mysql_bin/ && \
    tar -zxf /ctdb/cantian_install/Cantian_connector_*_RELEASE.tgz && \
    tar -zxf /ctdb/cantian_install/Mysql_server_*_RELEASE.tgz && \
    cp -arf connector/libctc_proxy.so /usr/lib64/  && \
    cp -arf connector/ha_ctc_share.so Mysql_server/mysql/lib/plugin/ha_ctc.so && \
    cp -arf connector/ha_ctc_share.so /opt/cantian/cantian/server/lib/ha_ctc.so && \
    rm -rf mysql && mv Mysql_server/mysql . && \
    cp -arf mysql /opt/cantian/mysql/install/ && \
    chown 5000:5000 /opt/cantian/mysql/install/mysql -R && \
    chown 5000:5000 /opt/cantian/cantian/server/lib -R && \
    cp -pf /opt/cantian/mysql/install/mysql/bin/mysql /usr/bin/ && \
    cp -prf /opt/cantian/mysql/install/mysql /usr/local/

RUN ln -s /ctdb/cantian_install/cantian_connector/action/docker/cantian_initer.sh /usr/local/bin/cantian-init && \
    chmod +x /ctdb/cantian_install/cantian_connector/action/docker/cantian_initer.sh

CMD ["cantian-init"]