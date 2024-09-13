FROM {{ .Values.images.cantian_base }}

ARG user=ctdba
RUN useradd -m ${user} -u 5000
WORKDIR /ctdb/cantian_install
RUN rm -rf *

COPY Cantian_24.*_RELEASE.tgz .
COPY DBStor_Client_*_RELEASE.tgz .
COPY mysql_release_8.0.26_*.tar.gz .

RUN tar -zxf Cantian_24.*_RELEASE.tgz && rm -rf Cantian_24.*_RELEASE.tgz && \
    cp DBStor_Client_*_RELEASE.tgz cantian_connector/repo && \
    rm -rf DBStor_Client_*_RELEASE.tgz && \
    sed -i 's/"cantian_in_container": "0"/"cantian_in_container": "1"/' cantian_connector/action/config_params.json && \
    sed -i "s/\"deploy_user\": \"ctdba:ctdba\"/\"deploy_user\": \"${user}:${user}\"/" cantian_connector/action/config_params.json && \
    cd cantian_connector/action && sh appctl.sh install config_params.json

RUN cd /opt/cantian/image/cantian_connector/cantian-connector-mysql/mysql_bin/ && \
    tar -zxf /ctdb/cantian_install/mysql_release_8.0.26_*.tar.gz && \
    tar -zxf /ctdb/cantian_install/mysql_release_8.0.26_*.tar.gz -C /opt/cantian/mysql/install/ && \
    chown 5000:5000 /opt/cantian/mysql/install/mysql -R && \
    cp -pf /opt/cantian/mysql/install/mysql/bin/mysql /usr/bin/ && \
    cp -prf /opt/cantian/mysql/install/mysql /usr/local/

RUN ln -s /ctdb/cantian_install/cantian_connector/action/docker/cantian_initer.sh /usr/local/bin/cantian-init && \
    chmod +x /ctdb/cantian_install/cantian_connector/action/docker/cantian_initer.sh

CMD ["cantian-init"]