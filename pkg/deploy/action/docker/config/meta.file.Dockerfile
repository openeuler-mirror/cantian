FROM {{ .Values.images.cantian_base }}

ARG user=ctdba
RUN useradd -m ${user} -u 5000
WORKDIR /ctdb/cantian_install
RUN rm -rf *

COPY Cantian_2*_RELEASE.tgz .
COPY Cantian_connector_mysql_*_RELEASE.tgz .

RUN tar -zxf Cantian_2*_RELEASE.tgz && rm -rf Cantian_2*_RELEASE.tgz && \
    sed -i 's/"cantian_in_container": "0"/"cantian_in_container": "1"/' cantian_connector/action/config_params_file.json && \
    cd cantian_connector/action && sh appctl.sh install config_params_file.json

RUN cd /opt/cantian/image/cantian_connector/cantian-connector-mysql/mysql_bin/ && \
    tar -zxf /ctdb/cantian_install/Cantian_connector_mysql_*_RELEASE.tgz && \
    cp -arf mysql/lib/plugin/meta/ha_ctc.so Cantian_connector_mysql/mysql/lib/plugin/ && \
    rm -rf mysql && mv Cantian_connector_mysql/mysql . && \
    cp -arf mysql /opt/cantian/mysql/install/ && \
    chown 5000:5000 /opt/cantian/mysql/install/mysql -R && \
    cp -pf /opt/cantian/mysql/install/mysql/bin/mysql /usr/bin/ && \
    cp -prf /opt/cantian/mysql/install/mysql /usr/local/

RUN ln -s /ctdb/cantian_install/cantian_connector/action/docker/cantian_initer.sh /usr/local/bin/cantian-init && \
    chmod +x /ctdb/cantian_install/cantian_connector/action/docker/cantian_initer.sh

CMD ["cantian-init"]