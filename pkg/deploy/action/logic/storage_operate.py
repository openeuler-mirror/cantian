# coding=utf-8

import time

from utils.client.rest_client import RestClient
from utils.config.rest_constant import Constant
from logic.common_func import exec_popen
from utils.client.response_parse import ResponseParse
from om_log import REST_LOG as LOG


class StorageInf(object):
    def __init__(self, login_tuple):
        self.ip, self.user_name, self.passwd = login_tuple
        self.url_prefix = Constant.HTTPS + self.ip + ":" + Constant.PORT
        self.rest_client = RestClient(login_tuple)

    @staticmethod
    def handle_error_msg(err_msg):
        LOG.error(err_msg)
        raise Exception(err_msg)

    @staticmethod
    def umount_file_system(fs_name):
        """
        挂载dbstore文件系统
        :param fs_name: 文件系统名称
        :return:
        """
        mount_dir = f"/mnt/dbdata/remote/{fs_name}"
        umount_cmd = f"umount {mount_dir}"
        check_mount = f"mountpoint {mount_dir}"
        retry_times = 3
        err_msg = f"Failed umount {mount_dir}, details:%s"
        while retry_times:
            return_code, stdout, stderr = exec_popen(check_mount)
            if return_code:
                LOG.info("%s has not been mounted.", mount_dir)
                return
            return_code, stdout, stderr = exec_popen(umount_cmd)
            if return_code:
                time.sleep(30)
                retry_times -= 1
                _err_msg = err_msg % stderr + f"remain retry times:{retry_times}"
                LOG.error(_err_msg)
                continue
            else:
                LOG.info("Umount %s success", mount_dir)
                return
        else:
            raise Exception(err_msg % stderr)

    @staticmethod
    def mount_file_system(fs_name, logic_ip, prefix=None, params=""):
        """
        取消dbstore文件系统挂载
        :param logic_ip: 挂载ip
        :param prefix: 挂载路径前缀
        :param params: 挂载参数
        :param fs_name: 文件系统名称
        :return:
        """
        mount_dir = f"/mnt/dbdata/remote/{fs_name}" if prefix is None \
            else f"/mnt/dbdata/remote/{prefix}_{fs_name}"
        mount_cmd = f"mount -t nfs {params} {logic_ip}:/{fs_name} " + mount_dir
        mkdir_cmd = f"if [ ! -d {mount_dir} ];then mkdir -p {mount_dir};fi"
        return_code, _, stderr = exec_popen(mkdir_cmd)
        if return_code:
            err_msg = f"Failed mkdir {mount_dir}, details:{stderr}"
            raise Exception(err_msg)
        check_mount = f"mountpoint {mount_dir}"
        return_code, _, stderr = exec_popen(check_mount)
        err_msg = f"Failed mount {mount_dir}, details:%s"
        if return_code:
            retry_times = 3
            while retry_times:
                return_code, stdout, stderr = exec_popen(mount_cmd)
                if return_code:
                    time.sleep(30)
                    retry_times -= 1
                    _err_msg = err_msg % stderr + f"retry times:{retry_times}/3"
                    LOG.error(_err_msg)
                    continue
                else:
                    LOG.info("Mount %s success", mount_dir)
                    return
            else:
                raise Exception(err_msg % stderr)

    @classmethod
    def _result_parse(cls, err_msg, res):
        err_msg = err_msg + ", Detail:[%s]%s.Suggestion:%s"
        result = ResponseParse(res)
        rsp_code, rsp_result, rsp_data = result.get_rsp_data()
        error_code = rsp_result.get('code')
        if rsp_code != 0 or error_code != 0:
            error_des = rsp_result.get('description')
            error_sgt = rsp_result.get('suggestion')
            err_msg = err_msg % (error_code, error_des, error_sgt)
            cls.handle_error_msg(err_msg)
        return rsp_data

    def login(self):
        """
        check login
        :return: None
        """
        LOG.info("login DM start")
        try:
            self.rest_client.login()
        except Exception as _err:
            err_msg = "Login DM[float ip:%s] failed, details: %s " \
                      % (self.ip, str(_err))
            self.handle_error_msg(err_msg)
        LOG.info("Login DM success.")

    def logout(self):
        self.rest_client.logout()

    def query_file_system_info(self, fs_name, vstore_id=0):
        """
        Query the file system ID based on the file system name.
        param fs_name: the file system name
        :return: the file system id
        """
        query_url = Constant.CREATE_FS.format(deviceId=self.rest_client.device_id)
        url = query_url + f"?filter=NAME:{fs_name}&vstoreId={vstore_id}"
        res = self.rest_client.normal_request(url, "get")
        err_msg = f"Failed to query fs{fs_name} id"
        data = self._result_parse(err_msg, res)
        for _fs_info in data:
            if _fs_info.get("NAME") == fs_name:
                return _fs_info
        return {}

    def query_storage_pool_info(self, pool_id):
        """
        check storage pool id exists
        :param pool_id: pool id
        :return: None
        """
        LOG.info("Query storage pool info start, pool_id:[%s]", pool_id)
        url = Constant.QUERY_POOL.format(deviceId=self.rest_client.device_id) + f"?filter=ID:{pool_id}"
        res = self.rest_client.normal_request(url, "get")
        err_msg = f"Failed to query pool  id:[{pool_id}]"
        resp_data = self._result_parse(err_msg, res)
        return resp_data

    def query_vstore_info(self, vstore_id):
        url = Constant.DELETE_VSTORE.format(deviceId=self.rest_client.device_id, id=vstore_id)
        res = self.rest_client.normal_request(url, "get")
        err_msg = f"Failed to query vstore id:[{vstore_id}]"
        rsp_data = self._result_parse(err_msg, res)
        return rsp_data

    def query_rollback_snapshots_process(self, fs_name, vstore_id=0):
        """
        查询文件系统快照回滚进度
        文件系统回滚状态：
            0：空闲状态；
            1：运行状态；
            2：暂停状态；
            3：完成状态；
            4：终止状态；
        文件系统回滚进度：0-99,回滚成功后，无该字段
        :param fs_name: 文件系统名称
        :param vstore_id: 租户id
        :return: rollback_rate：回顾进度， rollback_status：回滚状态
        """
        query_url = Constant.QUERY_ROLLBACK_SNAPSHOT_PROCESS.format(deviceId=self.rest_client.device_id,
                                                                    fs_name=fs_name)
        url = query_url + f"&&vstoreId={vstore_id}"
        res = self.rest_client.normal_request(url, 'get')
        err_msg = f"Failed to query fs[{fs_name}] rollback snapshot process."
        rsp_data = self._result_parse(err_msg, res)
        return rsp_data

    def query_split_clone_file_system_process(self, fs_name, vstore_id=0):
        """
        查询克隆文件系统分裂进度
        :param vstore_id: 文件系统所在租户id
        :param fs_name: 文件系统名称
        :return:
        """
        while True:
            clone_fs_info = self.query_file_system_info(fs_name, vstore_id)
            progress = clone_fs_info.get("SPLITPROGRESS")
            split_status = clone_fs_info.get("SPLITSTATUS")
            split_enable = clone_fs_info.get("SPLITENABLE")
            if 0 <= int(progress) < 100:
                LOG.info("Split clone fs[%s] progress:%s", fs_name, progress)
                time.sleep(10)
                continue
            if progress == "-1" and split_enable == "false":
                LOG.info("Split clone fs[%s] success.", fs_name)
                return
            if split_status == 4:
                err_msg = "Split clone fs[%s] failed" % fs_name
                raise Exception(err_msg)

    def query_nfs_info(self, fs_id, vstore_id=0):
        """
        查询nfs共享信息
        :param fs_id: 文件系统id
        :param vstore_id: 租户id， 默认为系统租户
        :return:
        """
        query_url = Constant.NFS_SHARE_QUERY.format(deviceId=self.rest_client.device_id)
        url = query_url + f"?filter=FSID:{fs_id}&vstoreId={vstore_id}"
        res = self.rest_client.normal_request(url, "get")
        err_msg = f"Failed to query NFS share id of fs{fs_id}"
        return self._result_parse(err_msg, res)

    def query_nfs_share_auth_client(self, nfs_share_id, vstore_id=0):
        """
        查询NFS共享客户端信息
        :param nfs_share_id: 共享ID
        :param vstore_id: 租户ID
        :return:
        """
        query_url = Constant.NFS_SHARE_ADD_CLIENT.format(deviceId=self.rest_client.device_id)
        url = query_url + f"?filter=PARENTID:{nfs_share_id}&vstoreId={vstore_id}&range=[0-1]"
        res = self.rest_client.normal_request(url, "get")
        err_msg = f"Failed to query nfs share auth client, nfs_share_id:%s" % nfs_share_id
        return self._result_parse(err_msg, res)

    def query_logical_port_info(self, ip_addr, vstore_id):
        """
        批量查询逻辑端口信息
        :param ip_addr: ip地址
        :param vstore_id: 租户id
        :return:
        """
        query_url = Constant.QUERY_LOGIC_PORT_INFO.format(deviceId=self.rest_client.device_id)
        url = query_url + f"?filter=IPV4ADDR:{ip_addr}&range=[0-100]&vstoreId={vstore_id}"
        res = self.rest_client.normal_request(url, "get")
        err_msg = f"Failed to query lf info"
        return self._result_parse(err_msg, res)

    def create_file_system(self, data):
        """
        params data:
            "NAME":  文件系统名 只支持数字、字母、下划线和中文字符，特殊字符支持“.”、“-”.长度：1-255
            "PARENTID":  存储池ID
            "SNAPSHOTRESERVEPER": 快照预留空间百分比。快照预留空间百分比可设范围（0%-50%）
            "CAPACITYTHRESHOLD": 总空间容量告警阈值。默认超过90%告警范围（50-95）。
            "workloadTypeId":  应用类型的ID。固定应用类型Database_cantian
            "CAPACITY": 文件系统对应容量
            "vstoreId": 租户ID
        :return:the file system id
        """
        url = Constant.CREATE_FS.format(deviceId=self.rest_client.device_id)
        res = self.rest_client.normal_request(url, "post", data=data)
        err_msg = f"Failed to create file system, data:{data}"
        rsp_data = self._result_parse(err_msg, res)
        LOG.info("Create file system succees, data:%s", data)
        return rsp_data.get("ID")

    def create_clone_file_system(self, parent_id, clone_fs_name, vstore_id=0):
        """
        创建克隆文件系统
        :param parent_id:
        :param clone_fs_name:
        :param vstore_id:
        :return: 克隆文件系统ID
        """
        LOG.info("Begin to clone fs id[%s], new fs[%s], vstore id [%s]", parent_id, clone_fs_name, vstore_id)
        url = Constant.CREATE_CLONE_FS.format(deviceId=self.rest_client.device_id)
        data = {
            "NAME": clone_fs_name,
            "PARENTFILESYSTEMID": parent_id,
            "vstoreId": vstore_id
        }
        res = self.rest_client.normal_request(url, "post", data=data)
        err_msg = f"Failed to clone fs[id:{parent_id}], clone fs name:{clone_fs_name} "
        rsp_data = self._result_parse(err_msg, res)
        LOG.info("Clone file system success")
        return rsp_data

    def create_file_system_snapshot(self, name, fs_id, vstore_id=0):
        """
        对文件系统打快照
        :param name:  快照名称
        :param fs_id:  文件系统id
        :param vstore_id:  租户id
        :return:
        """
        data = {
            'NAME': name,
            'PARENTID': fs_id,
            'vstoreId': vstore_id,
            'PARENTTYPE': 40
        }
        url = Constant.CREATE_FSSNAPSHOT.format(deviceId=self.rest_client.device_id)
        res = self.rest_client.normal_request(url, "post", data=data)
        err_msg = f"Failed to create fs snapshot, fs_id:[%s], name:[%s]" % (fs_id, name)
        rsp_data = self._result_parse(err_msg, res)
        return rsp_data

    def split_clone_file_system(self, clone_fs_id, action=1, vstore_id=0):
        """
        分裂克隆文件系统
        :param clone_fs_id: 克隆文件系统id
        :param action: 参数取值：1:启动分裂;2:停止分裂;3:取消分裂
        :param vstore_id: 租户id
        :return: none
        """
        LOG.info("Begin to split clone fs[id:%s]", clone_fs_id)
        url = Constant.SPLIT_CLONE_FS.format(deviceId=self.rest_client.device_id)
        data = {
            "ID": clone_fs_id,
            "action": action,
            "vstoreId": vstore_id
        }
        res = self.rest_client.normal_request(url, "put", data=data)
        err_msg = f"Failed to split clone fs[id:{clone_fs_id}]"
        self._result_parse(err_msg, res)
        LOG.info("Success to split clone fs[id:%s]", clone_fs_id)

    def rollback_file_system_snapshot(self, snapshot_id, vstore_id=0):
        """
        回滚快照
        :param snapshot_id: 快照ID
        :param vstore_id: 租户ID
        :return:
        """
        data = {
            'ID': snapshot_id,
            'vstoreId': vstore_id
        }
        url = Constant.ROLLBACK_SNAPSHOT.format(deviceId=self.rest_client.device_id)
        res = self.rest_client.normal_request(url, "put", data=data)
        err_msg = f"Failed to rollback snapshot, snapshot_id:[%s]" % snapshot_id
        rsp_data = self._result_parse(err_msg, res)
        return rsp_data

    def query_file_system_snapshot_info(self, snapshot_id):
        """
        回滚快照
        :param snapshot_id: 快照ID
        :return:
        """
        url = (Constant.CREATE_FSSNAPSHOT + "/{id}").format(deviceId=self.rest_client.device_id,
                                                            id=snapshot_id)
        res = self.rest_client.normal_request(url, "get")
        err_msg = f"Failed to rollback snapshot, snapshot_id:[%s]" % snapshot_id
        rsp_data = self._result_parse(err_msg, res)
        return rsp_data

    def create_nfs_share(self, data):
        """
        add nfs share
        :param data: create file system data
            exp:
              "SHAREPATH": 共享路径
               "vstoreId": 租户ID，多组场景必选
               "FSID": 文件系统ID
        :return: nfs share id
        """
        url = Constant.NFS_SHARE_ADD.format(deviceId=self.rest_client.device_id)
        res = self.rest_client.normal_request(url, "post", data=data)
        err_msg = f"Failed to create nfs share, data:{data}"
        rsp_data = self._result_parse(err_msg, res)
        LOG.info("Create nfs success, data:%s", data)
        return rsp_data.get("ID")

    def add_nfs_client(self, data):
        """
        add nfs client
        :param data:
               exp:
                    "ACCESSVAL": 权限。参数取值：0：只读， 1：读写， 5：无权限，当前场景配置为1
                    "ALLSQUASH": 权限限制。参数取值：0：all_squash， 1：no_all_squash，当前场景配置为1
                    "ROOTSQUASH": root权限限制。参数取值：0：root_squash， 1：no_root_squash，当前场景配置为1
                    "PARENTID": 父对象ID。
                    "vstoreId": 租户ID，多组场景必选
                    "NAME": 客户端IP或主机名或网络组名。192.168.0.10或192.168.0.0/24或*，“*”表示全部客户端IP地址
        :return: nfs client id
        """
        url = Constant.NFS_SHARE_ADD_CLIENT.\
            format(deviceId=self.rest_client.device_id)
        res = self.rest_client.normal_request(url, "post", data=data)
        err_msg = f'Failed to create nfs share, data:{data}'
        rsp_data = self._result_parse(err_msg, res)
        LOG.info("Add nfs client success, data:%s", data)
        return rsp_data.get("ID")

    def open_nfs_service(self, vstore_id):
        """
        打开租户对应nfs 4.0和4.1协议
        传参说明：
            vstoreId： 租户ID
            SUPPORTV4 返回string(bool) 是否开启NFSv4服务。
            参数取值：
            true：开启
            false：关闭
            SUPPORTV41 返回string(bool) 是否开启NFSv4.1服务。
            参数取值：
            true：开启
            false：关闭
        :param vstore_id: 租户id
        :return:
        """
        LOG.info("Begin to open nfs 4.0 and 4.1 configer of vstore[%s]", vstore_id)
        url = Constant.NFS_SERVICE.format(deviceId=self.rest_client.device_id)
        data = {
            "vstoreId": vstore_id,
            "SUPPORTV4": True,
            "SUPPORTV41": True
        }
        res = self.rest_client.normal_request(url, "put", data=data)
        err_msg = f"Failed to open vstore{vstore_id} nfs service"
        self._result_parse(err_msg, res)
        LOG.info("Open nfs 4.0 and 4.1 configer success.")

    def delete_nfs_share(self, nfs_share_id, vstore_id=0):
        """
        delete nfs share
        :param nfs_share_id:
        :param vstore_id
        :return: None
        """
        LOG.info("Begin to del nfs share, id[%s]", nfs_share_id)
        del_share_url = Constant.NFS_SHARE_DELETE.\
            format(deviceId=self.rest_client.device_id, id=nfs_share_id)
        url = del_share_url + f"?vstoreId={vstore_id}"
        res = self.rest_client.normal_request(url, "delete")
        err_msg = f"Failed to delete {nfs_share_id} nfs share"
        self._result_parse(err_msg, res)
        LOG.info("Delete id[%s] nfs share success", nfs_share_id)

    def delete_file_system(self, fs_id):
        """
        del fs by fs_id
        :param fs_id:
        :return:
        """
        LOG.info("Begin to del fs by id[%s]", fs_id)
        url = Constant.DELETE_FS.\
            format(deviceId=self.rest_client.device_id, id=fs_id)
        res = self.rest_client.normal_request(url, "delete")
        err_msg = f"Failed to delete {fs_id} nfs"
        self._result_parse(err_msg, res)
        LOG.info("Delete id[%s] fs success", fs_id)

    def modify_file_system_info(self, fs_id, key, value):
        """
        修改文件系统信息
        :param fs_id: 文件系统id
        :param key: 修改字段
        :param value: 修改值
        :return:
        """
        LOG.info("Begin to modify fs id[%s], key:[%s], value:[%s]", fs_id, key, value)
        url = Constant.DELETE_FS.format(deviceId=self.rest_client.device_id, id=fs_id)
        data = {
            key: value
        }
        res = self.rest_client.normal_request(url, data=data, method="put")
        err_msg = f"Failed to modify fs id[%s], key:[%s], value:[%s]" % (fs_id, key, value)
        self._result_parse(err_msg, res)
        LOG.info("Begin to modify fs id[%s], key:[%s], value:[%s] success.", fs_id, key, value)
