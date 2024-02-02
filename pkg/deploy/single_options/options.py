class Options(object):
    """
    command line options
    """

    def __init__(self):
        self.log_file = ""
        self.install_user_privilege = ""
        self.opts = []

        # Database username and password are required after disabling
        # confidential login
        self.db_user = "SYS"
        # New passwd of user [SYS]
        self.db_passwd = ""

        # User info
        self.os_user = ""
        self.os_group = ""

        # The object of opened log file.
        self.file_obj = None

        # program running mode
        self.running_mode = "cantiand_with_mysql_in_cluster"

        # node id, even not in cluster mode, still given value 0
        self.node_id = 0

        # flag indicate user using gss storage
        self.use_gss = False

        # flag indicate user using dbstor storage
        self.use_dbstor = False

        self.link_type = "TCP"
        self.link_type_from_para = False

        # list contains ip white list
        self.white_list = ""

        # flag of if install inside docker container
        self.cantian_in_container = False

        # flag of if need to check package is mattched with current os version
        self.ignore_pkg_check = False

        # path of mysql config file
        self.mysql_config_file_path = "/opt/cantian/image/cantian_connector/cantian-connector-mysql/scripts/my.cnf"

        self.install_type = ""

        self.storage_share_fs = ""

        # 默认密码加密
        self.isencrept = True

        self.namespace = ""

        self.password = ""

        self.db_type = ""

        self.archive_location = ""

        self.share_logic_ip = ""
