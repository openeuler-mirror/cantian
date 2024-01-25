class Constant:
    PORT = '8088'
    HTTPS = 'https://'
    LOGIN = '/deviceManager/rest/xxxxx/login'
    LOGOUT = '/deviceManager/rest/{deviceId}/sessions'
    QUERY_POOL = '/deviceManager/rest/{deviceId}/storagepool'
    CREATE_FS = '/deviceManager/rest/{deviceId}/filesystem'
    DELETE_FS = '/deviceManager/rest/{deviceId}/filesystem/{id}'
    NFS_SERVICE = '/deviceManager/rest/{deviceId}/nfsservice'
    NFS_SHARE_ADD = '/deviceManager/rest/{deviceId}/NFSSHARE'
    NFS_SHARE_ADD_CLIENT = '/deviceManager/rest/{deviceId}/NFS_SHARE_AUTH_CLIENT'
    NFS_SHARE_DELETE = '/deviceManager/rest/{deviceId}/NFSSHARE/{id}'
    NFS_SHARE_DEL_CLIENT = '/deviceManager/rest/{deviceId}/NFS_SHARE_AUTH_CLIENT/{id}'
    NFS_SHARE_QUERY = '/deviceManager/rest/{deviceId}/NFSSHARE'
    QUERY_VSTORE = '/deviceManager/rest/{deviceId}/vstore/count'
    CREATE_VSTORE = '/deviceManager/rest/{deviceId}/vstore'
    DELETE_VSTORE = '/deviceManager/rest/{deviceId}/vstore/{id}'
    CREATE_LIF = "/deviceManager/rest/{deviceId}/lif"
    DELETE_LIF = "/deviceManager/rest/{deviceId}/lif?NAME={name}"
    CREATE_CLONE_FS = "/deviceManager/rest/{deviceId}/filesystem"
    SPLIT_CLONE_FS = "/deviceManager/rest/{deviceId}/clone_fs_split"
    CREATE_FSSNAPSHOT = "/deviceManager/rest/{deviceId}/fssnapshot"
    ROLLBACK_SNAPSHOT = "/deviceManager/rest/{deviceId}/fssnapshot/rollback_fssnapshot"
    QUERY_ROLLBACK_SNAPSHOT_PROCESS = "/deviceManager/rest/{deviceId}/FSSNAPSHOT/" \
                                      "query_fs_snapshot_rollback?PARENTNAME={fs_name}"
    QUERY_LOGIC_PORT_INFO = "/deviceManager/rest/{deviceId}/lif"
