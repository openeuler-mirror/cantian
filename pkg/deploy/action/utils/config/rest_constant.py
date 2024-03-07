class Constant:
    PORT = '8088'
    HTTPS = 'https://'
    LOGIN = '/deviceManager/rest/xxxxx/login'
    LOGOUT = '/deviceManager/rest/{deviceId}/sessions'
    QUERY_POOL = '/deviceManager/rest/{deviceId}/storagepool'
    CREATE_FS = '/deviceManager/rest/{deviceId}/filesystem'
    QUERY_FILE_SYSTEM_NUM = '/deviceManager/rest/{deviceId}/filesystem/count'
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

    # 容灾查询操作
    QUERY_SYSTEM_INFO = "/deviceManager/rest/{deviceId}/system/"
    QUERY_REMOTE_DEVICE_INFO = "/deviceManager/rest/{deviceId}/remote_device"
    QUERY_LICENSE_FEATURE = "/deviceManager/rest/{deviceId}/license/feature"
    QUERY_HYPER_METRO_FILE_SYSTEM_PAIR = "/deviceManager/rest/{deviceId}/HyperMetroPair/associate"
    QUERY_REPLICATION_FILE_SYSTEM_PAIR = "/deviceManager/rest/{deviceId}/replicationpair/associate"
    QUERY_FILESYSTEM_FOR_REPLICATION = "/deviceManager/rest/{deviceId}/filesystem_for_replication"

    # 容灾搭建操作
    HYPER_METRO_DOMAIN = "/deviceManager/rest/{deviceId}/FsHyperMetroDomain"
    HYPER_METRO_VSTORE_PAIR = "/deviceManager/rest/{deviceId}/vstore_pair"
    HYPER_METRO_FILESYSTEM_PAIR = "/deviceManager/rest/{deviceId}/HyperMetroPair"
    SPLIT_REMOTE_REPLICATION_FILESYSTEM_PAIR = "/deviceManager/rest/{deviceId}/REPLICATIONPAIR/split"
    SYNC_REMOTE_REPLICATION_FILESYSTEM_PAIR = "/deviceManager/rest/{deviceId}/REPLICATIONPAIR/sync"
    REMOTE_REPLICATION_FILESYSTEM_PAIR_OPT = "/deviceManager/rest/{deviceId}/REPLICATIONPAIR/{id}"
    DELETE_HYPER_METRO_PAIR = "/deviceManager/rest/{deviceId}/HyperMetroPair/{id}"
    DELETE_HYPER_METRO_VSTORE_PAIR = "/deviceManager/rest/{deviceId}/vstore_pair/{id}"
    SPLIT_FILESYSTEM_HYPER_METRO_DOMAIN = "/deviceManager/rest/{deviceId}/SplitFsHyperMetroDomain"
    DELETE_FILESYSTEM_HYPER_METRO_DOMAIN = "/deviceManager/rest/{deviceId}/FsHyperMetroDomain/{id}"
    CANCEL_SECONDARY_WRITE_LOCK = "/deviceManager/rest/{deviceId}/REPLICATIONPAIR/CANCEL_SECONDARY_WRITE_LOCK"
    SET_SECONDARY_WRITE_LOCK = "/deviceManager/rest/{deviceId}/REPLICATIONPAIR/SET_SECONDARY_WRITE_LOCK"
    SWAP_ROLE_FS_HYPER_METRO_DOMAIN = "/deviceManager/rest/{deviceId}/SwapRoleFsHyperMetroDomain"
    SWAP_ROLE_REPLICATION_PAIR = "/deviceManager/rest/{deviceId}/REPLICATIONPAIR/switch"
    CHANGE_FS_HYPER_METRO_DOMAIN_SECOND_ACCESS = "/deviceManager/rest/{deviceId}/ChangeFsHyperMetroDomainSecondAccess"
    JOIN_FS_HYPER_METRO_DOMAIN = "/deviceManager/rest/{deviceId}/JoinFsHyperMetroDomain"

    # omtask rest api
    REMOTE_EXECUTE = "/api/v2/remote_execute"
    CREATE_HYPER_METRO_FILESYSTEM_PAIR = "/api/v2/task/fileSystem/HyperMetroPair"
    QUERY_TASK_PROCESS = "/api/v2/task/{id}"
    CREATE_REMOTE_REPLICATION_FILESYSTEM_PAIR = "/api/v2/task/protection/nas"
    # cdp操作
    DELETE_FS_CDP_SCHEDULE = '/deviceManager/rest/{deviceId}/filesystem/remove_associate'

    FULL_SYNC_MAX_TIME = 1500


SUPPORT_VERSION = ["6.1.8RC1"]
CANTIAN_DOMAIN_PREFIX = "CantianDomain_%s%s"


class HealthStatus:
    Normal = "1"              # 正常
    Faulty = "2"              # 故障
    Invalid = "14"            # 失效


class SystemRunningStatus:
    Normal = "1"
    NotRunning = "3"
    PoweringOn = "12"
    PoweringOff = "47"
    Upgrading = "51"


class RemoteDeviceStatus:
    LinkUp = "10"             # 已连接
    LinkDown = "11"           # 未连接
    Disabled = "31"           # 已禁用
    Connecting = "101"        # 正在连接
    AirGapLinkDown = "118"    # Air Gap断开


class ReplicationRunningStatus:
    Normal = "1"              # 正常
    Synchronizing = "23"      # 正在同步
    TobeRecovered = "33"      # 待恢复
    Interrupted = "34"        # 异常断开
    Split = "26"              # 已分裂
    Invalid = "35"            # 失效
    Standby = "110"           # 备用


class FilesystemRunningStatus:
    Online = "27"
    Offline = "28"
    Invalid = "35"
    Initializing = "53"


class MetroDomainRunningStatus:
    Normal = "0"              # 正常
    ToBeRecovered = "2"       # 待恢复
    Split = "3"               # 分裂
    Invalid = "6"             # 失效


class VstorePairRunningStatus:
    Normal = "1"              # 正常
    Unsynchronized = "25"     # 未同步
    Split = "26"              # 分裂
    Invalid = "35"            # 失效
    ForceStarted = "93"       # 强制启动


class FilesystemPairRunningStatus:
    Normal = "1"              # 正常
    Synchronizing = "23"      # 同步中
    Invalid = "35"            # 失效
    Paused = "41"             # 暂停
    ForceStarted = "93"       # 强制启动
    ToBeSynchronized = "100"  # 待同步
    Creating = "119"          # 创建中


class SecresAccess:
    AccessDenied = "1"        # 禁止访问
    ReadOnly = "2"            # 只读
    ReadAndWrite = "3"        # 读写


class PoolStatus:
    PreCopy = "14"            # 预拷贝
    Rebuilt = "16"            # 重构
    Online = "27"             # 在线
    Offline = "28"            # 离线
    Balancing = "32"          # 正在均衡
    Initializing = "53"       # 初始化中
    Deleting = "106"          # 删除中


class PoolHealth:
    Normal = "1"              # 正常
    Faulty = "2"              # 故障
    Degraded = "5"            # 降级


class DomainAccess:
    ReadAndWrite = "3"  # 读写
    ReadOnly = "1"      # 只读


class ConfigRole:
    Secondary = "0"     # 从端
    Primary = "1"       # 主端

class DataIntegrityStatus:
    consistent = "1"
    inconsistent = "2"