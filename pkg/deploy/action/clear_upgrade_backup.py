import os
import copy

from om_log import LOGGER as LOG

UPGRADE_BACKUP_DIR = "/opt/cantian/upgrade_backup"
BACKUP_NOTE_FILE = "/opt/backup_note"


class BackupRemover:
    def __init__(self):
        self._all_backup_lis = self._get_all_backup_lis()
        self._current_backup_list = self._get_recently_backup()

    @staticmethod
    def _get_all_backup_lis():
        return_lis = []
        try:
            return_lis = os.listdir(UPGRADE_BACKUP_DIR)
        except FileNotFoundError:
            LOG.error(f"upgrade backup path: {UPGRADE_BACKUP_DIR} not exist")
            exit(1)
        except Exception as err:
            LOG.error(f"lis dir: {UPGRADE_BACKUP_DIR} failed with error: {str(err)}")
            exit(1)

        if not return_lis:
            LOG.error(f"upgrade backup path: {UPGRADE_BACKUP_DIR} is empty")
            exit(1)

        return return_lis

    @staticmethod
    def _get_recently_backup():
        """
        获取记录的最新备份版本
        :return: list: /opt/backup_note中的版本号
        """
        return_list = []
        if not os.path.exists(BACKUP_NOTE_FILE):
            LOG.error(f"upgrade backup note: {BACKUP_NOTE_FILE} is not exist")
            exit(1)

        with open(BACKUP_NOTE_FILE, 'r', encoding='utf-8') as file:
            backup_lis = file.read().split('\n')
            backup_lis.remove("")

        for each_backup_info in backup_lis:
            # each_backup_info为：版本号:生成备份时的时间戳
            backup_info_lis = each_backup_info.split(':')

            if len(backup_info_lis) < 2:  # 长度小于2 说明文件格式不对； 为兼容错误情况，返回空列表
                LOG.error(f"upgrade backup note: {BACKUP_NOTE_FILE} with un_excepted format")
                exit(1)

            return_list.append(backup_info_lis[0])

        if not return_list:
            LOG.error("upgrade backup record is empty")
            exit(1)

        return return_list

    def clear_upgrade_backup(self):
        rm_list = copy.deepcopy(self._all_backup_lis)
        for backup_name in self._all_backup_lis:
            for backup_note_version in self._current_backup_list:
                if backup_name.endswith(backup_note_version):
                    rm_list.remove(backup_name)

        for rm_version in rm_list:
            rm_dir = os.path.join(UPGRADE_BACKUP_DIR, rm_version)
            os.rmdir(rm_dir)

            LOG.info(f"remove buackup files: {rm_dir} success")


if __name__ == '__main__':
    br = BackupRemover()
    try:
        br.clear_upgrade_backup()
    except Exception as error:
        LOG.error(f"execute remove upgrade backup failed with error: {error}")
        exit(1)
