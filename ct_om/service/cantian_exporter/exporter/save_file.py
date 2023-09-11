import os
import json
import stat
from datetime import datetime
from datetime import timezone
from collections import OrderedDict

dir_name, _ = os.path.split(os.path.abspath(__file__))
upper_path = os.path.abspath(os.path.join(dir_name, ".."))


class SaveFile:
    def __init__(self):
        self.file_save_path = os.path.join(upper_path, 'exporter_data')
        self._init_config()
        self.save = OrderedDict({name: os.path.join(self.file_save_path, name)
                                 for name in os.listdir(self.file_save_path)})

    @staticmethod
    def gen_file_name():
        utc_now = datetime.utcnow()
        cur_time = utc_now.replace(tzinfo=timezone.utc).astimezone(tz=None)
        return "%s.json" % str(cur_time.strftime('%Y%m%d%H%M%S'))

    def _init_config(self):
        if not os.path.exists(self.file_save_path):
            os.makedirs(self.file_save_path)

    def create_files(self, data_to_write):
        if not os.path.exists(self.file_save_path):
            os.mkdir(self.file_save_path)

        file_name = self.gen_file_name()
        cur_file_path = os.path.join(self.file_save_path, file_name)
        self.save.update({file_name: cur_file_path})
        while len(self.save) > 5:
            _, pop_file_path = self.save.popitem(last=False)
            os.remove(pop_file_path)

        modes = stat.S_IWRITE | stat.S_IRUSR
        flags = os.O_WRONLY | os.O_TRUNC | os.O_CREAT
        with os.fdopen(os.open(cur_file_path, flags, modes), 'w', encoding='utf-8') as file:
            file.write(json.dumps(data_to_write))
