import os
import shlex
import subprocess
import json
from pathlib import Path


class OmChecker:

    def __init__(self):
        self.decode_mod = 'utf-8'
        self.component_check_order = ['cms', 'cantian', 'cantian_exporter']
        self.check_file_parent_path = '/opt/cantian/action'
        self.check_file = 'check_status.sh'
        self.check_daemon_cmd = 'pgrep -f cantian_daemon'
        self.check_timer_cmd = 'systemctl is-active cantian.timer'
        self.check_note = {
            'cms': 'unknown',
            'cantian': 'unknown',
            'ct_om': 'unknown',
            'cantian_exporter': 'unknown',
            'cantian_daemon': 'unknown',
            'cantian_timer': 'unknown'
        }
        self.format_output = {
            'data': {},
            'error': {
                'code': 0,
                'description': ''
            }
        }

    def check_ctom(self):
        key_file = 'ctmgr/uds_server.py'
        check_popen = subprocess.Popen(['/usr/bin/pgrep', '-f', key_file],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        ct_om_pid, _ = check_popen.communicate(timeout=5)
        if ct_om_pid.decode(self.decode_mod):
            self.check_note['ct_om'] = 'online'
        else:
            self.check_note['ct_om'] = 'offline'

    def check_components(self):
        for component in self.component_check_order:
            script_path = str(Path(os.path.join(self.check_file_parent_path, component, self.check_file)))
            check_popen = subprocess.Popen(['/usr/bin/bash', script_path],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
            _, err = check_popen.communicate(timeout=5)
            if err.decode(self.decode_mod):
                continue

            check_result = check_popen.returncode
            if check_result:
                self.check_note[component] = 'offline'
            else:
                self.check_note[component] = 'online'

    def check_daemon(self):
        daemon = subprocess.Popen(shlex.split(self.check_daemon_cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  shell=False)
        output, err = daemon.communicate(timeout=5)
        if not err.decode(self.decode_mod):
            if output.decode(self.decode_mod):
                self.check_note['cantian_daemon'] = 'online'
            else:
                self.check_note['cantian_daemon'] = 'offline'

    def check_cantian_timer(self):
        daemon = subprocess.Popen(shlex.split(self.check_timer_cmd), stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, shell=False)
        output, err = daemon.communicate(timeout=5)
        if not err.decode(self.decode_mod):
            if output.decode(self.decode_mod).strip() == 'active':
                self.check_note['cantian_timer'] = 'active'

            if output.decode(self.decode_mod).strip() == 'inactive':
                self.check_note['cantian_timer'] = 'inactive'

    def get_format_output(self):
        try:
            self.check_components()
        except Exception as err:
            self.format_output['error']['code'] = 1
            self.format_output['error']['description'] = "check components failed with err: {}".format(str(err))
            return self.format_output

        try:
            self.check_ctom()
        except Exception as err:
            self.format_output['error']['code'] = 1
            self.format_output['error']['description'] = "check ct_om status failed with err: {}".format(str(err))
            return self.format_output

        try:
            self.check_daemon()
        except Exception as err:
            self.format_output['error']['code'] = 1
            self.format_output['error']['description'] = "check cantian_daemon failed with err: {}".format(str(err))
            return self.format_output

        try:
            self.check_cantian_timer()
        except Exception as err:
            self.format_output['error']['code'] = 1
            self.format_output['error']['description'] = "check cantian timer fained with err: {}".format(str(err))
            return self.format_output

        self.format_output['data'] = self.check_note
        return self.format_output


if __name__ == '__main__':
    oc = OmChecker()
    print(json.dumps(oc.get_format_output()))
