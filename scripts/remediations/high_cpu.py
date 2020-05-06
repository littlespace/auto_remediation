import json
import sys

from scripts.common import common


class HighCpu:

    junos_cmd = 'show system processes summary'

    def __init__(self, logger, opts):
        self.logger = logger
        self.opts = opts

    def run(self, inp, args):
        # get cpu stats frm device
        self.logger.info('Running remediation High CPU or: {}, Id: {}'.format(
            inp['name'], inp['id']))
        device = inp['data']['device']
        out = {
            'High CPU': f'{device}',
            'Description': f"{inp['data'].get('description', '')}",
            'Start Time': f"{inp['start_time']}",
        }
        try:
            ip = common.nb_device_ip(self.opts.get('netbox_url'), device)
            output = common.run_junos_command(
                ip, self.junos_cmd, self.opts)
        except common.CommonException as ex:
            self.logger.error(
                'failed to run command on device: {} / {} : {}'.format(device, ip, ex))
            out["error"] = str(ex)
            common.exit(out, False)
        try:
            task_id = inp['data'].get('task_id')
            if task_id:
                common.add_issue_comment(self.opts, task_id, output)
        except common.CommonException as ex:
            self.logger.error('Failed to add task comment: {}'.format(ex))

        common.exit(out, True)
