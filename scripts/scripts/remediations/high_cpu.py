import json
import sys

from scripts.remediations import common


class HighCpu:

    junos_cmd = 'show system processes summary'

    def __init__(self, logger, opts):
        self.logger = logger
        self.opts = opts

    def run(self, inp, args):
        # get cpu stats frm device
        self.logger.info('Running remediation for: {}, Id: {}'.format(
            inp['name'], inp['id']))
        device = inp['data']['device']
        out = {
            'High CPU': f'{device}',
            'Description': f"{inp['data'].get('description', '')}",
            'Start Time': f"{inp['start_time']}",
        }
        try:
            output = common.run_junos_command(
                device, self.junos_cmd, self.opts)
        except common.CommonException as ex:
            self.logger.error('failed to run command on device: {}'.format(ex))
            out["error"] = str(ex)
            common.exit(out, False)
        out['CPU Output'] = output

        common.exit(out, True)
