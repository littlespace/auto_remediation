import json
import sys

from scripts.remediations import common


class HighCpu:

    db_query = '''SELECT moving_average("cpu-idle", 10)  FROM "telegraf"."autogen"."jnpr_routing_engine" WHERE time > :dashboardTime: AND "device"='{device}'  FILL(null)'''

    junos_cmd = 'show system processes summary'

    def __init__(self, logger, opts):
        self.logger = logger
        self.opts = opts

    def run(self, inp, args):
        # get interface stats frm device
        self.logger.info('Running remediation for: {}, Id: {}'.format(
            inp['name'], inp['id']))
        device = inp['data']['device']
        out = {
            'High CPU': f'{device}',
            'Description': f"{inp['data'].get('description', '')}",
            'Start Time': f"{inp['start_time']}",
        }
        try:
            output = common.run_junos_command(device, self.junos_cmd, self.opts)
        except common.CommonException as ex:
            self.logger.error('failed to run command on device: {}'.format(ex))
            out["error"] = str(ex)
            common.exit(out, False)
        out['CPU Output'] = output
        dashboard_url = self.opts.get('dashboard_url')
        if dashboard_url:
            db_q = self.db_query.format(device=device)
            q = dashboard_url + '?query={}'.format(db_q)
            out["Dashboard URL"] = q
        common.exit(out, True)
