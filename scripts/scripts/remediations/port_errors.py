import json
import sys

from scripts.remediations import common


class PortErrors:

    db_query = '''SELECT non_negative_derivative("input-errors", 1s) FROM "telegraf"."autogen"."jnpr_interface_error" WHERE time > :dashboardTime: AND "device"='{device}' AND "interface"='{intf}' FILL(null)'''

    junos_cmd = 'show interfaces {intf} statistics'

    def __init__(self, logger, opts):
        self.logger = logger
        self.opts = opts

    def run(self, inp, args):
        # get interface stats frm device
        self.logger.info('Running remediation for: {}, Id: {}'.format(
            inp['name'], inp['id']))
        device = inp['data']['device']
        out = {
            'Port Errors': f"{device}:{inp['data']['entity']}",
            'Description': f"{inp['data'].get('description', '')}",
            'Start Time': f"{inp['start_time']}",
        }
        cmd = self.junos_cmd.format(intf=inp['data']['entity'])
        try:
            output = common.run_junos_command(device, cmd, self.opts)
        except common.CommonException as ex:
            self.logger.error('failed to run command on device: {}'.format(ex))
            out["error"] = str(ex)
            common.exit(out, False)
        out["Interface output"] = output
        dashboard_url = self.opts.get('dashboard_url')
        if dashboard_url:
            db_q = self.db_query.format(device=device, intf=inp['data']['entity'])
            q = dashboard_url + '?query={}'.format(db_q)
            out["Dashboard URL"] = q
        common.exit(out, True)
