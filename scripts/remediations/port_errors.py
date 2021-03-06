import json
import sys
import time

from scripts.common import common


class PortErrors:

    junos_cmd = 'show interfaces {intf} statistics'
    awx_dc_drain_job_template = 47

    def __init__(self, logger, opts):
        self.logger = logger
        self.opts = opts

    def run(self, inp, args):
        # get interface stats frm device
        self.logger.info('Running remediation Port Errors for: {}, Id: {}'.format(
            inp['name'], inp['id']))
        device = inp['data']['device']
        out = {
            'Port Errors': f"{device}:{inp['data']['entity']}",
            'Description': f"{inp['data'].get('description', '')}",
            'Start Time': f"{inp['start_time']}",
        }
        cmd = self.junos_cmd.format(intf=inp['data']['entity'])
        try:
            ip = common.nb_device_ip(self.opts.get('netbox_url'), device)
            output = common.run_junos_command(ip, cmd, self.opts)
        except common.CommonException as ex:
            self.logger.error(
                'failed to run command on device: {} / {}: {}'.format(device, ip, ex))
            out["error"] = f'Failed to run junos command: {ex}'
            common.exit(out, False)
        try:
            task_id = inp['data'].get('task_id')
            if task_id:
                common.update_issue(
                    self.opts, task_id,
                    comment=output,
                    fields={'Site': [inp['data']['site'].upper()]},
                    components=['Repair']
                )
        except common.CommonException as ex:
            self.logger.error('Failed to add task comment: {}'.format(ex))

        # implement auto drain for dc links only for now
        result = True
        if inp['data']['labels'].get('role', '') == 'dc' and args.auto_drain.lower() == 'true':
            if device in ['ps01-c1-chi1', 'ps02-c1-chi1']:
                peerDevice = inp['data']['labels'].get('peerDevice')
                if not peerDevice or not peerDevice.startswith('rs'):
                    # exception for pod0 - dont drain any uplinks
                    self.logger.info('Not draining any uplinks on pod0 PS')
                    out['auto-drain'] = False
                    common.exit(out, result)
            self.logger.info(
                f"Attempting auto-drain of {device}:{inp['data']['entity']}")
            dry_run = 'true'
            if hasattr(args, 'no_dry_run'):
                dry_run = 'false'
            out, result = self.auto_drain_dc(
                out, device, inp['data']['entity'], dry_run)
            if result:
                self.logger.info('Auto drain successful')

        common.exit(out, result)

    def auto_drain_dc(self, out, device, interface, dry_run):
        result = False
        url = self.opts.get('nornir_api_url')
        if not url:
            self.logger.error('Missing Nornir URL, unable to auto-drain')
            out['auto-drain'] = False
            return out, result
        if dry_run == 'true':
            self.logger.info('Performing dry-run drain/undrain')
        task_params = {
            'inventory': 'datacenter',
            'task_name': '_datacenter/tasks/drain_dc_links.py',
            'interfaces': [f'{device}:{interface}'],
            'ignore_warning': True,
            'params': {
                "no_prompt": True
            }
        }
        if dry_run != 'true':
            task_params['params']['push'] = True
        try:
            res = common.run_nornir_task(url, task_params)
            out['auto-drained'] = res['passed']
            out['nornir_job_id'] = res['job_id']
            if res['passed']:
                out['message'] = (
                    'This interface has been auto-drained. Use https://awx.simulprod.com/#/templates/job_template/{} to undrain'.format(
                        self.awx_dc_drain_job_template)
                )
            else:
                out['message'] = res['message']
            result = res['passed']
        except Exception as ex:
            self.logger.error('Failed to run nornir job: {}'.format(ex))
            out['error'] = f'Failed to auto-drain: {ex}'
        return out, result
