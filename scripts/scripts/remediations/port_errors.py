import json
import sys

from scripts.remediations import common


class PortErrors:

    junos_cmd = 'show interfaces {intf} statistics'
    awx_dc_drain_job_template = 47

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
            out["error"] = f'Failed to run junos command: {ex}'
            common.exit(out, False)
        out["Interface output"] = output

        # implement auto drain for dc links only for now
        result = True
        if inp['data']['labels'].get('role', '') == 'dc' and args.auto_drain.lower() == 'true':
            self.logger.info(
                f"Attempting auto-drain of {device}:{inp['data']['entity']}")
            dry_run = 'false'
            if hasattr(args, 'dry_run'):
                dry_run = args.dry_run.lower()
            out, result = self.auto_drain_dc(
                out, device, inp['data']['entity'], dry_run)
            if result:
                self.logger.info('Auto drain successful')

        common.exit(out, result)

    def auto_drain_dc(self, out, device, interface, dry_run):
        result = False
        token = self.opts.get('awx_token')
        url = self.opts.get('awx_url')
        if not url or not token:
            self.logger.error('Missing AWX url or token, unable to auto-drain')
            out['auto-drain'] = False
            return out, result
        e = {'interface': interface, 'dry_run': dry_run, 'undrain': 'false'}
        try:
            job_id, result = common.run_awx_job(
                url, token, self.awx_dc_drain_job_template, e, limit=device, timeout=120)
            out['auto-drain'] = result
            out['awx_job_id'] = job_id
            result = result
        except Exception as ex:
            self.logger.error('Failed to run awx job: {}'.format(ex))
            out['error'] = f'Failed to auto-drain: {ex}'
        return out, result
