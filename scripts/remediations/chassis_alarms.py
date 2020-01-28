import json
import sys
import time
import re


class ChassisAlarms:
    ''' This remediation checks chassis alarm alerts for legitimacy before paging victorops.
        It checks to make sure the chassis alarm is active for at least 30 seconds on the device 
        before proceeding
    '''

    junos_cmd = 'show chassis alarms'

    def __init__(self, logger, opts):
        self.logger = logger
        self.opts = opts

    def _add_task_comment(self, inp, comment):
        try:
            task_id = inp['data'].get('task_id')
            if task_id:
                common.add_issue_comment(self.opts, task_id, comment)
        except common.CommonException as ex:
            self.logger.error('Failed to add task comment: {}'.format(ex))

    def _close_task(self, inp, reason):
        try:
            task_id = inp['data'].get('task_id')
            if task_id:
                common.close_issue(self.opts, task_id, reason)
        except common.CommonException as ex:
            self.logger.error('Failed to close task: {}'.format(ex))

    def run(self, inp, args):
        self.logger.info('Running remediation Chassis Alarms for: {}, Id: {}'.format(
            inp['name'], inp['id']))
        self.logger.info('Sleeping 30s before checking alarms')
        time.sleep(30)
        device = inp['data']['device']
        description = inp['data'].get('description', '')
        out = {
            'Chassis Alarm': f'{device}',
            'Description': f"{description}",
            'Start Time': f"{inp['start_time']}",
        }
        ip = common.nb_device_ip(self.opts.get('netbox_url'), device)
        try:
            output = common.run_junos_command(ip, self.junos_cmd, self.opts)
        except common.CommonException as ex:
            self.logger.error(
                'failed to run command on device: {} / {} : {}'.format(device, ip, ex))
            out["error"] = str(ex)
            common.exit(out, False)
        if 'No alarms currently active' in output:
            msg = '0 alarms currently active after 30 seconds - Ignoring this alert'
            self.logger.info(msg)
            self._close_task(inp, msg)
            if self.opts.get('alertmanager_url'):
                common.clear_alertmanager_alert(
                    self.opts['alertmanager_url'], self.opts['alertmanager_token'], inp['id'], notify=False)
            common.exit(out, True)

        # check if the alarm from the alert is still present on the box
        r = re.compile(r'(?<=reason=)(.*)')
        m = r.search(description)
        if m:
            desc = m.group()
            if desc in description:
                msg = f'Alarm {desc} is active on the box after 30 seconds, escalating the alert'
        else:
            # TODO : Maybe dont esclate if there is no match
            msg = f'Found active alarms on the box after 30 seconds, escalating the alert'
        self.logger.info(msg)
        if self.opts.get('alertmanager_url'):
            common.escalate_alertmanager_alert(
                self.opts['alertmanager_url'], self.opts['alertmanager_token'], inp['id'], 'CRITICAL')
        self._add_task_comment(inp, msg)
        common.exit(out, True)
