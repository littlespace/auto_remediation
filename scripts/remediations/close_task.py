import json
import sys
import time

from scripts.remediations import common


class CloseTask:

    def __init__(self, logger, opts):
        self.logger = logger
        self.opts = opts

    def run(self, inp, args):
        self.logger.info('Running remediation Close Task for: {}, Id: {}'.format(
            inp['name'], inp['id']))
        data = inp['data']
        close_reason = 'Incident has now cleared'
        if args.close_reason:
            close_reason = args.close_reason
        out = {'Close Time': time.ctime(), 'msg': close_reason}
        try:
            common.close_issue(
                self.opts, data['task_id'], close_reason)
        except common.CommonException as ex:
            self.logger.error(f'Failed to close task: {ex}')
            out['error'] = f'Failed to close task: {ex}'
            out['passed'] = False
            common.exit(out, False)
        common.exit(out, True)
