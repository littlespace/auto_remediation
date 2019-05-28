import logging
import time
import json
import sys


class DummyRemediation:

    def __init__(self, logger, opts):
        self.logger = logger
        self.opts = opts

    def run(self, inp, args):
        self.logger.info('Got incident Name: {}, Id: {}'.format(
            inp['name'], inp['id']))
        t = time.time()
        data = inp['data']
        self.logger.info('Got incident task: {}'.format(
            data.get('task_id', 'None')))
        if inp['is_aggregate']:
            components = data.get('components', [])
            self.logger.info(
                'Incident has {} components'.format(len(components)))
        else:
            components = [data]
        ents = []
        for c in components:
            ent = '{}:{}'.format(c.get('device'), c['entity'])
            self.logger.info('Running remediation for {}'.format(ent))
            ents.append(ent)
            time.sleep(5)
        self.logger.info('Done')
        out = {
            'remediation': 'dummy_remediation',
            'entities': ents,
            'elapsed_time': int(time.time() - t),
            'message': 'Remediation successful',
        }
        print(json.dumps(out))
        sys.exit(0)
