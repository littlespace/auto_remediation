import logging
import time
import json
import sys


class DummyRemediation:

    def __init__(self, logger):
        self.logger = logger

    def run(self, inp, args):
        self.logger.info('Got incident Name: {}, Id: {}'.format(
            inp['name'], inp['id']))
        t = time.time()
        data = inp['data']
        ents = data.get('entities', [])
        if not ents:
            ents.append('{}:{}'.format(data.get('device'), data.get('entity')))
        for ent in ents:
            self.logger.info('Running remediation for {}'.format(ent))
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
