import logging
import time
import json
import sys


class DummyRemediation:

    def __init__(self, logger):
        self.logger = logger

    def run(self, inp, args):
        self.logger.info('Got {} incidents'.format(len(inp)))
        t = time.time()
        ents = []
        for i in inp:
            self.logger.info(
                'Running remediation on device: {}, entity: {}'.format(i['device'], i['entity']))
            ents.append('{}:{}'.format(i['device'], i['entity']))
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
