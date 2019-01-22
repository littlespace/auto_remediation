import logging
import time
import json
import random
import sys


class DummyAudit:

    def __init__(self, logger):
        self.logger = logger

    def run(self, inp, args):
        self.logger.info('Got {} incidents'.format(len(inp)))

        passed = True
        message = 'Audit passed'
        ents = []
        for i in inp:
            self.logger.info(
                'Running audit for device: {}, entity: {}'.format(i['device'], i['entity']))
            ents.append('{}:{}'.format(i['device'], i['entity']))
            time.sleep(5)
            r = random.randint(0, 100)
            if r > int(args.pass_percent):
                passed = False
                message = 'Audit Failed'
                break
        self.logger.info(message)
        out = {
            'audit': 'dummy_audit',
            'entities': ents,
            'passed': passed,
            'message': message
        }
        print(json.dumps(out))
        sys.exit(0)
