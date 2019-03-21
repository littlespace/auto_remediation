import logging
import time
import json
import random
import sys


class DummyAudit:

    def __init__(self, logger):
        self.logger = logger

    def run(self, inp, args):
        self.logger.info('Got incident Name: {}, Id: {}'.format(
            inp['name'], inp['id']))
        passed = True
        message = 'Audit passed'
        data = inp['data']
        ents = data.get('entities', [])
        if not ents:
            ents.append('{}:{}'.format(data.get('device'), data.get('entity')))
        for ent in ents:
            self.logger.info('Running audit for {}'.format(ent))
            time.sleep(10)
        r = random.randint(0, 100)
        if r > int(args.pass_percent):
            passed = False
            message = 'Audit Failed'
        self.logger.info(message)
        out = {
            'audit': 'dummy_audit',
            'entities': ents,
            'passed': passed,
            'message': message
        }
        print(json.dumps(out))
        if not passed:
            sys.exit(1)
        sys.exit(0)
