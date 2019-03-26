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
        if inp['is_aggregate']:
            components = data.get('components', [])
            self.logger.info(
                'Incident has {} components'.format(len(components)))
        else:
            components = [data]
        ents = []
        for c in components:
            ent = '{}:{}'.format(c.get('device'), c['entity'])
            self.logger.info('Running audit for {}'.format(ent))
            ents.append(ent)
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
