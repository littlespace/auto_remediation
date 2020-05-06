import logging
import time
import json
import random
import sys

from scripts.common import common


class DummyAudit:

    def __init__(self, logger, opts):
        self.logger = logger
        self.opts = opts

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
        common.exit(out, passed)

    def test(self):
        return {
            'input': {
                'name': 'test incident',
                'is_aggregate': False,
                'id': 100,
                'data': {'device': 'dev1', 'entity': 'e1'},
            },
            'args': {
                'pass_percent': 50,
            }
        }
