import json
import pprint
import sys


class Incident:
    ''' This remediation does nothing but dump the input incident back out '''

    def __init__(self, logger, opts):
        self.logger = logger
        self.opts = opts

    def run(self, inp, args):
        self.logger.info('Got incident Name: {}, Id: {}'.format(
            inp['name'], inp['id']))
        out = {'Incident Details': inp['data']['labels']}
        pprint.pprint(out)
        sys.exit(0)
