#!/usr/bin/env python3

import logging
import sys
import json
import yaml
import argparse
import scripts


def setup_logging(name, loglvl):
    logger = logging.getLogger(name)
    logger.setLevel(loglvl)
    h = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    h.setFormatter(formatter)
    logger.addHandler(h)
    return logger


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', dest='debug',
                        action='store_true', help='Debug logs')
    parser.add_argument('--script_name', dest='script_name',
                        help='Script name to run')
    parser.add_argument('--common_opts_file', dest='common_opts_file', default=None,
                        help='Path to common options yaml file for all scripts')
    return parser.parse_known_args()


def main(args):
    main_args, custom = args
    level = logging.INFO
    if main_args.debug:
        level = logging.DEBUG
    inp = json.load(sys.stdin)
    logger = setup_logging(main_args.script_name, loglvl=level)
    common_opts = {}
    if main_args.common_opts_file:
        with open(main_args.common_opts_file, 'r') as f:
            common_opts = yaml.load(f)
    scriptClass = scripts.getScript(main_args.script_name)
    if not scriptClass:
        print(json.dumps({'passed': False, 'message': 'Script not found'}))
        sys.exit(1)
    script = scriptClass(logger, common_opts)
    parser = argparse.ArgumentParser()
    for c in custom:
        if c.startswith('--'):
            parser.add_argument(c)
    script.run(inp, parser.parse_args(custom))


if __name__ == '__main__':
    main(parse_args())
