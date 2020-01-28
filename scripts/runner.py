#!/usr/bin/env python3

import logging
import sys
import json
import yaml
import argparse
import importlib
import munch
import os
import warnings
warnings.filterwarnings('ignore')


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
    parser.add_argument('--scripts_path', dest='scripts_path',
                        help='Full path to location of scripts')
    parser.add_argument('--script_name', dest='script_name',
                        help='Script name to run')
    parser.add_argument('--common_opts_file', dest='common_opts_file', default=None,
                        help='Path to common options yaml file for all scripts')
    parser.add_argument('--test', action='store_true',
                        help='Run locally in test mode')
    return parser.parse_known_args()


def main(args):
    main_args, custom = args
    level = logging.INFO
    if main_args.debug:
        level = logging.DEBUG
    logger = setup_logging(main_args.script_name, loglvl=level)
    common_opts = {}
    if main_args.common_opts_file:
        with open(main_args.common_opts_file, 'r') as f:
            common_opts = yaml.full_load(f)
    pkg_path, pkg_name = os.path.split(main_args.scripts_path)
    sys.path.append(pkg_path)
    scriptClass = None
    try:
        pkg = importlib.import_module(pkg_name)
        scriptClass = pkg.getScript(main_args.script_name)
    except Exception as ex:
        logger.error(ex)
        print(json.dumps(
            {'passed': False, 'message': 'Failed to import scripts pkg'}))
        sys.exit(1)
    if not scriptClass:
        print(json.dumps({'passed': False, 'message': 'Script not found'}))
        sys.exit(1)
    script = scriptClass(logger, common_opts)
    if main_args.test:
        data = script.test()
        args = munch.munchify(data['args'])
        script.run(data['input'], args)
    parser = argparse.ArgumentParser()
    for c in custom:
        if c.startswith('--'):
            parser.add_argument(c)
    inp = json.load(sys.stdin)
    script.run(inp, parser.parse_args(custom))


if __name__ == '__main__':
    main(parse_args())
