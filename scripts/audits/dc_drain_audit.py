import requests

from scripts.remediations import common


class DcDrainAudit:
    ''' Simple threshold based audit to ensure that no more than n uplinks are drained at a time
        at any given layer.
    '''

    supported_roles = {
        'pod-switch': ['rack-switch', 'cluster-switch', 'services-switch'],
        'rack-switch': ['pod-switch'],
        'cluster-switch': ['pod-switch', 'border-switch'],
        'border-switch': ['cluster-switch', 'border-router'],
    }

    def __init__(self, logger, opts):
        self.logger = logger
        self.opts = opts

    def run(self, inp, args):
        self.logger.info('Running dc drain audit for: {}, Id: {}'.format(
            inp['name'], inp['id']))
        self.args = args
        device = inp['data']['device']
        interface = inp['data']['entity']
        out = {
            'audit': 'DC Drain Audit',
            'entity': f'{device}:{interface}',
            'passed': False,
        }
        # get iface from netbox
        nb_url = self.opts.get('netbox_url') + \
            f'/api/rblx/device/dm/v1/{device}'
        try:
            nb_data = requests.get(nb_url)
            d = nb_data.json()
            iface = d['interfaces'][interface]
            if d['role'] not in self.supported_roles:
                out['message'] = f"Unsupported switch role: {d['role']}"
                common.exit(out, True)
            if iface['peer_role'] not in self.supported_roles[d['role']]:
                out['message'] = f"Unsupported peer-switch role: {iface['peer_role']}"
                common.exit(out, True)
            self._pre_checks(iface, out)
            ip = d['primary_ip'].split('/')[0]
            passed, msg = self._audit(
                ip, interface, d, threshold=self.args.threshold)
            self.logger.info(
                f'Drain audit returned {passed} for {device}:{interface}: {msg}')
            out['passed'] = passed
            out['message'] = msg
        except Exception as ex:
            self.logger.exception(ex)
            out['msg'] = f'Failed to exec audit: {ex}'
        common.exit(out, out['passed'])

    def _pre_checks(self, iface, out):
        if 'drained' in iface['tags']:
            out['message'] = 'Link is already drained'
            common.exit(out, True)
        # dont drain if part of a lag
        if iface['lag'] is not None:
            out['message'] = 'Link is part of a lag'
            common.exit(out, True)

    def _check_threshold(self, device_ip, interface, nb_data, threshold=0.5):
        # no more than threshold% uplinks drained at any time based on drained tags and down links
        iface = nb_data['interfaces'][interface]
        iface['tags'].append('drained')
        same_role_links = [
            i for i in nb_data['interfaces'].values()
            if i['peer_role'] == iface['peer_role'] and
            i['name'] != iface['name']
        ]
        drained_same_role_links = [
            i for i in same_role_links if 'drained' in i['tags'] or i['peer_status'].lower() != 'active']
        ifaces = common.napalm_get(device_ip, 'get_interfaces', self.opts)
        for i in same_role_links:
            if i['name'] not in ifaces:
                self.logger.warn(
                    f"Interface {i['name']} not found in router data")
                continue
            device_int = ifaces[i['name']]
            if device_int['is_enabled'] and not device_int['is_up']:
                drained_same_role_links.append(i)
        self.logger.info(
            f"Found {len(drained_same_role_links)} links connected to {iface['peer_role']} that are drained or down")
        if len(drained_same_role_links) / len(same_role_links) > float(threshold):
            msg = f"Found more than {float(threshold) * 100}% drained/down capacity on {nb_data['name']} to {iface['peer_role']}"
            self.logger.info(msg)
            return False, msg
        return True, f"Found no more than {float(threshold) * 100}% drained/down capacity on {nb_data['name']} to {iface['peer_role']}"

    def _audit(self, device_ip, interface, nb_data, threshold=0.5):
        iface = nb_data['interfaces'][interface]
        if (
            nb_data['role'] == 'rack-switch' and iface['peer_role'] == 'pod-switch' or
            nb_data['role'] == 'pod-switch' and iface['peer_role'] in ['cluster-switch', 'services-switch'] or
            nb_data['role'] == 'cluster-switch' and iface['peer_role'] == 'border-switch' or
            nb_data['role'] == 'border-switch' and iface['peer_role'] == 'border-router'
        ):
            return self._check_threshold(device_ip, interface, nb_data, threshold)

        if (
            nb_data['role'] == 'border-switch' and iface['peer_role'] == 'cluster-switch' or
            nb_data['role'] == 'cluster-switch' and iface['peer_role'] == 'pod-switch' or
            nb_data['role'] == 'pod-switch' and iface['peer_role'] == 'rack-switch'
        ):
            try:
                nb_url = self.opts.get(
                    'netbox_url') + f"/api/rblx/device/dm/v1/{iface['peer_name']}"
                peer_data = requests.get(nb_url).json()
                peer_ip = peer_data['primary_ip'].split('/')[0]
                return self._check_threshold(peer_ip, iface['peer_int'], peer_data)
            except Exception as ex:
                self.logger.exception(ex)
                return False, f'Hit exeption running audit: {ex}'
        return False, 'Unexpected error - unsupported role'
