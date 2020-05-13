import napalm
import sys
import requests
import time
from lxml import etree
from jnpr.junos import Device
from jira import JIRA, JIRAError


class CommonException(Exception):
    pass


def get_jira_issue(opts, issue_key):
    url = opts.get('jira_url')
    if not url:
        raise CommonException('Invalid URL specified')
    try:
        auth = (opts.get('jira_username'), opts.get('jira_password'))
        j = JIRA(url, auth=auth)
        issue = j.issue(issue_key)
        return j, issue
    except JIRAError as ex:
        raise CommonException(
            'Failed to get Jira issue {}: {}'.format(issue_key, ex))


def create_jira_issue(url, auth, project, issue_type, summary, description):
    j = JIRA(url, auth=auth)
    try:
        issue = j.create_issue(
            project=project,
            summary=summary,
            description=description,
            issuetype={'name': issue_type}
        )
        issue.fields.labels.append(u'auto-remediate')
        issue.update(fields={'labels': issue.fields.labels})
    except JIRAError as ex:
        raise CommonException(
            'Failed to create/update JIRA Issue: {}'.format(ex))
    return issue


def add_issue_comment(opts, issue_key, comment):
    url = opts.get('jira_url')
    if not url:
        raise CommonException('Invalid URL specified')
    auth = (opts.get('jira_username'), opts.get('jira_password'))
    j = JIRA(url, auth=auth)
    try:
        j.add_comment(issue_key, comment)
    except JIRAError as ex:
        raise CommonException('Failed to add comment: {}'.format(ex))


def close_issue(opts, issue_key, reason):
    url = opts.get('jira_url')
    if not url:
        raise CommonException('Invalid URL specified')
    auth = (opts.get('jira_username'), opts.get('jira_password'))
    j = JIRA(url, auth=auth)
    try:
        j.add_comment(issue_key, reason)
        issue = j.issue(issue_key)
        trans = j.transitions(issue)
        for t in trans:
            if t['name'] in ['Done', 'Close']:
                j.transition_issue(issue, t['id'])
    except JIRAError as ex:
        raise CommonException(f'Failed to transition: {ex}')


def update_issue(opts, issue_key, comment=None, fields=None, labels=None, components=None):
    j, issue = get_jira_issue(opts, issue_key)
    fields_to_update = {}
    update = {}
    if fields:
        allfields = j.fields()
        name_map = {field['name']: field['id'] for field in allfields}
        fields_to_update = {name_map.get(
            fk, fk): fv for fk, fv in fields.items()}
    if labels:
        fields_to_update['labels'] = labels
    if components:
        update['components'] = [
            {'set': [{'name': name} for name in components]}]
    try:
        if comment:
            j.add_comment(issue_key, comment)
        if fields or update:
            issue.update(fields=fields_to_update, update=update)
    except JIRAError as ex:
        raise CommonException(
            'Failed to update issue {}: {}'.format(issue_key, ex))


def run_junos_command(device, command, opts, port=22):
    username = opts.get('junos_user')
    password = None
    keyfile = None
    if opts.get('junos_ssh_keyfile'):
        keyfile = opts['junos_ssh_keyfile']
    elif opts.get('junos_pwd'):
        password = opts['junos_pwd']
    if not username or not (password or keyfile):
        raise CommonException('Username and password required')
    kwargs = {
        'host': device,
        'port': port,
        'user': username,
        'gather_facts': False,
        'auto_probe': 0
    }
    if password:
        kwargs['password'] = password
    if keyfile:
        kwargs['ssh_private_key_file'] = keyfile
    try:
        with Device(**kwargs) as dev:
            dev.timeout = 10
            result = dev.rpc.cli(command, format='text')
    except Exception as ex:
        raise CommonException('failed to run command on device: {}'.format(ex))
    output = etree.tostring(result, encoding='unicode')
    return output


def run_awx_job(url, token, job_id, extra_vars, limit=None, timeout=90):
    u = url + '/api/v2/job_templates/{}/launch/'.format(job_id)
    body = {
        'job_type': 'run',
        'extra_vars': extra_vars
    }
    if limit:
        body['limit'] = limit
    headers = {
        'Authorization': 'Bearer {}'.format(token),
        'Content-Type': 'Application/Json'
    }
    resp = requests.post(u, headers=headers, json=body)
    resp.raise_for_status()
    job = resp.json()
    job_id = job.get('job')
    if not job_id:
        raise CommonException('Failed to start AWX job')
    job_url = url + job['url']
    start = time.time()
    while time.time() - start <= timeout:
        resp = requests.get(job_url, headers=headers)
        job = resp.json()
        if job['status'] in ['successful', 'failed']:
            break
        time.sleep(7)
    if job['failed']:
        return job_id, False
    return job_id, True


def exit(out, passed):
    out['passed'] = passed
    txt = ''
    for k, v in out.items():
        txt += f'{k}: {v}\n\n'
    print(txt)
    if passed:
        sys.exit(0)
    sys.exit(1)


def nb_device_ip(nb_url, device):
    url = nb_url + f'/api/dcim/devices/?name={device}'
    resp = requests.get(url)
    resp.raise_for_status()
    results = resp.json()
    if len(results['results']) == 0:
        raise CommonException(f'Failed to get nb result for {device}')
    return results['results'][0]['primary_ip']['address'].split('/')[0]


def napalm_get(device_ip, getter, opts):
    driver = napalm.get_network_driver('junos')
    device = driver(device_ip, opts['junos_user'], opts['junos_pwd'])
    device.open()
    method = getattr(device, getter)
    if not method:
        raise CommonException('Invalid napalm method')
    resp = method()
    device.close()
    return resp


def clear_alertmanager_alert(am_url, am_token, alert_id, notify=True):
    url = am_url + f'/api/alerts/{alert_id}/clear'
    if not notify:
        url += '?notify=false'
    headers = {
        'Authorization': f'Bearer {am_token}',
    }
    resp = requests.patch(url, headers=headers)
    resp.raise_for_status()
    alert = resp.json()
    if alert['status'] != 'CLEARED':
        raise CommonException(f'Failed to clear alert {alert_id}')


def escalate_alertmanager_alert(am_url, am_token, alert_id, sev, notify=True):
    url = am_url + f'/api/alerts/{alert_id}/escalate?severity={sev}'
    if not notify:
        url += '&notify=false'
    headers = {
        'Authorization': f'Bearer {am_token}',
    }
    resp = requests.patch(url, headers=headers)
    resp.raise_for_status()
    alert = resp.json()
    if alert['severity'] != sev:
        msg = f'Failed to escalate alert {alert_id}'
        raise CommonException(msg)


def run_nornir_task(url, task_params, poll_interval=10, max_wait=600):
    ''' Call a nornir task and wait until result '''
    task_params.update(
        {
            'vars_file': 'shared/variables.yaml',
            'default_vars_file': 'shared/defaults.yaml',
            'project': 'Project-X',
            'use_vault_creds': True,
        }
    )
    resp = requests.post(f'{url}/tasks/', json=task_params, timeout=5.0)
    resp.raise_for_status()
    data = resp.json()
    start = int(time.time())
    while int(time.time()) - start <= max_wait:
        time.sleep(poll_interval)
        resp = requests.get(f"{url}/tasks/?job_id={data['id']}", timeout=5.0)
        resp.raise_for_status()
        data = resp.json()
        if data['status'] in ['failed', 'passed']:
            break
    if data['status'] not in ['failed', 'passed']:
        raise CommonException(
            f"Timed out waiting for job {data['id']} to finish")
    if not data['result']['output']['output']:
        return {'job_id': data['id'], 'passed': False, 'message': 'Failed to run task'}
    messages = []
    passed = True
    for device, taskresults in data['result']['output']['output'].items():
        for taskresult in taskresults:
            if not taskresult['passed']:
                messages.append(
                    f"Task {taskresult['task']} on host {device} failed with output {taskresult['output']}")
                passed = False
    return {'job_id': data['id'], 'passed': passed, 'message': '\n'.join(messages)}
