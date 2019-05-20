import sys
import requests
import time
from lxml import etree
from jnpr.junos import Device
from jira import JIRA, JIRAError


class CommonException(Exception):
    pass


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


def add_issue_comment(url, auth, project, issue_type, summary, comment):
    j = JIRA(url, auth=auth)
    issue_filter = "project={} and issueType='{}' and status != closed and summary~{}".format(
        project, issue_type, summary
    )
    try:
        issues = j.search_issues(issue_filter)
    except JIRAError as ex:
        raise CommonException('Failed to search JIRA Issue: {}'.format(ex))
    if len(issues) == 0:
        return
    try:
        j.add_comment(issues[0].key, comment)
    except JIRAError as ex:
        raise CommonException('Failed to add comment: {}'.format(ex))
    return issues[0]


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
