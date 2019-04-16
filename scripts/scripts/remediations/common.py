import sys
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
    if pwd:
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


def exit(out, passed):
    out['passed'] = passed
    txt = ''
    for k, v in out.items():
        txt += f'{k}: {v}\n\n'
    print(txt)
    if passed:
        sys.exit(0)
    sys.exit(1)
