import json
import sys
import smtplib
import requests
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from jinja2 import Template

from scripts.remediations import common


class Fibercut:

    NB_PROV_URL = '/api/circuits/providers'

    def __init__(self, logger, opts):
        self.logger = logger
        self.opts = opts

    def run(self, inp, args):
        self.logger.info('Running remediation for: {}, Id: {}'.format(
            inp['name'], inp['id']))

        data = inp['data']
        out = {
            'Description': f"{inp['data'].get('description', '')}",
            'Start Time': f"{inp['start_time']}",
        }
        if inp['is_aggregate']:
            components = data.get('components', [])
            self.logger.info(
                f'{len(components)} entities affected by this fibercut')
        else:
            components = [data]
        tpl = {'start_time': inp['start_time']}
        providers, cids, roles = set(), set(), set()
        for c in components:
            providers.add(c['labels']['provider'])
            cids.add(c['labels']['provider_id'])
            roles.add(c['labels']['role'])
        if len(providers) > 1 or len(roles) > 1:
            out['error'] = 'Found more than 1 provider or ckt Role in incident'
            out['passed'] = False
            common.exit(out, False)
        tpl['provider'] = list(providers)[0]
        tpl['cids'] = list(cids)
        tpl['task_id'] = data.get('task_id', 'UNKNOWN')
        nb_url = self.opts.get('netbox_url') + \
            self.NB_PROV_URL + f"?slug={tpl['provider']}"
        try:
            nb_data = requests.get(nb_url)
            contacts = self.parse_contacts(nb_data.json(), list(roles)[0])
            if not contacts:
                out['error'] = (
                    f"Failed to fetch contacts for {tpl['provider']} from netbox")
                common.exit(out, False)
            t = Template(self.email_template())
            body = t.render(**tpl)
            self.sendmail(body, self.opts.get('email_server'),
                          self.opts.get('email_user'), self.opts.get(
                              'email_pass'),
                          args.email_from, contacts)
        except Exception as ex:
            self.logger.error(f'Failed to send email: {ex}')
            out['error'] = f'Failed to send email: {ex}'
            out['passed'] = False
            common.exit(out, False)
        try:
            if data.get('task_id'):
                comment = f'Email sent to provider: \n {body}'
                common.add_issue_comment(self.opts, data['task_id'], comment)
        except common.CommonException as ex:
            self.logger.error('Failed to add task comment: {}'.format(ex))

        out['passed'] = True
        common.exit(out, True)

    @staticmethod
    def parse_contacts(data, role):
        contact_str = data['results'][0]['noc_contact']
        if not contact_str:
            return []
        contacts = contact_str.split('\r\n')
        to = []
        for c in contacts:
            parts = c.split(':')
            if len(parts) > 1:
                if parts[0] == role:
                    to.append(parts[1].strip())
                    continue
            else:
                to.append(parts[0].strip())
        return to

    @staticmethod
    def email_template():
        return '''
            Dear {{provider}} Noc,
            
            The following circuits have been detected down by Roblox:

            Start Time: {{start_time}}
            Roblox Task ID: {{task_id}}

            {% for cid in cids %}
            Circuit ID: {{cid}}
            {% endfor %}
            
            Please investigate and reply back with your case number asap.

            - Roblox NOC
        '''

    def sendmail(self, body, server, username, password, em_from, em_to):
        host, port = server.split(':')
        s = smtplib.SMTP(host=host, port=int(port))
        if int(port) != 25:
            s.starttls()
        if username and password:
            s.login(username, password)
        msg = MIMEMultipart()
        msg['From'] = em_from
        msg['To'] = ','.join(em_to)
        # TODO Get the Jira task into the subject somehow
        msg['Subject'] = "Please investigate Roblox Fibercut"
        msg.attach(MIMEText(body, 'plain'))
        self.logger.info(f"Sending email to {msg['To']}")
        s.send_message(msg)
        s.quit()
