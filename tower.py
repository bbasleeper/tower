#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=no-member,invalid-name,attribute-defined-outside-init

"""
Import/Export Ansible Tower resources (teams, users, projects, credentials,
inventories and job templates)
"""

from __future__ import print_function

import sys
import os
import time
import argparse
import tempfile
import string
import random
import yaml
import json

import tower_cli
import requests

from paramiko.rsakey import RSAKey

# Constants
HELP_MSG = 'Import/Export Ansible Tower resources (teams, users, projects, credentials, \
            inventories and job templates)'
USAGE = '''tower <command> <args>

command can be :
load    Load data from a given file to Ansible Tower
dump    Dump data from Ansible Tower to a given file
'''
BSC_ORG = 'BSC'
SSH_KEY_BITS = 2048
PROJECT_SYNC_WAIT_TIME = 15
EDGE_DEFAULT_USER = 'automation'
ROLE_TYPES = ['admin', 'read', 'member', 'owner', 'execute', 'adhoc', 'update', 'use', 'auditor']
RESOURCE_TYPES = ['project', 'inventory', 'job_template', 'credential']
ORG_RES = tower_cli.get_resource('organization')
TEAM_RES = tower_cli.get_resource('team')
USER_RES = tower_cli.get_resource('user')
CRED_RES = tower_cli.get_resource('credential')
INV_RES = tower_cli.get_resource('inventory')
HOST_RES = tower_cli.get_resource('host')
GROUP_RES = tower_cli.get_resource('group')
PROJECT_RES = tower_cli.get_resource('project')
JOB_TMPL_RES = tower_cli.get_resource('job_template')
ROLE_RES = tower_cli.get_resource('role')


# Helper functions
def red(text, end='\n'):
    print("\033[91m {}\033[00m" .format(text), end=end)


def green(text, end='\n'):
    print("\033[92m {}\033[00m" .format(text), end=end)


def yellow(text, end='\n'):
    print("\033[93m {}\033[00m" .format(text), end=end)


def blue(text, end='\n'):
    print("\033[96m {}\033[00m" .format(text), end=end)


def gray(text, end='\n'):
    print("\033[97m {}\033[00m" .format(text), end=end)


def password_gen(size=14, chars=string.ascii_letters + string.digits + string.punctuation):
    return ''.join(random.choice(chars) for _ in range(size))


def generate_ssh_key(password, bits=SSH_KEY_BITS):
    rsakey = RSAKey.generate(bits)
    # We use a temporary file to get ssh private key
    # because RSAKey.write_private_key method does not
    # work
    ssh_priv_file = tempfile.NamedTemporaryFile(delete=False)
    ssh_priv_file.close()
    rsakey.write_private_key_file(ssh_priv_file.name, password=password)
    with open(ssh_priv_file.name) as myfile:
        ssh_private_key = myfile.read()
    os.unlink(ssh_priv_file.name)
    return dict(public=rsakey.get_name() + ' ' + rsakey.get_base64(),
                private=ssh_private_key,
                password=password)


def has_duplicates(data, resource_type):
    if resource_type in data:
        resources = {}
        for r in data[resource_type]:
            try:
                resources[r['name']] += 1
            except KeyError:
                resources[r['name']] = 1
        duplicates = [k for k, v in resources.iteritems() if v > 1]
        if len(duplicates) > 0:
            for res_name in duplicates:
                red('{} {} is duplicated !!!'.format(resource_type, res_name))
            return True
    return False


def extra_vars_to_json(vars):
    return json.dumps(yaml.load(vars))


def validate(import_data):
    is_data_valid = True
    if 'team' not in import_data:
        red('Missing "team" section !!!')
        is_data_valid = False
    elif 'name' not in import_data['team']:
        red('Missing "name" attribute in "team" section !!!')
        is_data_valid = False

    if 'credentials' in import_data:
        for cred in import_data['credentials']:
            try:
                if cred['vault_password'] == '$encrypted$':
                    red('You must set "vault_password" attribute in credential {name} !!!'.
                        format(**cred))
                    is_data_valid = False
            except KeyError:
                continue

    if 'organization' in import_data and import_data['organization'] != BSC_ORG:
        red('"organization" is not {} !!!'.format(BSC_ORG))
        is_data_valid = False

    if has_duplicates(import_data, 'credentials'):
        is_data_valid = False
    if has_duplicates(import_data, 'projects'):
        is_data_valid = False
    if has_duplicates(import_data, 'inventories'):
        is_data_valid = False
    if has_duplicates(import_data, 'job_templates'):
        is_data_valid = False

    if 'job_templates' in import_data:
        cred_resources = []
        prj_resources = []
        inv_resources = []
        if 'credentials' in import_data:
            cred_resources = [k['name'] for k in import_data['credentials']]
        if 'inventories' in import_data:
            inv_resources = [k['name'] for k in import_data['inventories']]
        if 'projects' in import_data:
            prj_resources = [k['name'] for k in import_data['projects']]
        for job in import_data['job_templates']:
            if job['credential'] not in cred_resources:
                red('Resource {credential} in job template {name} is missing !!!'.format(**job))
                is_data_valid = False
            if job['inventory'] not in inv_resources:
                red('Resource {inventory} in job template {name} is missing !!!'.format(**job))
                is_data_valid = False
            if job['project'] not in prj_resources:
                red('Resource {project} in job template {name} is missing !!!'.format(**job))
                is_data_valid = False

    return is_data_valid


class TowerResource(object):
    role_res = tower_cli.get_resource('role')
    resource_types = ['project', 'inventory', 'job_template', 'credential']
    role_types = ['admin', 'read', 'member', 'owner', 'execute', 'adhoc', 'update',
                  'use', 'auditor']

    def __init__(self, **entries):
        self.api_host = tower_cli.conf.settings.__getattr__('host')
        self.api_auth = (tower_cli.conf.settings.__getattr__('username'),
                         tower_cli.conf.settings.__getattr__('password'))
        self.__dict__.update(entries)

    def grant_permission(self, team, resource_type, resource, role_type='use', indent_level=0):
        """
            Grant permission on a resource for a team

            This function grants **role_type** permission on **resource**
            of type **resource_type** for the team **team**.
            :param team: The team to grant permission to
            :param resource_type: The type of the resource to grant permission to.
                                  Value should belong to **RESOURCE_TYPES** constant.
            :param resource: The name of the resource to grant permission to
            :param role_type: The permission type to grant
            :type team: Dictionary coming from *create_team*
            :type resource_type: string
            :type resource: string
            :type role_type: string
        """
        if resource_type not in self.resource_types:
            red('Granting permission failed, unknown resource type {}'.format(resource_type))
            return

        if role_type not in self.role_types:
            red('Granting permission failed, unknown permission type {}'.format(role_type))
            return

        if indent_level < 0:
            indent_level = 0

        role_data = dict(team=team.id, type=role_type)
        role_data[resource_type] = resource.id
        if indent_level == 0:
            print()
            yellow('Granting {} on {} {} to team {}...'
                   .format(role_type, resource_type, resource.name, team.name),
                   end='')
        else:
            gray('\t' * indent_level, end='')
            yellow('Granting {} permission to team {}...'
                   .format(role_type, team.name),
                   end='')
        self.role_res.grant(**role_data)
        green('ok')


class TowerOrganization(TowerResource):
    res = tower_cli.get_resource('organization')

    @classmethod
    def get_by_name(cls, name):
        return cls(**cls.res.get(name=name))

    @classmethod
    def get_by_id(cls, id):
        return cls(**cls.res.get(id=id))

    def associate(self, resource_id):
        self.res.associate(self.id, resource_id)


class TowerProject(TowerResource):
    res = tower_cli.get_resource('project')

    @classmethod
    def create(cls, **entries):
        return cls(**cls.res.create(**entries))

    @classmethod
    def get_by_name(cls, name):
        return cls(**cls.res.get(name=name))

    @classmethod
    def get_by_id(cls, id):
        return cls(**cls.res.get(id=id))

    def authorize_team(self, team):
        self.grant_permission(team, 'project', self, indent_level=1)

    def sync(self):
        self.res.update(pk=self.id)
        yellow('Waiting {} seconds for project syncing...'.format(PROJECT_SYNC_WAIT_TIME))
        time.sleep(PROJECT_SYNC_WAIT_TIME)


class TowerUser(TowerResource):
    res = tower_cli.get_resource('user')

    @classmethod
    def create(cls, **entries):
        return cls(**cls.res.create(**entries))

    @classmethod
    def get_by_id(cls, id):
        return cls(**cls.res.get(id=id))

    @classmethod
    def get_by_name(cls, username):
        return cls(**cls.res.get(username=username))


class TowerTeam(TowerResource):
    res = tower_cli.get_resource('team')

    @classmethod
    def create(cls, **entries):
        return cls(**cls.res.create(**entries))

    @classmethod
    def get_by_name(cls, name):
        return cls(**cls.res.get(name=name))

    def associate_users(self, users):
        print()
        gray('Associating users to team ' + self.name + '...')
        for username, user in users.iteritems():
            gray('\t' + username + '...', end='')
            self.res.associate(self.id, user.id)
            green('ok')

    def users(self):
        r = requests.get('https://' + self.api_host + self.related['users'],
                         auth=self.api_auth, verify=False)
        if r.ok:
            users = r.json()['results']
            for user in users:
                yield dict(username=str(user['username']), email=str(user['email']),
                           first_name=str(user['first_name']), last_name=str(user['last_name']))

    def credentials(self):
        r = requests.get('https://' + self.api_host + self.related['credentials'],
                         auth=self.api_auth, verify=False)
        if r.ok:
            credentials = r.json()['results']
            for cred in credentials:
                if cred['kind'] == 'ssh':
                    yield dict(username=str(cred['username']), name=str(cred['name'].upper()),
                               vault_password=str(cred['vault_password']))


class TowerCredential(TowerResource):
    res = tower_cli.get_resource('credential')

    @classmethod
    def create(cls, **entries):
        return cls(**cls.res.create(**entries))

    @classmethod
    def get_by_name(cls, name):
        return cls(**cls.res.get(name=name))

    def set_username(self, username):
        self.username = username

    def set_key_data(self, key_data):
        self.ssh_key_data = key_data

    def set_key_unlock(self, password):
        self.ssh_key_unlock = password

    def save(self):
        self.res.modify(pk=self.id, **self.__dict__)

    def authorize_team(self, team):
        self.grant_permission(team, 'credential', self, indent_level=1)


class TowerInventory(TowerResource):
    res = tower_cli.get_resource('inventory')

    @classmethod
    def create(cls, **entries):
        return cls(**cls.res.create(**entries))

    @classmethod
    def get_by_id(cls, id):
        return cls(**cls.res.get(id=id))

    def authorize_team(self, team, permission='read'):
        self.grant_permission(team, 'inventory', self, role_type=permission, indent_level=1)

    def groups(self):
        r = requests.get('https://' + self.api_host + self.related['groups'],
                         auth=self.api_auth, verify=False)
        if r.ok:
            groups = r.json()['results']
            for group in groups:
                hosts = []
                r = requests.get('https://' + self.api_host + group['related']['hosts'],
                                 auth=self.api_auth, verify=False)
                if r.ok:
                    hosts_in_group = r.json()['results']
                    for host in hosts_in_group:
                        hosts.append(dict(name=str(host['name'])))
                yield dict(name=str(group['name']), hosts=hosts)


class TowerInventoryGroup(TowerResource):
    res = tower_cli.get_resource('group')

    @classmethod
    def create(cls, **entries):
        return cls(**cls.res.create(**entries))


class TowerInventoryHost(TowerResource):
    res = tower_cli.get_resource('host')

    @classmethod
    def create(cls, **entries):
        return cls(**cls.res.create(**entries))

    def add_to_group(self, group_id):
        self.res.associate(self.id, group_id)


class TowerJobTemplate(TowerResource):
    res = tower_cli.get_resource('job_template')

    @classmethod
    def create(cls, **entries):
        return cls(**cls.res.create(**entries))

    @classmethod
    def get(cls, name):
        return cls(**cls.res.get(name=name))

    @classmethod
    def find_by_trigram(cls, trigram):
        job_templates = cls.res.list(all_pages=True)
        for tmpl in job_templates['results']:
            if tmpl['name'].upper().startswith('JOB_{}_'.format(trigram)):
                try:
                    t = dict(name=str(tmpl['name'].upper()),
                             inventory=str(tmpl['summary_fields']['inventory']['name'].upper()),
                             credential=str(tmpl['summary_fields']['credential']['name'].upper()),
                             project=str(tmpl['summary_fields']['project']['name'].upper()),
                             playbook=str(tmpl['playbook']))

                    if len(tmpl['extra_vars']) > 0:
                        t.update(extra_vars=extra_vars_to_json(tmpl['extra_vars']))

                    if bool(tmpl['survey_enabled']):
                        api_host = tower_cli.conf.settings.__getattr__('host')
                        api_auth = (tower_cli.conf.settings.__getattr__('username'),
                                    tower_cli.conf.settings.__getattr__('password'))

                        r = requests.get('https://' + api_host + tmpl['related']['survey_spec'],
                                         auth=api_auth, verify=False)
                        if r.ok:
                            survey_spec = r.json()['spec']
                            t.update(survey_spec=survey_spec)

                    yield (t, dict(inventory=tmpl['inventory'], credential=tmpl['credential'],
                                   project=tmpl['project']))
                except KeyError:
                    red('Template {} is not properly configured, skipping...'.format(tmpl['name']))


class TowerManager(object):
    def __init__(self):
        self.org = None
        self.team = None
        self.users = None
        self.credentials = None
        self.inventories = None
        self.projects = None
        self.job_templates = None


class TowerLoad(TowerManager):
    def __init__(self, data):
        super(TowerLoad, self).__init__()
        self.users = {}
        self.projects = {}
        self.credentials = {}
        self.inventories = {}
        self.job_templates = {}
        self._data = data

    def _create_users(self, userlist):
        print()
        gray('Creating users...')
        for user in userlist:
            gray('\t{username}...'.format(**user), end='')
            try:
                if user.get('external', True):
                    new_user = TowerUser.get_by_name(user['username'])
                else:
                    new_user = TowerUser.create(**user)
                self.org.associate(new_user.id)
                green('ok')
                self.users[new_user.username] = new_user
            except tower_cli.utils.exceptions.NotFound:
                red('failed')

    def _create_team(self, team_data):
        team_data.update(dict(organization=self.org.id,
                              description=team_data.get('description',
                                                        team_data['name'] + ' project team')))
        print()
        gray('Creating {description}...'.format(**team_data), end='')
        self.team = TowerTeam.create(**team_data)
        green('ok')

    def _create_projects(self, projects):
        print()
        for prj in projects:
            gray('Creating project {name}...'.format(**prj), end='')
            prj.update(dict(scm_type=prj.get('scm_type', 'git'),
                            organization=self.org.id,
                            scm_clean=prj.get('scm_clean', True),
                            scm_update_on_launch=prj.get('scm_update_on_launch', True),
                            scm_delete_on_update=prj.get('scm_delete_on_update', True)))
            new_prj = TowerProject.create(**prj)
            self.projects[prj['name']] = new_prj
            green('ok')
            new_prj.sync()
            new_prj.authorize_team(self.team)

    def _create_credentials(self, credentials):
        for cred in credentials:
            force_update = cred.get('force_update', False)
            try:
                new_cred = TowerCredential.get_by_name(cred['name'])
                already_exists = True
            except tower_cli.utils.exceptions.NotFound:
                already_exists = False
            print()
            if force_update or not already_exists:
                gray('Generate password protected ssh key for {username}@{name}...'.format(**cred),
                     end='')
                ssh_key = generate_ssh_key(password_gen())
                green('ok')
                with open(cred['name'] + '.pub', 'w') as ssh_pub_file:
                    ssh_pub_file.write(ssh_key['public'])
                yellow('SSH public key written to : ', end='')
                green(cred['name'] + '.pub')
                gray('Creating credential {name}...'.format(**cred), end='')
                if not already_exists:
                    cred.update(dict(organization=self.org.id, ssh_key_data=ssh_key['private'],
                                     ssh_key_unlock=ssh_key['password'],
                                     kind=cred.get('kind', 'ssh'),
                                     vault_password=cred.get('vault_password', password_gen())))
                    new_cred = TowerCredential.create(**cred)
                else:
                    # existing_cred.organization = self.org.id
                    new_cred.set_username(cred['username'])
                    new_cred.set_key_data(ssh_key['private'])
                    new_cred.set_key_unlock(ssh_key['password'])
                    # new_cred.kind = cred.get('kind', 'ssh')
                    # new_cred.vault_password = cred.get('vault_password', password_gen())
                    new_cred.save()
            else:
                gray('Credential {name} already exists, skipping...'.format(**cred), end='')
            self.credentials[cred['name']] = new_cred
            green('ok')
            new_cred.authorize_team(self.team)

    def _create_inventories(self, invlist):
        for inv in invlist:
            print()
            gray('Creating inventory {name}...'.format(**inv), end='')
            inv['organization'] = self.org.id
            new_inv = TowerInventory.create(**inv)
            green('ok')
            for grp in inv.get('groups', []):
                grp['inventory'] = new_inv.id
                gray('\tadding group {name} to inventory...'.format(**grp), end='')
                new_group = TowerInventoryGroup.create(**grp)
                green('ok')
                for host in grp.get('hosts', []):
                    host['inventory'] = new_inv.id
                    gray('\t\tadding host {name} to group...'.format(**host), end='')
                    new_host = TowerInventoryHost.create(**host)
                    new_host.add_to_group(new_group.id)
                    green('ok')
            new_inv.authorize_team(self.team)
            self.inventories[new_inv.name] = new_inv

    def _create_job_templates(self, templates):
        for template in templates:
            print()
            gray('Creating job template {name}...'.format(**template), end='')
            template['organization'] = self.org.id
            template['credential'] = self.credentials.get(template['credential']).id
            template['inventory'] = self.inventories.get(template['inventory']).id
            template['project'] = self.projects.get(template['project']).id
            if 'extra_vars' in template:
                template['extra_vars'] = [template['extra_vars']]
            new_job_template = TowerJobTemplate.create(**template)
            green('ok')
            self.job_templates[new_job_template.name] = new_job_template

    def run(self):
        try:
            self.org = TowerOrganization.get_by_name(self._data.get('organization', BSC_ORG))
        except tower_cli.utils.exceptions.NotFound:
            return

        self._create_team(self._data['team'])
        self._create_users(self._data['team'].get('users', []))
        self.team.associate_users(self.users)
        self._create_projects(self._data.get('projects', []))
        self._create_credentials(self._data.get('credentials', []))
        self._create_inventories(self._data.get('inventories', []))
        self._create_job_templates(self._data.get('job_templates', []))


class TowerDump(TowerManager):
    def __init__(self, trigram, filename):
        super(TowerDump, self).__init__()
        self.job_related_resources = []
        self.yml = dict(organization=None, team=None, projects=[], credentials=[],
                        inventories=[], job_templates=[])
        self.trigram = trigram
        self.filename = filename

    def _get_users_from_team(self):
        for user in self.team.users():
            self.yml['team']['users'].append(user)

    def _get_creds_from_team(self):
        for cred in self.team.credentials():
            self.yml['credentials'].append(cred)

    def _get_job_templates_from_trigram(self):
        for job_tmpl, job_rel_res in TowerJobTemplate.find_by_trigram(self.trigram):
            self.job_related_resources.append(job_rel_res)
            self.yml['job_templates'].append(job_tmpl)

    def _get_inventories_from_job_related_resources(self):
        inv_to_get = set([i['inventory'] for i in self.job_related_resources])
        for inventory_id in inv_to_get:
            inventory = TowerInventory.get_by_id(inventory_id)
            groups = []
            for group in inventory.groups():
                groups.append(group)
            self.yml['inventories'].append(dict(name=str(inventory.name),
                                                groups=groups))

    def _get_projects_from_job_related_resources(self):
        prj_to_get = set([i['project'] for i in self.job_related_resources])
        for project_id in prj_to_get:
            project = TowerProject.get_by_id(project_id)
            prj = dict(name=str(project.name), scm_url=str(project.scm_url))
            if len(project.scm_branch) > 0:
                prj.update(scm_branch=str(project.scm_branch))
            self.yml['projects'].append(prj)

    def run(self):
        try:
            self.team = TowerTeam.get_by_name('TEAM_' + self.trigram)
            self.yml['team'] = dict(name=str(self.team.name), users=[])
            self.org = TowerOrganization.get_by_id(self.team.organization)
            self.yml['organization'] = str(self.org.name)
        except tower_cli.utils.exceptions.NotFound:
            return

        self._get_users_from_team()
        self._get_creds_from_team()

        self._get_job_templates_from_trigram()
        self._get_inventories_from_job_related_resources()
        self._get_projects_from_job_related_resources()
        # TODO
        # Ajoute les creds qui ne sont pas deja recuperes par _get_creds_from_team
        # self._get_creds_from_job_related_resources()
        with open(self.filename, 'w') as output_file:
            yaml.safe_dump(self.yml, default_flow_style=False, indent=2, stream=output_file)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=HELP_MSG, usage=USAGE)
    parser.add_argument('command', help='command to run', choices=['load', 'dump'])
    args = parser.parse_args(sys.argv[1:2])

    if args.command == 'load':
        parser = argparse.ArgumentParser(description='Load data to Ansible Tower',
                                         usage='tower.py load [-h] <filename>')
        parser.add_argument('filename', help='Path to input file')
        args = parser.parse_args(sys.argv[2:])
        with open(args.filename) as import_file:
            import_data = yaml.load(import_file.read())

        if validate(import_data):
            t = TowerLoad(import_data)
            t.run()
    elif args.command == 'dump':
        parser = argparse.ArgumentParser(description='Export data from Ansible Tower',
                                         usage='tower.py dump [-h] <trigram> <filename>')
        parser.add_argument('trigram', help='Trigram to export')
        parser.add_argument('filename', help='Path to output file')
        args = parser.parse_args(sys.argv[2:])
        t = TowerDump(args.trigram.upper(), args.filename)
        t.run()
    else:
        sys.exit(1)
