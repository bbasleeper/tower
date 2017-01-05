#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=no-member,invalid-name,attribute-defined-outside-init
# pylint: disable=too-many-instance-attributes, too-few-public-methods

"""
Import/Export Ansible Tower resources (teams, users, projects, credentials,
inventories and job templates)
"""

from __future__ import print_function

import sys
import os
import os.path
import time
import argparse
import tempfile
import string
import random
import json
import yaml

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
    """
    Prints a message in RED

    :param text: The text to print
    :param end: The character to print at the end of the line.
    :type text: string
    :type end: string
    """
    print("\033[91m {}\033[00m" .format(text), end=end)


def green(text, end='\n'):
    """
    Prints a message in GREEN

    :param text: The text to print
    :param end: The character to print at the end of the line.
    :type text: string
    :type end: string
    """
    print("\033[92m {}\033[00m" .format(text), end=end)


def yellow(text, end='\n'):
    """
    Prints a message in YELLOW

    :param text: The text to print
    :param end: The character to print at the end of the line.
    :type text: string
    :type end: string
    """
    print("\033[93m {}\033[00m" .format(text), end=end)


def blue(text, end='\n'):
    """
    Prints a message in BLUE

    :param text: The text to print
    :param end: The character to print at the end of the line.
    :type text: string
    :type end: string
    """
    print("\033[96m {}\033[00m" .format(text), end=end)


def gray(text, end='\n'):
    """
    Prints a message in GRAY

    :param text: The text to print
    :param end: The character to print at the end of the line.
    :type text: string
    :type end: string
    """
    print("\033[97m {}\033[00m" .format(text), end=end)


def password_gen(size=14, chars=string.ascii_letters + string.digits + string.punctuation):
    """
    Generates a random password

    :param size: Length of the password.
    :param chars: List of characters to use to generate the password.
    :type size: int
    :type chars: string
    :return: The generated password.
    :rtype: string
    """
    return ''.join(random.choice(chars) for _ in range(size))


def generate_ssh_key(password, bits=SSH_KEY_BITS):
    """
    Generates a password protected SSH key

    :param password: Password used to encrypt the key.
    :param bits: Length of the bits used for the key.
    :type password: string
    :type bits: int
    :return: The generated SSH key.
    :rtype: dict
    """
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
    """
    Check if a resource is duplicated.
    """
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


def extra_vars_to_json(extra_vars):
    """
    Convert 'extra_vars' from yaml to json.
    """
    return json.dumps(yaml.load(extra_vars))


def validate(data):
    """
    Validates yaml data before importing into Ansible Tower
    """
    gray('Validating data before import...')
    is_data_valid = True
    if 'team' not in data:
        red('Missing "team" section !!!')
        is_data_valid = False
    elif 'name' not in data['team']:
        red('Missing "name" attribute in "team" section !!!')
        is_data_valid = False

    if 'credentials' in data:
        for cred in data['credentials']:
            try:
                if cred['vault_password'] == '$encrypted$':
                    red('You must set "vault_password" attribute in credential {name} !!!'.
                        format(**cred))
                    is_data_valid = False
            except KeyError:
                continue

    if 'organization' in data and data['organization'] != BSC_ORG:
        red('"organization" is not {} !!!'.format(BSC_ORG))
        is_data_valid = False

    if has_duplicates(data, 'credentials'):
        is_data_valid = False
    if has_duplicates(data, 'projects'):
        is_data_valid = False
    if has_duplicates(data, 'inventories'):
        is_data_valid = False
    if has_duplicates(data, 'job_templates'):
        is_data_valid = False

    if 'users' in data['team']:
        for user in data['team'].get('users', []):
            if not user.get('external', True):
                if 'password' not in user:
                    red('Password must be set for user {username}'.format(**user))
                    is_data_valid = False

    if 'job_templates' in data:
        cred_resources = []
        prj_resources = []
        inv_resources = []
        if 'credentials' in data:
            cred_resources = [k['name'] for k in data['credentials']]
        if 'inventories' in data:
            inv_resources = [k['name'] for k in data['inventories']]
        if 'projects' in data:
            prj_resources = [k['name'] for k in data['projects']]
        for job in data['job_templates']:
            if job['credential'] not in cred_resources:
                red('Resource {credential} in job template {name} is missing !!!'.format(**job))
                is_data_valid = False
            if job['inventory'] not in inv_resources:
                red('Resource {inventory} in job template {name} is missing !!!'.format(**job))
                is_data_valid = False
            if job['project'] not in prj_resources:
                red('Resource {project} in job template {name} is missing !!!'.format(**job))
                is_data_valid = False

    if is_data_valid:
        green('Import data ok')

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
        """
        Get tower organization by name
        """
        return cls(**cls.res.get(name=name))

    @classmethod
    def get_by_id(cls, org_id):
        """
        Get tower organization by id
        """
        return cls(**cls.res.get(id=org_id))

    def associate(self, resource_id):
        """
        Associates a resource to this organization
        """
        self.res.associate(self.id, resource_id)


class TowerProject(TowerResource):
    res = tower_cli.get_resource('project')

    @classmethod
    def create(cls, **entries):
        """
        Creates a tower project
        """
        return cls(**cls.res.create(**entries))

    @classmethod
    def get_by_name(cls, prj_name):
        """
        Get a towerproject by name
        """
        return cls(**cls.res.get(name=prj_name))

    @classmethod
    def get_by_id(cls, prj_id):
        """
        Get a tower project by id
        """
        return cls(**cls.res.get(id=prj_id))

    def authorize_team(self, team):
        """
        Grants permission on this project to specified team
        """
        self.grant_permission(team, 'project', self, indent_level=1)

    def sync(self):
        """
        Ask Ansible Tower to launch a project sync
        """
        self.res.update(pk=self.id)
        yellow('Waiting {} seconds for project syncing...'.format(PROJECT_SYNC_WAIT_TIME))
        time.sleep(PROJECT_SYNC_WAIT_TIME)


class TowerUser(TowerResource):
    res = tower_cli.get_resource('user')

    @classmethod
    def create(cls, **entries):
        """
        Create a tower user
        """
        return cls(**cls.res.create(**entries))

    @classmethod
    def get_by_id(cls, user_id):
        """
        Get a tower user by id
        """
        return cls(**cls.res.get(id=user_id))

    @classmethod
    def get_by_name(cls, user_name):
        """
        Get a tower user by name
        """
        return cls(**cls.res.get(username=user_name))


class TowerTeam(TowerResource):
    res = tower_cli.get_resource('team')

    @classmethod
    def create(cls, **entries):
        """
        Create a tower team
        """
        return cls(**cls.res.create(**entries))

    @classmethod
    def get_by_name(cls, team_name):
        """
        Get a tower team by name
        """
        return cls(**cls.res.get(name=team_name))

    @classmethod
    def list_names_by_trigram(cls, trigram):
        """
        List all team names matching a trigram, or all teams if trigram is None
        """
        for team in cls.res.list(all_pages=True)['results']:
            if trigram is None or team['name'].upper() == 'TEAM_' + trigram.upper():
                yield team['name']

    def associate_users(self, users):
        """
        Associates users to this team
        """
        print()
        gray('Associating users to team ' + self.name + '...')
        for username, user in users.iteritems():
            gray('\t' + username + '...', end='')
            self.res.associate(self.id, user.id)
            green('ok')

    def users(self):
        """
        Get all users associated to this team
        """
        r = requests.get('https://' + self.api_host + self.related['users'],
                         auth=self.api_auth, verify=False)
        if r.ok:
            users = r.json()['results']
            for user in users:
                yield dict(username=str(user['username']), email=str(user['email']),
                           first_name=str(user['first_name']), last_name=str(user['last_name']))

    def credentials(self):
        """
        Get all credentials associated to this team
        """
        r = requests.get('https://' + self.api_host + self.related['credentials'],
                         auth=self.api_auth, verify=False)
        if r.ok:
            credentials = r.json()['results']
            for cred in credentials:
                if cred['kind'] == 'ssh':
                    result = dict(username=str(cred['username']), name=str(cred['name'].upper()))
                    if len(cred['vault_password']) > 0:
                        result.update(dict(vault_password=str(cred['vault_password'])))
                    yield result


class TowerCredential(TowerResource):
    res = tower_cli.get_resource('credential')

    @classmethod
    def create(cls, **entries):
        """
        Create a tower credential
        """
        return cls(**cls.res.create(**entries))

    @classmethod
    def get_by_name(cls, cred_name):
        """
        Get a tower credential by name
        """
        return cls(**cls.res.get(name=cred_name))

    def set_username(self, username):
        """
        Change credential username
        """
        self.username = username

    def set_key_data(self, key_data):
        """
        Change credential SSH private key
        """
        self.ssh_key_data = key_data

    def set_key_unlock(self, password):
        """
        Change credential SSH private key password
        """
        self.ssh_key_unlock = password

    def save(self):
        """
        Save changes to Ansible Tower
        """
        self.res.modify(pk=self.id, **self.__dict__)

    def authorize_team(self, team):
        """
        Allow 'use' permission to specified team on this credential
        """
        self.grant_permission(team, 'credential', self, indent_level=1)


class TowerInventory(TowerResource):
    res = tower_cli.get_resource('inventory')

    @classmethod
    def create(cls, **entries):
        """
        Create tower inventory
        """
        return cls(**cls.res.create(**entries))

    @classmethod
    def get_by_id(cls, inv_id):
        """
        Get tower inventory by id
        """
        return cls(**cls.res.get(id=inv_id))

    def authorize_team(self, team, permission='read'):
        """
        Allow permission to specified team on this inventory
        """
        self.grant_permission(team, 'inventory', self, role_type=permission, indent_level=1)

    def groups(self):
        """
        Returns groups (and hosts in each group) of the inventory
        """
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
        """
        Create inventory group
        """
        return cls(**cls.res.create(**entries))


class TowerInventoryHost(TowerResource):
    res = tower_cli.get_resource('host')

    @classmethod
    def create(cls, **entries):
        """
        Create inventory host
        """
        return cls(**cls.res.create(**entries))

    def add_to_group(self, group_id):
        """
        Associate host to group
        """
        self.res.associate(self.id, group_id)


class TowerJobTemplate(TowerResource):
    res = tower_cli.get_resource('job_template')

    @classmethod
    def create(cls, **entries):
        """
        Create tower job template
        """
        return cls(**cls.res.create(**entries))

    @classmethod
    def get(cls, job_name):
        """
        Get tower job template by name
        """
        return cls(**cls.res.get(name=job_name))

    @classmethod
    def find_by_trigram(cls, trigram):
        """
        Returns job templates matching a trigram
        """
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

    def add_survey(self, spec):
        api_host = tower_cli.conf.settings.__getattr__('host')
        api_auth = (tower_cli.conf.settings.__getattr__('username'),
                    tower_cli.conf.settings.__getattr__('password'))
        gray('  Adding survey to {}...'.format(self.name), end='')
        survey_spec = dict(name='', description='', spec=spec)
        r = requests.post('https://' + api_host + self.related['survey_spec'],
                          auth=api_auth, verify=False, json=survey_spec)
        green('ok') if r.ok else red('failed')


def create_team(org, team_data):
    team_data.update(dict(organization=org.id,
                          description=team_data.get('description',
                                                    team_data['name'] + ' project team')))
    print()
    gray('Creating {description}...'.format(**team_data), end='')
    team = TowerTeam.create(**team_data)
    green('ok')

    return team


def create_users(userlist):
    print()
    gray('Creating users...')
    for user in userlist:
        gray('\t{username}...'.format(**user), end='')
        try:
            user['username'] = user['username'].lower()
            if user.get('external', True):
                new_user = TowerUser.get_by_name(user['username'])
                green('already exists')
            else:
                if 'password' not in user:
                    user['password'] = password_gen()
                new_user = TowerUser.create(**user)
                green('created')
        except tower_cli.utils.exceptions.NotFound:
            yellow(' does not exist in Tower, skipping')
            continue

        yield new_user


def create_projects(org, team, projects):
    print()
    for prj in projects:
        gray('Creating project {name}...'.format(**prj), end='')
        prj.update(dict(scm_type=prj.get('scm_type', 'git'),
                        organization=org.id,
                        scm_clean=prj.get('scm_clean', True),
                        scm_update_on_launch=prj.get('scm_update_on_launch', True),
                        scm_delete_on_update=prj.get('scm_delete_on_update', True)))
        new_prj = TowerProject.create(**prj)
        green('ok')
        new_prj.sync()
        new_prj.authorize_team(team)

        yield new_prj


def create_credentials(org, team, credentials):
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
                cred.update(dict(organization=org.id, ssh_key_data=ssh_key['private'],
                                 ssh_key_unlock=ssh_key['password'],
                                 kind=cred.get('kind', 'ssh')))
                if 'vault_password' in cred:
                    cred.update(dict(vault_password=cred['vault_password']))
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
        green('ok')
        new_cred.authorize_team(team)

        yield new_cred


def create_inventories(org, team, invlist):
    for inv in invlist:
        print()
        gray('Creating inventory {name}...'.format(**inv), end='')
        inv['organization'] = org.id
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
        new_inv.authorize_team(team)

        yield new_inv


def create_job_templates(org, credentials, inventories, projects, templates):
    for template in templates:
        print()
        gray('Creating job template {name}...'.format(**template), end='')
        template['organization'] = org.id
        template['credential'] = credentials.get(template['credential']).id
        template['inventory'] = inventories.get(template['inventory']).id
        template['project'] = projects.get(template['project']).id
        if 'extra_vars' in template:
            template['extra_vars'] = [template['extra_vars']]
        if 'survey_spec' in template:
            template['survey_enabled'] = True
        new_job_template = TowerJobTemplate.create(**template)
        green('ok')
        if 'survey_spec' in template:
            new_job_template.add_survey(template['survey_spec'])


def tower_load(data):
    org = None
    team = None
    users = {}
    projects = {}
    credentials = {}
    inventories = {}

    try:
        org = TowerOrganization.get_by_name(data.get('organization', BSC_ORG))
    except tower_cli.utils.exceptions.NotFound:
        return

    team = create_team(org, data['team'])
    for new_user in create_users(data['team'].get('users', [])):
        org.associate(new_user.id)
        users[new_user.username] = new_user
    team.associate_users(users)
    for new_prj in create_projects(org, team, data.get('projects', [])):
        projects[new_prj.name] = new_prj
    for new_cred in create_credentials(org, team, data.get('credentials', [])):
        credentials[new_cred.name] = new_cred
    for new_inv in create_inventories(org, team, data.get('inventories', [])):
        inventories[new_inv.name] = new_inv
    create_job_templates(org, credentials, inventories, projects, data.get('job_templates', []))


def get_inventories_from_job_related_resources(job_related_resources):
    inv_to_get = set([i['inventory'] for i in job_related_resources])
    for inventory_id in inv_to_get:
        inventory = TowerInventory.get_by_id(inventory_id)
        groups = []
        for group in inventory.groups():
            groups.append(group)
        yield dict(name=str(inventory.name), groups=groups)


def get_projects_from_job_related_resources(job_related_resources):
    prj_to_get = set([i['project'] for i in job_related_resources])
    for project_id in prj_to_get:
        project = TowerProject.get_by_id(project_id)
        prj = dict(name=str(project.name), scm_url=str(project.scm_url))
        if len(project.scm_branch) > 0:
            prj.update(scm_branch=str(project.scm_branch))
        yield prj


def tower_dump(base_filename, trigram_to_dump=None):
    for team_name in TowerTeam.list_names_by_trigram(trigram_to_dump):
        job_related_resources = []
        yml = dict(organization=None, team=dict(name=None, users=[]), projects=[],
                   credentials=[], inventories=[], job_templates=[])
        trigram_current = team_name.replace('TEAM_', '')
        if not trigram_to_dump:
            filename = os.path.splitext(base_filename)[0] + '_' + \
                trigram_current.upper() + os.path.splitext(base_filename)[1]
        else:
            filename = base_filename

        try:
            gray('Exporting data for team {} to {}...'.format(team_name, filename))
            team = TowerTeam.get_by_name(team_name)
            yml['team'].update(dict(name=str(team.name)))
            org = TowerOrganization.get_by_id(team.organization)
            yml['organization'] = str(org.name)

            for user in team.users():
                yml['team']['users'].append(user)

            for cred in team.credentials():
                yml['credentials'].append(cred)

            for job_tmpl, job_rel_res in TowerJobTemplate.find_by_trigram(trigram_current):
                job_related_resources.append(job_rel_res)
                yml['job_templates'].append(job_tmpl)

            for inv in get_inventories_from_job_related_resources(job_related_resources):
                yml['inventories'].append(inv)
            for prj in get_projects_from_job_related_resources(job_related_resources):
                yml['projects'].append(prj)
            # TODO
            # Ajoute les creds qui ne sont pas deja recuperes par _get_creds_from_team
            # self._get_creds_from_job_related_resources()
            with open(filename, 'w') as output_file:
                yaml.safe_dump(yml, default_flow_style=False, indent=2, stream=output_file)
        except tower_cli.utils.exceptions.NotFound:
            red('Team {} not found'.format(team_name))
            continue


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
            tower_load(import_data)
    elif args.command == 'dump':
        parser = argparse.ArgumentParser(description='Export data from Ansible Tower',
                                         usage='tower.py dump [-h] <filename> [trigram]')
        parser.add_argument('filename', help='Path to output file')
        parser.add_argument('-t', '--trigram',
                            help='Trigram to export. If empty, export all trigrams. \
                                  Each one in its own file.',
                            required=False)
        args = parser.parse_args(sys.argv[2:])
        tower_dump(args.filename, args.trigram)
    else:
        sys.exit(1)
