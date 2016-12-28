#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import sys
import os
import tempfile
import string
import random
import yaml
import tower_cli

from paramiko.rsakey import RSAKey

# Constants
BSC_ORG = 'BSC'
SSH_KEY_BITS = 2048
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


class TowerResource(object):
    role_res = tower_cli.get_resource('role')
    resource_types = ['project', 'inventory', 'job_template', 'credential']

    def __init__(self, **entries):
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
    org_res = tower_cli.get_resource('organization')

    @classmethod
    def get(cls, org_name):
        return cls(**cls.org_res.get(name=org_name))

    def associate(self, resource_id):
        self.org_res.associate(self.id, resource_id)


class TowerProject(TowerResource):
    project_res = tower_cli.get_resource('project')

    @classmethod
    def create(cls, **entries):
        return cls(**cls.project_res.create(**entries))

    def authorize_team(self, team):
        self.grant_permission(team, 'project', self, indent_level=1)


class TowerUser(TowerResource):
    user_res = tower_cli.get_resource('user')

    @classmethod
    def create(cls, **entries):
        return cls(**cls.user_res.create(**entries))


class TowerTeam(TowerResource):
    team_res = tower_cli.get_resource('team')

    @classmethod
    def create(cls, **entries):
        return cls(**cls.team_res.create(**entries))

    def associate_users(self, users):
        print()
        gray('Associating users to team ' + self.name + '...')
        for username, user in users.iteritems():
            gray('\t' + username + '...', end='')
            self.team_res.associate(self.id, user.id)
            green('ok')


class TowerCredential(TowerResource):
    cred_res = tower_cli.get_resource('credential')

    @classmethod
    def create(cls, **entries):
        return cls(**cls.cred_res.create(**entries))

    def authorize_team(self, team):
        self.grant_permission(team, 'credential', self, indent_level=1)


class TowerInventory(TowerResource):
    inv_res = tower_cli.get_resource('inventory')

    @classmethod
    def create(cls, **entries):
        return cls(**cls.inv_res.create(**entries))

    def authorize_team(self, team, permission='read'):
        self.grant_permission(team, 'inventory', self, role_type=permission, indent_level=1)


class TowerInventoryGroup(TowerResource):
    group_res = tower_cli.get_resource('group')

    @classmethod
    def create(cls, **entries):
        return cls(**cls.group_res.create(**entries))


class TowerInventoryHost(TowerResource):
    host_res = tower_cli.get_resource('host')

    @classmethod
    def create(cls, **entries):
        return cls(**cls.host_res.create(**entries))

    def add_to_group(self, group_id):
        self.host_res.associate(self.id, group_id)

class TowerManager(object):
    role_types = ['admin', 'read', 'member', 'owner', 'execute', 'adhoc', 'update', 'use', 'auditor']

    job_tmpl_res = tower_cli.get_resource('job_template')

    def __init__(self):
        self.org = None
        self.team = None
        self.users = {}
        self.credentials = {}
        self.inventories = []
        self.projects = {}
        self.job_templates = []

    def _create_users(self, userlist):
        print()
        gray('Creating users...')
        self.users = {}
        for user in userlist:
            gray('\t{username}...'.format(**user), end='')
            new_user = TowerUser.create(**user)
            self.org.associate(new_user.id)
            green('ok')
            self.users[new_user.username] = new_user

    def _create_team(self, team_name):
        team_data = dict(organization=self.org.id, name=team_name,
                         description=team_name + ' project team')
        print()
        gray('Creating {description}...'.format(**team_data), end='')
        self.team = TowerTeam.create(**team_data)
        green('ok')

    def _create_projects(self, projects):
        print()
        for prj in projects:
            gray('Creating project {name}...'.format(**prj), end='')
            project_data = dict(scm_type='git', scm_url=prj['scm_url'], name=prj['name'],
                                organization=self.org.id, scm_clean=True,
                                scm_update_on_launch=True, scm_delete_on_update=True)
            new_prj = TowerProject.create(**project_data)
            self.projects[prj['name']] = new_prj
            green('ok')
            new_prj.authorize_team(self.team)

    def _create_credentials(self, credentials):
        for cred in credentials:
            print()
            gray('Generate password protected ssh key for {name}...'.format(**cred), end='')
            ssh_key = generate_ssh_key(password_gen())
            green('ok')
            with open(cred['name'] + '.pub', 'w') as ssh_pub_file:
                ssh_pub_file.write(ssh_key['public'])
            yellow('SSH public key written to : ', end='')
            green(cred['name'] + '.pub')
            gray('Creating credential {name}...'.format(**cred), end='')
            cred_data = dict(kind='ssh', name=cred['name'], organization=self.org.id,
                             username=cred['username'], ssh_key_data=ssh_key['private'],
                             ssh_key_unlock=ssh_key['password'],
                             vault_password=cred.get('vault_password', password_gen()))
            new_cred = TowerCredential.create(**cred_data)
            self.credentials[cred['name']] = new_cred
            green('ok')
            new_cred.authorize_team(self.team)

    def _create_inventories(self, inventories):
        for inv in inventories:
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

    def load(self, filename):
        with open(filename) as import_file:
            import_data = yaml.load(import_file.read())

        if 'global' in import_data and 'team' in import_data \
            and 'name' in import_data['team']:

            try:
                self.org = TowerOrganization.get(import_data['global'].get('organization', BSC_ORG))
            except tower_cli.utils.exceptions.NotFound:
                return

        self._create_team(import_data['team']['name'])
        self._create_users(import_data['team'].get('users', []))
        self.team.associate_users(self.users)
        self._create_projects(import_data.get('projects', []))
        self._create_credentials(import_data.get('credentials', []))
        self._create_inventories(import_data.get('inventories', []))

    def save(self, org, trigram, filename):
        pass


if __name__ == '__main__':
    t = TowerManager()
    t.load(sys.argv[1])
