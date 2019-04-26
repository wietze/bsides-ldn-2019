import asyncio
import random

from plugins.adversary.app.utility.general import get_simulated_domain_data

"""
This module is designed to mock out Windows commands and return the parsed Python objects
that a step is expecting to get back. 
"""


def is_fake(rat):
    return rat['pid'] == 9999


async def fake_response(rat, cmd):
    await asyncio.sleep(random.randint(2, 5))  # random sleep for realism
    domain = get_simulated_domain_data(domain=rat.host.dns_domain_name.split('.')[0])
    if 'Get-DomainComputer' in cmd.command_line:
        return await get_computers(domain)
    elif 'Invoke-Mimikatz' in cmd.command_line:
        return await get_creds(rat, domain)
    elif 'Get-NetLocalGroupMember' in cmd.command_line:
        return await get_admin(rat, domain)
    elif 'nbtstat' in cmd.command_line:
        return rat.host.dns_domain_name.split('.')[0]
    elif 'net use' in cmd.command_line:
        return True  # this step simply does, it does not return
    elif 'cmd /c copy' in cmd.command_line:
        return True  # this step simply does, it does not return


async def get_computers(domain):
    objects = dict()
    for host, data in domain['hosts'].items():
        os = data['os']
        info = dict(os_name=os['name'], major_version=os['major'], minor_version=os['minor'], build_number=os['build'])
        objects['%s.%s.local' % (host, domain['name'])] = dict(parsed_version_info=info)
    return objects


async def get_creds(rat, domain):
    host_details = next(v for k, v in domain['hosts'].items() if k == rat.host['hostname'])
    accounts = []
    for account in host_details['accounts']:
        accounts.append(dict(Username=account['user'], Password=account['password'], Domain=domain['name']))
    return accounts


async def get_admin(rat, domain):
    host_details = next(v for k, v in domain['hosts'].items() if k == rat.host['hostname'])
    users = []
    for account in host_details['accounts']:
        if account['is_admin']:
            users.append(dict(username=account['user'], sid=account['sid'], is_group=account['is_group'], windows_domain=domain['name']))
    return users


