from plugins.adversary.app.commands import systeminfo
from plugins.adversary.app.operation.operation import Step, OPUser, OPDomain, OPCredential, OPHost, OPRat, OPVar, OPOSVersion


class SysteminfoRemote(Step):
    """
    Description:
        This step enumerates a target machine located remotely on a network.
    Requirements:
        Requires enumeration of the target host, credentials for an administrator on the target host (needs both
        administrator enumeration 'GetAdmin', and credential data 'Credentials'), and domain enumeration.
    """
    attack_mapping = [("T1082", "Discovery"), ('T1106', 'Execution')]
    display_name = "systeminfo(remote)"
    summary = "Use systeminfo.exe to enumerate a remote system"

    preconditions = [('rat', OPRat),
                     ('host', OPHost(OPVar('rat.host'))),
                     ('dest_host', OPHost),
                     ("cred", OPCredential({'$in': {'user': OPVar("dest_host.admins")}})),
                     ('user', OPUser(OPVar("cred.user"))),
                     ('domain', OPDomain(OPVar("user.domain")))]
    postconditions = [('host_g', OPHost),
                      ("domain_g", OPDomain),
                      ('os_version_g', OPOSVersion)]

    postproperties = ['host_g.hostname', 'host_g.dns_domain_name', 'host_g.fqdn',
                      'domain_g.windows_domain', 'domain_g.dns_domain', 'host_g.systeminfo', 'host_g.os_version']

    not_equal = [('dest_host', 'rat.host')]

    significant_parameters = ['dest_host']

    @staticmethod
    def description(rat, host, dest_host):
        return "Using systeminfo.exe to remotely enumerate {}".format(dest_host.hostname)

    @staticmethod
    async def simulate(operation, rat, host, dest_host, cred, user, domain, host_g, domain_g, os_version_g):
        return True

    @staticmethod
    async def action(operation, rat, host, dest_host, cred, user, domain, host_g, domain_g, os_version_g):
        info = await operation.execute_shell_command(rat, *systeminfo.csv(remote_host=dest_host.fqdn,
                                                                          user_domain=domain.windows_domain,
                                                                          user=user.username,
                                                                          password=cred.password))

        # Domain info  -- kind of redundant to leave this in for the remote technique.
        await domain_g({'windows_domain': info['Domain'].split('.')[0], 'dns_domain': info['Domain']})

        # Add info about our current host. If we need more host information pulled with systeminfo in the future add it
        # here.
        host_fqdn = '.'.join([info['Host Name'], info['Domain']]).lower()
        os_version = await os_version_g({**info['parsed_version_info']})
        await host_g({'hostname': info['Host Name'].lower(), 'dns_domain_name': info['Domain'], 'fqdn': host_fqdn,
                      'system_info': info['_original_text'], 'os_version': os_version})

        # If the RAT is running in a Domain user's context we can find a DC with this (does nothing if we're SYSTEM):
        if info['Logon Server'] != 'N/A':
            logon_server_fqdn = '.'.join([info['Logon Server'].strip('\\\\'), info['Domain']]).lower()
            await host_g({'fqdn': logon_server_fqdn, 'hostname': info['Logon Server'].strip('\\\\').lower(),
                          'dns_domain_name': info['Domain']})

        return True
