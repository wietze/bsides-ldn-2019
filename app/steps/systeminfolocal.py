from plugins.adversary.app.commands import systeminfo
from plugins.adversary.app.operation.operation import Step, OPDomain, OPHost, OPRat, OPVar, OPOSVersion


class SysteminfoLocal(Step):
    """
    Description:
        This step enumerates the target machine locally using systeminfo.exe.
    Requirements:
        This step only requires the existence of a RAT on a host in order to run.
    """
    attack_mapping = [("T1082", "Discovery"), ('T1106', 'Execution')]
    display_name = "systeminfo(local)"
    summary = "Use systeminfo.exe to enumerate the local system"

    preconditions = [('rat', OPRat),
                     ('host', OPHost(OPVar('rat.host')))]
    postconditions = [('host_g', OPHost),
                      ("domain_g", OPDomain),
                      ("os_version_g", OPOSVersion)]

    postproperties = ['host_g.hostname', 'host_g.dns_domain_name', 'host_g.fqdn', 'host_g.systeminfo',
                      'host_g.os_version', 'domain_g.windows_domain', 'domain_g.dns_domain']

    significant_parameters = ['host']

    @staticmethod
    def description(rat):
        return "Using systeminfo.exe to enumerate {}".format(rat.host.hostname)

    @staticmethod
    async def simulate(operation, rat, host, host_g, domain_g, os_version_g):
        return True

    @staticmethod
    async def action(operation, rat, host, host_g, domain_g, os_version_g):
        info = await operation.execute_shell_command(rat, *systeminfo.csv())

        # Domain info
        await domain_g({'windows_domain': info['Domain'].split('.')[0], 'dns_domain': info['Domain']})

        # Add info about our current host. If we need more host information pulled with systeminfo in the future add it
        # here.
        host_fqdn = '.'.join([info['Host Name'], info['Domain']]).lower()
        # Update the host attributes that we're tracking. Also, save the command result to the database as a text
        # string.
        os_version = await os_version_g({**info['parsed_version_info']})
        await host_g({'hostname': info['Host Name'].lower(), 'dns_domain_name': info['Domain'], 'fqdn': host_fqdn,
                      'system_info': info['_original_text'], 'os_version': os_version})

        # If the RAT is running in a Domain user's context we can find a DC with this (does nothing if we're SYSTEM):
        if info['Logon Server'] != 'N/A':
            logon_server_fqdn = '.'.join([info['Logon Server'].strip('\\\\'), info['Domain']]).lower()
            await host_g({'fqdn': logon_server_fqdn, 'hostname': info['Logon Server'].strip('\\\\').lower(),
                          'dns_domain_name': info['Domain']})

        return True
