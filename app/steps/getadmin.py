from plugins.adversary.app.commands import parsers
from plugins.adversary.app.commands.powershell import PSArg, PSFunction
from plugins.adversary.app.operation.operation import Step, OPUser, OPDomain, OPHost, OPRat, OPVar


class GetAdmin(Step):
    """
    Description:
        This step enumerates the administrator accounts on a target domain connected machine using PowerView by
        querying the Windows Active Directory.
    Requirements:
        Requires a connection to a responsive Active Directory server.
    """
    attack_mapping = [('T1069', 'Discovery'), ('T1086', 'Execution'), ('T1087', 'Discovery'),
                      ('T1064', 'Defense Evasion'), ('T1064', 'Execution'), ('T1106', 'Execution')]
    display_name = "get_admin"
    summary = "Use PowerView's Get-NetLocalGroup command to query the Active Directory server for administrators " \
              "on a specific computer"

    preconditions = [("rat", OPRat),
                     ("host", OPHost)]
    postconditions = [("domain_g", OPDomain),
                      ("user_g", OPUser({'$in': OPVar("host.admins")}))]

    postproperties = ["user_g.username", "user_g.is_group", "user_g.sid"]

    significant_parameters = ["host"]

    cddl = """
    Knowns:
        rat: OPRat
        host: OPHost
    Effects:
        if not exist rat {
            forget rat
        } elif rat.elevated == True {
            know host[domain[dns_domain]]
            know host[admins[username, is_group, sid, host, domain]]
        }
    """

    @staticmethod
    def description(host):
        return "Enumerating the Administrators group of {}".format(host.fqdn)

    @staticmethod
    async def action(operation, rat, host, domain_g, user_g):
        objects = await operation.execute_powershell(rat, "powerview", PSFunction('Get-NetLocalGroupMember',
                                                                                  PSArg('ComputerName', host.hostname)),
                                                     parsers.powerview.getnetlocalgroupmember)
        for parsed_user in objects:
            # find the user for this account
            user_dict = {'username': parsed_user['username'],
                         'is_group': parsed_user['is_group'],
                         'sid': parsed_user['sid']}

            if 'dns_domain' in parsed_user:
                domain = await domain_g({'dns_domain': parsed_user['dns_domain']})
                user_dict['domain'] = domain
            elif 'windows_domain' in parsed_user:
                domain = await domain_g({'windows_domain': parsed_user['windows_domain']})
                user_dict['domain'] = domain
            else:
                user_dict['host'] = host

            await user_g(user_dict)

        return True
