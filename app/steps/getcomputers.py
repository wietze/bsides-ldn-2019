from plugins.adversary.app.commands import parsers
from plugins.adversary.app.commands.powershell import PSFunction
from plugins.adversary.app.operation.operation import Step, OPHost, OPRat, OPOSVersion, OperationWrapper, ObservedRat


class GetComputers(Step):
    """
    Description:
        This step enumerates the machines and their operating systems belonging to a domain using PowerView.
    Requirements:
        Requires a connection to a responsive Active Directory server.
    """
    attack_mapping = [('T1018', 'Discovery'), ('T1086', 'Execution'), ('T1064', 'Defense Evasion'),
                      ('T1064', 'Execution'), ('T1106', 'Execution')]
    display_name = "get_computers"
    summary = "Use PowerView to query the Active Directory server for a list of computers in the Domain"

    preconditions = [("rat", OPRat)]
    postconditions = [("host_g", OPHost),
                      ("os_version_g", OPOSVersion)]

    postproperties = ["host_g.fqdn", "host_g.os_version"]

    significant_parameters = []

    cddl = """
    Knowns:
        rat: OPRat
    Effects:
        if not exist rat {
            forget rat
        } else {
            know rat[host[domain[hosts[fqdn, os_version]]]]
        }   
    """

    @staticmethod
    def description():
        return "Enumerating all computers in the domain"

    @staticmethod
    async def action(operation: OperationWrapper, rat: ObservedRat, host_g, os_version_g):
        objects = await operation.execute_powershell(rat, 'powerview', PSFunction("Get-DomainComputer"),
                                                     parsers.powerview.getdomaincomputer)
        in_scope_fqdns = operation.filter_fqdns(objects.keys())

        # save fqdns & os versions
        for fqdn in in_scope_fqdns:
            os_version = await os_version_g({**objects[fqdn]['parsed_version_info']})
            await host_g({'fqdn': fqdn, 'os_version': os_version})

        return True
