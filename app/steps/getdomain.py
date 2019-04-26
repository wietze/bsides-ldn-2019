from plugins.adversary.app.commands import nbtstat
from plugins.adversary.app.operation.operation import Step, OPDomain, OPRat


class GetDomain(Step):
    """
    Description:
        This step enumerates the domain a machine belongs to using nbtstat.
    Requirements:
        Requires the computer to be connected to a domain, and for a rat to be accessible.
    """
    attack_mapping = [('T1016', 'Discovery'), ('T1106', 'Execution')]
    display_name = "get_domain"
    summary = "Use nbtstat to get information about the Windows Domain"

    preconditions = [("rat", OPRat)]
    postconditions = [("domain_g", OPDomain)]

    preproperties = ["rat.host.fqdn"]
    postproperties = ["domain_g.windows_domain", "domain_g.dns_domain"]

    significant_parameters = []

    cddl = """
    Knowns:
        rat: OPRat[host[fqdn]]
    Effects:
        if not exist rat {
            forget rat
        } else {
            know rat[host[domain[windows_domain, dns_domain]]]
        }
    """

    @staticmethod
    def description():
        return "Enumerating the Windows and DNS information of this domain"

    @staticmethod
    async def action(operation, rat, domain_g):
        windows_domain = await operation.execute_shell_command(rat, *nbtstat.n())
        dns_domain = '.'.join(rat.host.fqdn.split('.')[1:])
        await domain_g({'windows_domain': windows_domain, 'dns_domain': dns_domain})
        return True
