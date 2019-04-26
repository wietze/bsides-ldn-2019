from plugins.adversary.app.commands import net
from plugins.adversary.app.operation.operation import Step, OPHost, OPRat, OPVar, OPShare, OPFile


class RemoveNetShare(Step):
    """
    Description:
        This step unmounts a C$ network share on a target remote machine using net use.
    Requirements:
        Requires destation host has an executed RAT and a mounted share.
    """
    attack_mapping = [('T1126', 'Defense Evasion'), ('T1077', 'Lateral Movement'), ('T1106', 'Execution')]
    display_name = "remove_share"
    summary = "Unmount a C$ network share using net use"

    preconditions = [("rat", OPRat),
                     ('dest_host', OPHost),
                     ('rat_file', OPFile({'host': OPVar("dest_host"), 'use_case': 'rat'})),
                     ('share', OPShare({'src_host': OPVar("rat.host"), 'share_removed': False}))]

    postconditions = [('share_g',OPShare({"src_host": OPVar("rat.host"), "dest_host": OPVar("dest_host"),
                                           'share_name': 'C$', 'share_removed': True}))]

    not_equal = [('dest_host', 'rat.host')]

    significant_parameters = ["rat_file"]

    preproperties = ['share.share_path']
    postproperties = ["share_g.share_removed"]

    cddl = """
    """

    @staticmethod
    def description(rat, dest_host):
        return "Unmounting {}'s C$ network share from {} with net use".format(dest_host.fqdn, rat.host.fqdn)

    @staticmethod
    async def simulate(operation, rat, rat_file, dest_host, share, share_g):
        return True

    @staticmethod
    async def action(operation, rat, rat_file, dest_host, share, share_g):
        await operation.execute_shell_command(rat, *net.use_delete(remote_host=dest_host.fqdn,
                                                                   remote_share=share.share_name))
        await share_g({'share_path': '\\\\{}\\C$'.format(dest_host.fqdn), 'mount_point': 'C:', 'share_removed': True})
        return True
