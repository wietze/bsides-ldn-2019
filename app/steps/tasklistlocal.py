from plugins.adversary.app.commands import tasklist
from plugins.adversary.app.operation.operation import Step, OPHost, OPRat, OPVar, OPProcess


class TasklistLocal(Step):
    """
    Description:
        This step locally enumerates the processes currently running on a target machine using tasklist.exe.
        This enumeration provides information about the processes, as well as associated services and modules.
    Requirements:
        This step only requires the existence of a RAT on a host in order to run.
    """
    attack_mapping = [("T1057", "Discovery"), ("T1007", "Discovery"), ('T1106', 'Execution')]
    display_name = "tasklist(local)"
    summary = "Enumerate process information using tasklist on the local system. The command is run 3 times with the" \
              " /v (verbose), /svc (service) and /m (modules) flags"

    preconditions = [('rat', OPRat),
                     ('host', OPHost(OPVar('rat.host')))]
    postconditions = [("process_g", OPProcess({'$in': OPVar("host.processes")}))]

    postproperties = ['process_g.host', 'host.processes']

    significant_parameters = ['host']

    @staticmethod
    def description(rat):
        return "Using tasklist.exe to enumerate processes on {}".format(rat.host.hostname)

    @staticmethod
    async def simulate(operation, rat, host, process_g):
        return True

    @staticmethod
    async def action(operation, rat, host, process_g):
        processes = await operation.execute_shell_command(rat, *tasklist.main(verbose=True))

        # Add host to process dictionaries
        [proc.update({'host': host}) for proc in processes]

        is_equivalent = lambda proc1, proc2: True if (proc1['pid'] == proc2['pid'] and
                                                      proc1['image_name'] == proc2['image_name']) else False

        # Add service information to processes (use is_equivalent lambda to look for matching processes)
        service_information = await operation.execute_shell_command(rat, *tasklist.main(services=True))
        [old.update(new) if is_equivalent(old, new) else None for old in processes for new in service_information]
        # TODO: Add service results to Observed_Services in db after change to new technique cleanup is done.

        # Add module information to processes
        modules_information = await operation.execute_shell_command(rat, *tasklist.main(modules=True))
        [old.update(new) if is_equivalent(old, new) else None for old in processes for new in modules_information]

        for proc in processes:
            await process_g(proc)

        return True
