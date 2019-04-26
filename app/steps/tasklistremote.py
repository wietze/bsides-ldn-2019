from plugins.adversary.app.commands import tasklist
from plugins.adversary.app.operation.operation import Step, OPUser, OPDomain, OPCredential, OPHost, OPRat, OPVar, OPProcess


class TasklistRemote(Step):
    """
    Description:
        This step enumerates the processes currently running on a remote target machine using tasklist.exe.
        This enumeration provides information about the processes, as well as associated services and modules.
    Requirements:
        Requires enumeration of the target host, domain enumeration, and credentials of an administrator on the
        target machine (needs both administrator enumeration 'GetAdmin', and credential data 'Credentials').
    """
    attack_mapping = [("T1057", "Discovery"), ("T1007", "Discovery"), ('T1106', 'Execution')]
    display_name = "tasklist(remote)"
    summary = "Enumerate process information using tasklist on a remote host. The command is run 3 times with the " \
              "/v (verbose), /svc (service) and /m (modules) flags"

    preconditions = [('rat', OPRat),
                     ('host', OPHost),
                     ("cred", OPCredential({'$in': {'user': OPVar("host.admins")}})),
                     ('user', OPUser(OPVar("cred.user"))),
                     ('domain', OPDomain(OPVar("user.domain")))]

    postconditions = [('process_g', OPProcess),
                      ('host_g', OPHost)]

    postproperties = ['process_g.host', 'host.processes']

    not_equal = [('host', 'rat.host')]

    significant_parameters = ['host']

    @staticmethod
    def description(rat, host):
        return "Using tasklist.exe to remotely enumerate processes on {} from {}".format(host.hostname, rat.host.hostname)

    @staticmethod
    async def simulate(operation, rat, host, cred, user, domain, process_g, host_g):
        return True

    @staticmethod
    async def action(operation, rat, host, cred, user, domain, process_g, host_g):
        processes = await operation.execute_shell_command(rat, *tasklist.main(verbose=True,
                                                                              remote_host=host.hostname,
                                                                              user_domain=domain.windows_domain,
                                                                              user=user.username,
                                                                              password=cred.password))
        # Add host to process dictionaries
        [proc.update({'host': host}) for proc in processes]

        is_equivalent = lambda proc1, proc2: True if (proc1['pid'] == proc2['pid'] and
                                                      proc1['image_name'] == proc2['image_name']) else False

        # Add service information to processes (use is_equivalent lambda to look for matching processes)
        service_information = await operation.execute_shell_command(rat, *tasklist.main(services=True,
                                                                                        remote_host=host.hostname,
                                                                                        user_domain=domain.windows_domain,
                                                                                        user=user.username,
                                                                                        password=cred.password))
        [old.update(new) if is_equivalent(old, new) else None for old in processes for new in service_information]
        # TODO: Add service results to Observed_Services in db after change to new technique cleanup is done.

        # Add module information to processes
        modules_information = await operation.execute_shell_command(rat, *tasklist.main(modules=True,
                                                                                        remote_host=host.hostname,
                                                                                        user_domain=domain.windows_domain,
                                                                                        user=user.username,
                                                                                        password=cred.password))
        [old.update(new) if is_equivalent(old, new) else None for old in processes for new in modules_information]

        for proc in processes:
            await process_g(proc)

        return True
