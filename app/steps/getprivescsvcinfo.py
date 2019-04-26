from plugins.adversary.app.commands.powershell import PSFunction
from plugins.adversary.app.operation.operation import Step, OPHost, OPRat, OPVar, OPService
from plugins.adversary.app.commands import parsers


class GetPrivEscSvcInfo(Step):
    """
    Description:
        This step utilises the PowerUp powershell script to identify potential service-based privilege
        escalation opportunities on a target machine.
    Requirements:
        Requires an non-elevated RAT. This step identifies unquoted service paths, modifiable service targets,
        and modifiable services for privilege escalation purposes.
    """
    attack_mapping = [('T1007', 'Discovery'), ('T1106', 'Execution')]
    display_name = "privilege_escalation(service)"
    summary = "Use PowerUp to find potential service-based privilege escalation vectors"

    preconditions = [("rat", OPRat({"elevated": False})),
                     ("host", OPHost(OPVar("rat.host")))]

    postconditions = [("service_g", OPService({"host": OPVar("host"),
                                               "user_context": OPVar("rat.username")}))]

    @staticmethod
    def description():
        return "Looking for potential privilege escalation vectors related to services"

    @staticmethod
    async def simulate(operation, rat, host, service_g):
        return True

    @staticmethod
    async def action(operation, rat, host, service_g):
        unquoted = await operation.execute_powershell(rat, "powerup", PSFunction("Get-ServiceUnquoted"),
                                                      parsers.powerup.get_serviceunquoted)
        for parsed_service in unquoted:
            # insert each service into the database
            service_dict = {"name": parsed_service['name'],
                            "bin_path": parsed_service['bin_path'],
                            'service_start_name': parsed_service['service_start_name'],
                            'can_restart': parsed_service['can_restart'],
                            'modifiable_paths': parsed_service['modifiable_paths'],
                            'vulnerability': 'unquoted',
                            'revert_command': ""}
            await service_g(service_dict)
        fileperms = await operation.execute_powershell(rat, "powerup", PSFunction("Get-ModifiableServiceFile"),
                                                       parsers.powerup.get_modifiableservicefile)
        for parsed_service in fileperms:
            service_dict = {'name': parsed_service['name'],
                            'bin_path': parsed_service['bin_path'],
                            'service_start_name': parsed_service['service_start_name'],
                            'can_restart': parsed_service['can_restart'],
                            'modifiable_paths': parsed_service['modifiable_paths'],
                            'vulnerability': 'file',
                            'revert_command': ""}
            await service_g(service_dict)
        mod_bin_path = await operation.execute_powershell(rat, "powerup", PSFunction("Get-ModifiableService"),
                                                          parsers.powerup.get_modifiableservice)
        for parsed_service in mod_bin_path:
            service_dict = {'name': parsed_service['name'],
                            'bin_path': parsed_service['bin_path'],
                            'service_start_name': parsed_service['service_start_name'],
                            'can_restart': parsed_service['can_restart'],
                            'vulnerability': 'bin_path',
                            'revert_command': ""}
            await service_g(service_dict)
        return True
