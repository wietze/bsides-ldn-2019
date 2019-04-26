import logging

from plugins.adversary.app.commands import netstat
from plugins.adversary.app.operation.operation import Step, OPRat


log = logging.getLogger(__name__)


class NetworkConnections(Step):
    attack_mapping = [("T1049", "Discovery")]
    display_name = "get network connections"
    summary = "Uses netstat to retrieve current network connections."

    preproperties = ['rat.host.fqdn', 'rat.username']

    preconditions = [('rat', OPRat)]

    postconditions = []

    @staticmethod
    def description(rat):
        return "Using netstat to retrieve network connections on {}".format(rat.host.fqdn)

    @staticmethod
    async def simulate(operation, rat):
        return True

    @staticmethod
    async def action(operation, rat):
        if "system" in rat.username:
            await operation.execute_shell_command(rat, *netstat.anob())
        else:
            await operation.execute_shell_command(rat, *netstat.ano())
        return True
