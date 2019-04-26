from datetime import datetime

from plugins.adversary.app.commands import net
from plugins.adversary.app.operation.operation import Step, OPHost, OPRat, OPVar, OPTimeDelta


class NetTime(Step):
    """
    Description:
        This step determines the current time on a target machine, using the 'net time' command.
    Requirements:
        This step has no hard requirements, but is necessary for several other steps, such as Schtasks.
    """
    attack_mapping = [('T1124', 'Discovery'), ('T1106', 'Execution')]
    display_name = "net_time"
    summary = 'Remotely enumerate host times using "net time"'

    preconditions = [("rat", OPRat),
                     ('host', OPHost)]

    postconditions = [('time_delta_g', OPTimeDelta({"host": OPVar("host")}))]

    preproperties = ["host.fqdn"]
    postproperties = ["time_delta_g.seconds", "time_delta_g.microseconds", "time_delta_g.days"]

    deterministic = True

    cddl = """
    Knowns:
        rat: OPRat
        host: OPHost
    Effects:
        if not exist rat {
            forget rat
        } else {
            know host[timedelta[seconds, microseconds]]
        }
    """

    @staticmethod
    def description(host):
        return "Determining the time on {}".format(host.fqdn)

    @staticmethod
    async def simulate(operation, rat, host, time_delta_g):
        return True

    @staticmethod
    async def action(operation, rat, host, time_delta_g):
        d = await operation.execute_shell_command(rat, *net.time(host.fqdn))
        now = datetime.utcnow()
        delta = now - d
        await time_delta_g({'seconds': delta.seconds, 'microseconds': delta.microseconds, 'days': delta.days})
        return True
