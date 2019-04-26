from plugins.adversary.app.commands import reg
from plugins.adversary.app.operation.operation import Step, OPUser, OPHost, OPRat, OPVar


class GetLocalProfiles(Step):
    """
    Description:
        This step enumerates the local profiles of a target machine by enumerating the registry using reg.exe.
    Requirements:
        This step has no hard requirements, but is necessary for another action, HKURunKeyPersist.
    """
    attack_mapping = [('T1033', 'Discovery'), ('T1012', 'Discovery'), ('T1106', 'Execution')]
    display_name = "get_local_profiles"
    summary = "Use reg.exe to enumerate user profiles that exist on a local machine"

    preconditions = [("rat", OPRat),
                     ("host", OPHost(OPVar("rat.host")))]
    postconditions = [("user_g", OPUser({'$in': OPVar("host.local_profiles")}))]

    significant_parameters = ["host"]

    postproperties = ["user_g.username", "user_g.sid", "user_g.is_group"]

    @staticmethod
    def description(rat, host):
        return "Enumerating user profiles on {}".format(rat.host.hostname)

    @staticmethod
    async def simulate(operation, rat, host, user_g):
        return True

    @staticmethod
    async def action(operation, rat, host, user_g):
        # Enumerate Local Profiles
        profile_list_loc = '"HKLM\\software\\microsoft\\windows nt\\currentversion\\profilelist"'

        q = await operation.execute_shell_command(rat, *reg.query(key=profile_list_loc, switches=["/s"]))

        profile_keys = [x for x in q.keys() if "S-1-5-21" in x]
        for key in profile_keys:
            sid = key[key.rfind("\\")+1:]  # The SID is at the end of the key
            profile_path = q[key]['ProfileImagePath'].data
            username = profile_path[profile_path.rfind('\\')+1:]  # Assume that directory name is the username.
            await user_g({'username': username, 'sid': sid, 'is_group': False})

        return True
