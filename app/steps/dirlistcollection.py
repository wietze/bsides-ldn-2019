from plugins.adversary.app.commands import cmd
from plugins.adversary.app.operation.operation import Step, OPFile, OPHost, OPRat, OPVar


class DirListCollection(Step):
    """
    Description:
        This step enumerates files on the target machine. Specifically, it looks for files with 'password' or
        'admin' in the name.
    Requirements:
        This step only requires the existence of a RAT on a host in order to run.
    """
    attack_mapping = [("T1005", "Collection"), ("T1083", "Discovery"), ('T1106', 'Execution')]
    display_name = "list_files"
    summary = "Enumerate files locally with a for loop and the dir command recursively"

    preconditions = [('rat', OPRat),
                     ('host', OPHost(OPVar("rat.host")))]

    postconditions = [('file_g', OPFile({'use_case': 'collect',
                                         'host': OPVar("host")}))]

    significant_parameters = ['host']  # no need to do this more than once per host

    postproperties = ['file_g.path']

    @staticmethod
    def description(rat, host):
        return "Using cmd to recursively look for files to collect on {}".format(host.hostname)

    @staticmethod
    async def simulate(operation, rat, host, file_g):
        return True

    @staticmethod
    async def action(operation, rat, host, file_g):
        # dir path\*word1* /s /b /a-d
        # for now, hard coded list of words we're interested in in file names
        # for now, hard coded list of paths to check for these files
        keywords = operation.adversary_artifactlist.get_targets()
        if "system" in rat.username:
            keypaths = ["C:\\Users\\"]
        else:
            keypaths = ['C:\\Users\\' + rat.username.split("\\")[1] + "\\"]

        for path in keypaths:
            for word in keywords:
                try:
                    # if the b,s, and a flags change on this command, be sure to implement a new parser!
                    files = await operation.execute_shell_command(rat, *cmd.dir_list(search=path + "*" + word + "*",
                                                                                     b=True, s=True, a="-d"))
                    for file in files:
                        await file_g({'path': file})
                except FileNotFoundError:
                    # the path was invalid, the file wasn't found, or access denied, so move on
                    continue

        return True
