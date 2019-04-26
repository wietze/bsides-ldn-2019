from plugins.adversary.app.commands.powershell import PSArg, PSFunction
from plugins.adversary.app.operation.operation import Step, OPFile, OPHost, OPRat, OPVar
from plugins.adversary.app.commands import parsers


class Timestomp(Step):
    """
    Description:
        This step adjusts the logged timestamps for a target file to match those of a similar file. The cleanup
        process restores the original timestamps for the file.
    Requirements:
        Requires administrative access on the target machine.
    """
    attack_mapping = [('T1099', 'Defense Evasion'), ('T1106', 'Execution')]
    display_name = "timestomp"
    summary = "Reduce suspicion of a copied file by altering its timestamp to look legitimate"

    preconditions = [("rat", OPRat({"elevated": True})),
                     ("host", OPHost(OPVar("rat.host"))),
                     ('file', OPFile({'host': OPVar('host')}))]

    postconditions = [("file_g", OPFile)]

    postproperties = ["file_g.new_creation_time", "file_g.new_last_access",
                      "file_g.new_last_write", "file_g.old_creation_time",
                      "file_g.old_last_access", "file_g.last_write",
                      "file_g.timestomped"]

    # Prevents the rat's timestamps from being altered (attempting to timestamp the rat produces an error)
    # Comment this next line out for testing
    not_equal = [('file.path', 'rat.executable')]

    @staticmethod
    def description(file, host):
        return "Modifying the timestamp of {} on {}".format(file.path, host.fqdn)

    @staticmethod
    async def simulate(operation, rat, host, file, file_g):
        return True

    @staticmethod
    async def action(operation, rat, host, file, file_g):
        results = await operation.execute_powershell(rat, "timestomper",
                                                     PSFunction('Perform-Timestomp', PSArg('FileLocation', file.path),
                                                                PSArg('Verbose')), parsers.timestomp.timestomp)

        # Don't parse if type 0 failure
        if results == {}:
            return False
        # Unpack parser...
        if results["TimestampModified"] == "True":
            timestamp_modified = True
        else:
            timestamp_modified = False

        await file_g({'path': file.path,
                      'host': file.host,
                      'use_case': file.use_case,
                      'new_creation_time': results["CreationTime"],
                      'new_last_access': results["LastAccessTime"],
                      'new_last_write': results["LastWriteTime"],
                      'old_creation_time': results["OldCreationTime"],
                      'old_last_access': results["OldAccessTime"],
                      'old_last_write': results["OldWriteTime"],
                      'timestomped': timestamp_modified
                      })

        return True

    # Resets the timestamp of the file
    @staticmethod
    async def cleanup(cleaner, host, file_g):
        for file in file_g:
            try:
                await cleaner.revert_timestamp(host, file)
            except AttributeError:
                continue
