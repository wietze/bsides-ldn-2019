from plugins.adversary.app.commands import parsers
from plugins.adversary.app.commands import cmd
from plugins.adversary.app.operation.operation import Step, OPDevice, OPHost, OPRat, OPVar


class GetPeripheralDevicesLocal(Step):
    """
    Description:
        This step enumerates peripheral devices on the host.  This grabs USB devices, Disk Drives,
        and image devices.
    Requirements:
        This step only requires the existence of a RAT on a host in order to run.
    """
    attack_mapping = [("T1005", "Collection"), ("T1120", "Discovery"), ('T1106', 'Execution')]
    display_name = "get_pnpdevices"
    summary = "Enumerate peripheral devices attached to the host device"

    preconditions = [('rat', OPRat),
                     ('host', OPHost(OPVar("rat.host")))]

    postconditions = [('device_g', OPDevice({'$in': OPVar('host.devices')}))]

    significant_parameters = ['host']  # no need to do this more than once per host

    postproperties = ['device_g.host','host.devices']

    @staticmethod
    def description(rat, host):
        return "Using powershell to enumerate PNP devices on {}".format(host.hostname)

    @staticmethod
    async def simulate(operation, rat, host, device_g):
        return True

    @staticmethod
    async def action(operation, rat, host, device_g):
        # Cmd will call a powershell instance to run Get-PnpDevices for a specific set of devices

        # Set up static parameters regarding device classes and query parameters
        dev_classes = {'Image': '{6bdd1fc6-810f-11d0-bec7-08002be2092f}',
                       'Camera': '{ca3e7ab9-b4c3-4ae6-8251-579ef933890f}',
                       'DiskDrive': '{4d36e967-e325-11ce-bfc1-08002be10318}',
                       'SmartCardReader': '{50dd5230-ba8a-11d1-bf5d-0000f805f530}',
                       'Sensors': '{5175d334-c371-4806-b3ba-71fd53c9258d}'}
        dev_selectors = ['ClassGuid', 'Name', 'Status', 'DeviceID']

        # build query strings
        dev_query = "\\\"Select * FROM Win32_PnPEntity Where ClassGUID like "
        dev_query += ' or ClassGUID like '.join("'%s'" % c for c in dev_classes.values())
        dev_query += '\\\"'
        dev_select = ','.join(dev_selectors)
        get_dev_cmd = "gwmi -Query {}".format(dev_query)

        # get devices
        device_objects = await operation.execute_shell_command(rat, *cmd.powershell(get_dev_cmd,\
                                                parsers.cmd.powershell_devices))

        # create device obects
        for dev in device_objects:

            dev.update({'host': host})
            await device_g(dev)

        return True