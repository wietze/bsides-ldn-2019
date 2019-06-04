from typing import Union, List
import random
import base64
import re

class CommandLine(object):
    """This represents a command line that can be executed.

    The actual string representing the command is stored in the variable ``command_line``.
    """
    def __init__(self, command_line: Union[str, List[str]]=None):
        """Creates a CommandLine.

        Args:
            command_line: The commandline. Can be a string, in which case the string is used directly as the command, or
                a list of strings, in which case the list is join together with the space character to create the
                final command.
        """

        if command_line and isinstance(command_line, list):
            command_line = ' '.join(command_line)
        self.command_line = command_line

class CustomCommandLine(object):
    def __init__(self, command_line: List[str]=None):
        if not command_line or len(command_line) <= 0:
            raise Exception('No command line given')
        self.command_line = command_line

    async def generate(self, drop_file, register_file):
        command_line = self.command_line
        r = False
        # PowerShell-specific changes
        if self.command_line[0].startswith('powershell'):
            method = random.randrange(4)
            if method == 0:
                # Move command line to file
                r = True
                command_line = await CustomCommandLine.ps_local_file(command_line, drop_file, register_file)
            elif method == 1:
                # Format string obfuscation
                r = True
                command_line = CustomCommandLine.ps_format_string(command_line)
            elif method == 2:
                # Base64 encode
                r = True
                command_line = CustomCommandLine.ps_base64_encode(command_line)
            elif method == 3:
                # Do nothing
                pass
        # CMD-specific changes
        if self.command_line[0].startswith('cmd'):
            # CMD Obfuscate
            r = True
            command_line = CustomCommandLine.cmd_env_obfuscate(command_line)

        # Generic changes
        if not r and command_line[0].split('\\')[-1].replace('.exe', '') in ['powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'rundll32', 'certutil']:
            # Masquerade
            command_line = await CustomCommandLine.masquerade_common_process(command_line, register_file)

        self.command_line = ' '.join(command_line)

    @staticmethod
    async def ps_local_file(powershell_command, drop_file, register_file):
        # Prepare filename for file to write command to
        filename = "C:\\Windows\\Temp\\{}.ps1".format(CustomCommandLine.random_name())
        # Write command to file
        i, cmd = CustomCommandLine.ps_find_command(powershell_command)
        if i >= 0:
            await drop_file(filename, CustomCommandLine.strip_quotes(CustomCommandLine.unescape(cmd, "cmd").strip()) + ";")
            await register_file(filename)
            # Generate new command, using
            return ["powershell", "-File", filename]
        else:
            return powershell_command

    @staticmethod
    def ps_format_string(powershell_command: List[str]) -> List[str]:
        i, cmd = CustomCommandLine.ps_find_command(powershell_command)
        if i >= 0:
            # Break command in random partitions
            parts = CustomCommandLine.partition(cmd)
            # Generate a list containing 0..len(parts)
            order = list(range(len(parts)))
            # Shuffle order of this list
            random.shuffle(order)
            # Generate IEX command that concatenates string in the randomised order using `-f`
            new_command = CustomCommandLine.escape("iex (\"" + "".join(["{{{}}}".format(order.index(x)) for x in range(len(parts))]) + "\" -f " +(",".join(["\"{}\"".format(parts[x]) for x in order])) + ")", "cmd")
            # Replace old command with new command
            powershell_command[i] = '"{}"'.format(new_command)
        return powershell_command

    @staticmethod
    def ps_base64_encode(powershell_command: List[str]) -> List[str]:
        i, cmd = CustomCommandLine.ps_find_command(powershell_command)
        if i > 0:
            # Basse64 encode (in unicode) the command
            powershell_command[i] = base64.b64encode(CustomCommandLine.unescape(cmd, "cmd").encode('utf-16le')).decode()
            # Replace the `command` switch with the `encodedcommand` switch
            powershell_command[i - 1] = CustomCommandLine.randomise_case(random.choice(['-ec', '-encodedCommand']))
        return powershell_command

    @staticmethod
    def cmd_env_obfuscate(cmd_command: List[str]) -> List[str]:
        i, cmd = CustomCommandLine.cmd_find_command(cmd_command)
        if i >= 0:
            # Break command in random partitions
            parts = CustomCommandLine.partition(CustomCommandLine.strip_quotes(cmd))
            # Put list back together with garbage delimiter
            delimiter, variable = random.choice('@?¬'), random.choice('abcdefghijklmnopqrstuvwxyz')
            env_command = delimiter.join(parts)
            # Generate IEX command that concatenates string in the randomised order using `-f`
            new_command = "set {var}={cmd} & echo %{var}:{delimiter}=%|cmd".format(var=variable, cmd=CustomCommandLine.escape(env_command,"cmd"), delimiter=delimiter)
            # Replace old command with new command
            cmd_command[i] = '"{}"'.format(new_command)
        return cmd_command

    @staticmethod
    async def masquerade_common_process(command, register_file):
        # Prepare filename for file to write command to
        filename = "C:\\Windows\\Temp\\{}.exe".format(CustomCommandLine.random_name())
        # Write command to file
        if ':' in command[0]:
            copy_command = "COPY /Y \"{old}\" \"{new}\"".format(old=command[0], new=filename)
        else:
            # Windows equivalent of bash's `which`
            copy_command = "(FOR /f %i IN ('WHERE {old}') DO COPY /Y %i \"{new}\")".format(old=command[0], new=filename)
        new_command = ["cmd", "/c",  '"'+CustomCommandLine.escape("{} & {} {}".format(copy_command, filename, CustomCommandLine.join(command[1:], " ")), "cmd") + '"']
        # Register created file
        await register_file(filename)
        return new_command

    # HELPERS
    @staticmethod
    def ps_find_command(powershell_command: List[str]) -> (int, str):
        found = False
        for i, cmd in enumerate(powershell_command):
            if found:
                return i, cmd
            elif cmd.lower() in ['-c', '-command', '/c', '/command']:
                found=True
        return -1, None

    @staticmethod
    def cmd_find_command(cmd_command: List[str]) -> (int, str):
        found = False
        for i, cmd in enumerate(cmd_command):
            if found:
                return i, cmd
            elif cmd.lower() in ['/c', '/k']:
                found=True
        return -1, None

    @staticmethod
    def randomise_case(input: str) -> str:
        return ''.join([x.lower() if random.getrandbits(1) else x.upper() for x in input])

    @staticmethod
    def random_name() -> str:
        vendors = ['Microsoft', 'Windows', 'Dell', 'HP', 'Lenovo', 'Asus', 'Samsung', 'Acer', 'Toshiba', 'Panasonic', 'Intel', 'AMD', 'Adobe', 'Apple', 'VMware', 'Citrix', 'McAfee', 'Symantec']
        separators = ['', '.', '_', '']
        processes = ['Update', 'Updater', 'Sync', 'Agent', 'Support', 'Background', 'Daemon', 'Host', 'Run', 'Runner', 'Transfer', 'Link', 'Client', 'Service', 'Svc', 'Engine', 'Eng', '32', 'Refresh']
        return '{}{}{}'.format(random.choice(vendors), random.choice(separators), random.choice(processes))

    @staticmethod
    def partition(input_str: str) -> List[str]:
        number_of_partions = random.randint(3, int(len(input_str)/2))
        result = []
        for i in range(0, len(input_str), number_of_partions):
            result.append(input_str[i:i + number_of_partions])
        return result

    @staticmethod
    def escape(input: str, style: str) -> str:
        if style == 'cmd':
            return input.replace('"', '"""').replace(">", "^>").replace("<", "^<")
        elif style == 'powershell': #TODO
            return input
    @staticmethod
    def unescape(input: str, style: str) -> str:
        if style == 'cmd':
            return input.replace("^<","<").replace("^>",">").replace('"""', '"')
        elif style == 'powershell': #TODO
            return input

    @staticmethod
    def strip_quotes(input: str) -> str:
        return re.sub(r'^[\'"](.*?)[\'"]$', r'\1', input)

    @staticmethod
    def join(input:List[str], joiner: str) -> str:
        return joiner.join(['"{}"'.format(x) if ' ' in x else x for x in input])
