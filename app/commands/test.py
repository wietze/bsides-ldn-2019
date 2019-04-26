from plugins.adversary.app.commands.command import CommandLine
from typing import Callable, Tuple
from plugins.adversary.app.commands import parsers


def regsvr32() -> Tuple[CommandLine, Callable[[str], None]]:

    command_line = ['regsvr32','/s /u /i:C://Example.sct scrobj.dll']

    return CommandLine(command_line), parsers.test.regsvr32
