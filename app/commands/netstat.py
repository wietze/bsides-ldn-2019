from typing import List, Callable, Tuple

from plugins.adversary.app.commands.command import CommandLine

from . import parsers


def netstat(args: List[str]=None) -> CommandLine:
	command_line = ['netstat']
	if args:
		command_line += args

	return CommandLine(command_line)


def ano() -> Tuple[CommandLine, Callable[[str], None]]:
	args = ['-ano']
	return netstat(args=args), parsers.netstat.ano


def anob() -> Tuple[CommandLine, Callable[[str], None]]:
	args = ['-anob']
	return netstat(args=args), parsers.netstat.anob
