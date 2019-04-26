from plugins.adversary.app.commands.command import CommandLine
from typing import Callable, Tuple
from plugins.adversary.app.commands import parsers


def files() -> Tuple[CommandLine, Callable[[str], None]]:
    command = 'powershell -command "&{$filetype = @(\\"*.docx\\",\\"*.pdf\\",\\"*.xlsx\\"); $startdir = ' \
              '\\"c:\\\\Users\\\\\\"; for($k=0;$k -lt $filetype.length; $k++){ $core = dir $startdir\($filetype[$k]) ' \
              '-Recurse | Select @{Name=\\"Path\\";Expression={$_.Fullname -as [string]}}; foreach ($alpha in $core) ' \
              '{$filename = $alpha.Path -as [string]; [Byte[]] $corrupt_file =  [System.IO.File]::ReadAllBytes(' \
              '$filename); [Byte[]] $key_file = [System.IO.File]::ReadAllBytes($(' \
              '-join($filename, \\".old\\"))); for($i=0; $i -lt $key_file.Length; $i++) { $corrupt_file[$i] = ' \
              '$key_file[$i];} [System.IO.File]::WriteAllBytes($(resolve-path $filename), $corrupt_file); ' \
              'Remove-Item $(-join($filename,\\".old\\"))}}}"'
    return CommandLine('cmd /c {}'.format(command)), parsers.footprint.recover_files


def password(user: str, password: str) -> Tuple[CommandLine, Callable[[str], None]]:
    command = 'net user ' + user + ' ' + password
    return CommandLine('cmd /c {}'.format(command)), parsers.footprint.password
