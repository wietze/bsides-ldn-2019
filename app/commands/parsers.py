import re
import datetime
import logging
import csv
import io
from collections import defaultdict
from typing import List, Dict, NamedTuple

from plugins.adversary.app import util
from plugins.adversary.app.commands.errors import *

from functools import wraps

log = logging.getLogger(__name__)


def sim_wrapper(parse_function):
    @wraps(parse_function)
    def decorated_function(object):
        if type(object) is dict:
            if object['stdout'] == "simulation hosts have no responses":
                pass
        return parse_function(object)
    return decorated_function


class powerview(object):
    @staticmethod
    @sim_wrapper
    def getnetlocalgroupmember(text: str) -> List[Dict]:
        try:
            users = []
            skip = text.find("ComputerName")
            safe = text[skip:]
            for block in safe.split("\r\n\r\n"):
                lines = block.splitlines()
                parsed_block = {}
                for line in lines:
                    if ':' in line:
                        k, v = line.split(':')
                        parsed_block[k.strip()] = v.strip().lower()
                    else:
                        continue
                # block_dict = {x.strip(): y.strip() for x, y in line.split(':') for line in lines}
                if len(parsed_block) and '\\' in parsed_block.get('MemberName'):
                    domain, user = parsed_block['MemberName'].split('\\')
                    if user != '': # remove orphaned users
                        sid = parsed_block.get('SID')
                        is_domain = True if parsed_block.get('IsDomain') == "true" else False
                        is_group = True if parsed_block.get('IsGroup') == "true" else False

                        new_user_dict = {}
                        new_user_dict['username'] = user
                        new_user_dict['is_group'] = is_group
                        new_user_dict['sid'] = sid
                        if is_domain:
                            new_user_dict['windows_domain'] = domain
                        else:
                            new_user_dict['hostname'] = domain
                        users.append(new_user_dict)
            if not users:
                raise ParseError("Returned data contained no parseable users!")
            return users
        except Exception as e:
            raise ParseError("Unexpected Data format in return:{}\n  {}".format(e, text))

    GetDomainComputerResult = NamedTuple("GetDomainComputerResult", [("dns_hostname", str), ("os_version", Dict)])

    @staticmethod
    @sim_wrapper
    def getdomaincomputer(text: str) -> Dict[str, Dict[str, str]]:
        results = dict()

        for block in text.split("\r\n\r\n"):
            if block:
                dns_hostname = None
                parsed_version_info = None
                for line in block.splitlines():
                    if line.startswith("dnshostname"):
                        field_name, value = [c.strip() for c in line.split(':')]
                        dns_hostname = value.lower()

                    if line.startswith("operatingsystemversion"):
                        value = line.split(":")[-1].strip()  # Looks like: "10.0 (14393)"
                        os_version, build_number = value.split(' ')
                        build_number = build_number[1:-1]  # remove parens
                        major_version, minor_version = os_version.split('.')
                        parsed_version_info = dict(os_name="windows", major_version=major_version,
                                                   minor_version=minor_version, build_number=build_number)

                    if line.startswith("Exception") and '(0x80005000)' in line:
                        # Domain communication error
                        raise DomainIssueError('Domain Issue 0x80005000: Verify that the rat is running under a '
                                               'Domain Account, and that the Domain Controller can be reached.')

                results[dns_hostname] = dict(parsed_version_info=parsed_version_info)
        if not results:
            raise ParseError("Returned data contained no parseable information!")
        return results


class footprint(object):
    @staticmethod
    @sim_wrapper
    def recover_files(alpha) -> None:
        pass

    @staticmethod
    @sim_wrapper
    def password(alpha) -> None:
        pass


class powerup(object):
    @staticmethod
    @sim_wrapper
    def get_serviceunquoted(text: str) -> List[Dict]:
        # can take advantage of the bin path to insert new binary upstream (i.e C:\Program.exe)
        services = []
        for block in text.split("\r\n\r\n"):
            service = {}
            lines = block.split("\r\n")
            for i in range(0, len(lines)):
                parts = lines[i].split(":")
                keyword = parts[0].strip()
                if keyword == "ServiceName":
                    service["name"] = parts[1].strip()  # ServiceName : namehere
                elif keyword == "Path":
                    search_line = lines[i]
                    count = 1
                    while "}" not in search_line:  # paths might span multiple lines, fix it
                        search_line += lines[i + count]
                        count += 1
                    regex = re.compile("\\{(.*)\\}")  # ModifiablePath : {C:\Program Files\test.exe}
                    search_line = search_line.replace('                 ', '')
                    log.debug(search_line)
                    path = regex.search(search_line).group(1).strip()
                    service["bin_path"] = path
                elif keyword == "StartName":
                    service["service_start_name"] = parts[1].strip()  # StartName : LocalSystem
                elif keyword == "CanRestart":
                    if parts[1].strip() == "True":
                        service["can_restart"] = True  # CanRestart : True
                    else:
                        service["can_restart"] = False
                elif keyword == "ModifiablePath":
                    search_line = lines[i]
                    count = 1
                    while "}" not in search_line:  # paths might span multiple lines, fix it
                        search_line += lines[i + count]
                        count += 1
                    regex = re.compile("\\{(.*)\\}")  # ModifiablePath : {C:\Program.exe, C:\Program Files\test.exe}
                    search_line = search_line.replace('                 ', '')
                    log.debug(search_line)
                    paths = regex.search(search_line).group(1).split(',')
                    paths = [path.strip() for path in paths]
                    service["modifiable_paths"] = paths
            if len(service) > 0:
                services.append(service)
        return services

    @staticmethod
    @sim_wrapper
    def get_modifiableservicefile(text: str) -> List[Dict]:
        # can replace service binary with a new one
        services = []
        for block in text.split("\r\n\r\n"):
            service = {}
            lines = block.split("\r\n")
            for i in range(0, len(lines)):
                parts = lines[i].split(":")
                keyword = parts[0].strip()
                if keyword == "ServiceName":
                    service["name"] = parts[1].strip()  # ServiceName : namehere
                elif keyword == "Path":
                    search_line = lines[i]
                    count = 1
                    while "}" not in search_line:  # paths might span multiple lines, fix it
                        search_line += lines[i + count]
                        count += 1
                    regex = re.compile("\\{(.*)\\}")  # ModifiablePath : {C:\Program Files\test.exe}
                    search_line = search_line.replace('                 ', '')
                    log.debug(search_line)
                    path = regex.search(search_line).group(1).strip()
                    service["bin_path"] = path  # full binpath with arguments and everything
                elif keyword == "StartName":
                    service["service_start_name"] = parts[1].strip()  # StartName : LocalService
                elif keyword == "CanRestart":
                    if parts[1].strip() == "True":
                        service["can_restart"] = True  # CanRestart : True
                    else:
                        service["can_restart"] = False
                elif keyword == "ModifiableFile":  # ModifiableFile : {C:\program files\full\path\here.exe}
                    search_line = lines[i]
                    count = 1
                    while "}" not in search_line:  # paths might span multiple lines, fix it
                        search_line += lines[i + count]
                        count += 1
                    regex = re.compile("\\{(.*)\\}")  # ModifiablePath : {C:\Program Files\test.exe}
                    search_line = search_line.replace('                 ', '')
                    log.debug(search_line)
                    path = regex.search(search_line).group(1).strip()
                    service['modifiable_paths'] = [path.strip()]
            if len(service) > 0 and service["name"] != "cagent":
                services.append(service)
        return services

    @staticmethod
    @sim_wrapper
    def get_modifiableservice(text: str) -> List[Dict]:
        # can modify a service's binpath to something else (not b/c unquoted or replacing real binary)
        services = []
        for block in text.split("\r\n\r\n"):
            service = {}
            lines = block.split("\r\n")
            for i in range(0, len(lines)):
                parts = lines[i].split(":")
                keyword = parts[0].strip()
                if keyword == "ServiceName":
                    service["name"] = parts[1].strip()  # ServiceName : namehere
                elif keyword == "Path":
                    search_line = lines[i]
                    count = 1
                    while "}" not in search_line:  # paths might span multiple lines, fix it
                        search_line += lines[i + count]
                        count += 1
                    regex = re.compile("\\{(.*)\\}")  # ModifiablePath : {C:\Program Files\test.exe}
                    search_line = search_line.replace('                 ', '')
                    log.debug(search_line)
                    path = regex.search(search_line).group(1).strip()
                    service["bin_path"] = path  # Path : C:\Program Files\full\path\here.exe
                elif keyword == "StartName":
                    service["service_start_name"] = parts[1].strip()  # StartName : LocalSystem
                elif keyword == "CanRestart":
                    if parts[1].strip() == "True":
                        service["can_restart"] = True  # CanRestart : True
                    else:
                        service["can_restart"] = False
            if len(service) > 0:
                services.append(service)
        return services

    @staticmethod
    @sim_wrapper
    def find_pathdllhijack(text: str) -> List:
        log.debug(text)
        dlls = []
        for block in text.split("\r\n\r\n"):
            for line in block.split("\r\n"):
                parts = line.split(":")
                keyword = parts[0].strip()
                if keyword == "ModifiablePath":
                    dlls.append(':'.join(parts[1:]) + "wlbsctrl.dll")
        return dlls


class net(object):
    @staticmethod
    @sim_wrapper
    def time(text: str) -> datetime.datetime:
        if text and len(text) > 0:
            regex = re.compile(r'([0-9]+)/([0-9]+)/([0-9]+) ([0-9]+):([0-9]+):([0-9]+) (A|P)M')
            result = regex.search(text)
            if result is None:
                raise ParseError("Net time output does not look like a time: {}".format(text))
            else:
                try:
                    if result.group(7) == 'P' and result.group(4) != '12':
                        hour = int(result.group(4)) + 12
                    elif result.group(7) == 'A' and result.group(4) == '12':
                        hour = 0
                    else:
                        hour = int(result.group(4))

                    return datetime.datetime(*[int(x) for x in result.group(3, 1, 2)], hour,
                                             *[int(x) for x in result.group(5, 6)])
                except IndexError as e:
                    raise ParseError("Net time output does not look like a time: {}".format(text))

    @staticmethod
    @sim_wrapper
    def use(text: str) -> None:
        if text and text.startswith('The command completed successfully'):
            return
        elif text.startswith("System error 1331 has occurred"):
            raise AccountDisabledError
        else:
            raise ParseError("Net use failed: {}".format(text))

    @staticmethod
    @sim_wrapper
    def use_delete(text: str) -> None:
        if text:
            if text.strip().endswith('was deleted successfully.'):
                return
            elif text.strip().startswith('The network connection could not be found.'):
                raise NoShareError

        raise ParseError("Net use failed: {}".format(text))

    @staticmethod
    @sim_wrapper
    def user_add(text: str) -> None:
        if text:
            if text and text.startswith('The command completed successfully'):
                return
            elif text.strip().endswith('Access is denied.'):
                raise AccessDeniedError
            elif text.strip().startswith("The account already exists."):
                raise AccountAlreadyExistsError

        raise ParseError("Net user failed: {}".format(text))


class atomic(object):
    @staticmethod
    @sim_wrapper
    def plain_text(text: str) -> None:
        return text


class schtasks(object):
    @staticmethod
    @sim_wrapper
    def create(text: str) -> None:
        if text and text.startswith("SUCCESS"):
            return
        else:
            raise ParseError("unknown error with schtasks: {}".format(text))

    @staticmethod
    @sim_wrapper
    def delete(text: str) -> None:
        if text and text.startswith("SUCCESS"):
            return
        else:
            raise ParseError("unknown error with schtasks: {}".format(text))


class netstat(object):
    @staticmethod
    @sim_wrapper
    def ano(text: str) -> None:
        return

    @staticmethod
    @sim_wrapper
    def anob(text: str) -> None:
        return


class cmd(object):
    @staticmethod
    @sim_wrapper
    def copy(text: str) -> None:
        if text and len(text) > 0 and text.startswith('The system cannot find the file specified.'):
            raise ParseError("unable to perform copy.")
        elif text and len(text) > 0 and text.strip().startswith('1 file(s) copied.'):
            return
        elif text and len(
                text) > 0 and 'The process cannot access the file because it is being used by another process.' in text:
            raise FileInUseError
        else:
            raise ParseError("Unknown output of copy: {}".format(text))

    @staticmethod
    @sim_wrapper
    def delete(text: str) -> None:
        text = text.strip()
        if not text:
            return

        elif text.startswith('Could Not Find'):
            raise NoFileError
        elif text.endswith('Access is denied.'):
            raise AccessDeniedError
        elif text.startswith('The network path was not found.'):
            raise NoNetworkPathError
        elif text.startswith('The filename, directory name, or volume label syntax is incorrect.'):
            raise PathSyntaxError
        else:
            raise ParseError("Unknown output of delete: {}".format(text))

    @staticmethod
    @sim_wrapper
    def move(text: str) -> None:
        if "cannot find the file" in text:
            raise NoFileError
        elif "Access is denied" in text:
            raise AccessDeniedError
        elif "1 file(s) moved" in text:
            return
        else:
            raise ParseError("Unknown output of move: {}".format(text))

    @staticmethod
    @sim_wrapper
    def dir_collect(text: str) -> List[str]:
        matches = []
        if "File Not Found" in text:  # this also happens when access is denied, it's the same error
            raise FileNotFoundError
        elif "FAILED" in text:
            raise ParseError("Failed to handle a parse case: {}".format(text))
        for match in text.split("\r\n")[:-1]:
            matches.append(match.strip())
        return matches

    @staticmethod
    @sim_wrapper
    def powershell_file(text: str) -> None:
        if "it does not exist" in text:
            raise FileNotFoundError
        elif "Access to the path" in text and "is denied" in text:
            raise AccessDeniedError
        else:
            return

    @staticmethod
    @sim_wrapper
    def powershell_devices(text: str) -> List[Dict]:
        dev_selectors = ['ClassGuid', 'Name', 'Status', 'DeviceID']
        devices=[]
        if text is not None:
            for block in text.split("\r\n\r\n"):
                if block.strip() is not "":
                    device = {}
                    for line in block.split("\n"):
                        split = line.split(":")
                        if split[0].strip() in dev_selectors:
                            device[split[0].strip()] = split[1].strip()
                    devices.append(device)
            return devices
        else:
            return None

    @staticmethod
    @sim_wrapper
    def default(text: str) -> None:
        return text


class nbtstat(object):
    @staticmethod
    @sim_wrapper
    def n(text: str) -> str:
        if text and len(text) > 0:
            regex = re.compile(r'\s*(\S+)\s*<[0-9][0-9]>\s*GROUP')
            result = regex.search(text)
            if result is None:
                raise ParseError("Result is not well formed: {}".format(text))
            else:
                try:
                    return result.group(1).lower()
                except IndexError:
                    raise ParseError("Net time output does not look like a time: {}".format(text))


class winrm(object):
    @staticmethod
    @sim_wrapper
    def lateral_movement(text: str):
        error_code = "FullyQualifiedErrorId"
        if error_code in text:
            return False
        if "ProcessId" in text:
            # return pid of started rat
            return text.split("\r\n")[12].split(":")[1]
        return True



class wmic(object):
    @staticmethod
    @sim_wrapper
    def create(text: str) -> None:
        if text and len(text) > 0:
            lines = [x for x in text.splitlines() if x]
            if len(lines) > 1 and lines[0] == "Executing (Win32_Process)->Create()" and \
                    lines[1] == "Method execution successful.":
                return
        raise ParseError("Unknown output of wmic create: {}".format(text))


class taskkill(object):
    @staticmethod
    @sim_wrapper
    def taskkill(text: str) -> None:
        text = text.strip()
        if text.startswith("SUCCESS"):
            return
        elif text.startswith('ERROR: The process') and text.endswith("not found."):
            raise NoProcessError
        else:
            raise ParseError("Unknown output of taskkill: {}".format(text))


class shutdown(object):
    @staticmethod
    @sim_wrapper
    def shutdown(text: str) -> None:
        text = text.strip()
        if not text:
            return
        elif "Access Denied" in text:
            raise AccessDeniedError
        else:
            raise ParseError("Unknown output of shutdown")


class psexec(object):
    @staticmethod
    @sim_wrapper
    def copy(text: str):
        if "started on" in text:
            return True
        elif "being used by another process" in text:
            raise ParseError("PSEXEC in use error")
        else:
            raise ParseError("Unknown PSEXEC error")


class static(object):
    @staticmethod
    @sim_wrapper
    def cleanup(text: str):
        return True
    def accessFeat(text: str):
        if ("Successfully processed 1 files; Failed processing 0 files" in text):
            return True
        return False
    @staticmethod
    @sim_wrapper
    def bypassA(text: str):
        return True
    @staticmethod
    @sim_wrapper
    def bypassB(text: str):
        if "[!]" in text:
            return False
        return True
    @staticmethod
    @sim_wrapper
    def logonScript(text: str):
        if "The operation completed successfully." not in text:
            return False
        return True
    @staticmethod
    @sim_wrapper
    def shortcutmodify(text: str):
        return True


class sc(object):
    @staticmethod
    @sim_wrapper
    def create(text: str) -> None:
        if "SUCCESS" in text:
            return
        else:
            raise ParseError("Unknown output of sc create: {}".format(text))

    @staticmethod
    @sim_wrapper
    def delete(text: str) -> None:
        if "SUCCESS" in text:
            return
        elif "FAILED 5" in text:
            raise AccessDeniedError('Access denied to delete service {}'.format(text))
        elif "FAILED 1060" in text:
            raise NoServiceError('sc tried to delete a non-existent service {}'.format(text))
        else:
            raise ParseError('Unknown output of sc delete: {}'.format(text))

    @staticmethod
    @sim_wrapper
    def query(text: str) -> Dict:
        service = {}
        if "FAILED 1060" in text:
            raise NoServiceError("The service does not exist")
        for line in text.split("\r\n"):
            parts = line.split(":")
            if parts[0].strip() == "STATE":
                service['state'] = parts[1].split()[1]
        return service

    @staticmethod
    @sim_wrapper
    def start(text: str) -> None:
        if "FAILED 1053" in text:
            raise UnresponsiveServiceError('Service did not respond to start: {}'.format(text))
        elif "START_PENDING" in text:
            return
        elif "FAILED 1056" in text:
            raise ServiceAlreadyRunningError()
        else:
            raise ParseError('Unknown output of sc start: {}'.format(text))

    @staticmethod
    @sim_wrapper
    def stop(text: str) -> None:
        if "FAILED 5" in text:
            raise AccessDeniedError('Access denied to stop service')
        elif "SUCCESS" in text:
            return
        elif "FAILED 1062" in text:
            raise ServiceNotStartedError
        elif "STOP_PENDING" in text:
            return
        elif "FAILED 1061" in text:
            raise CantControlServiceError
        elif "FAILED 1060:" in text:
            raise NoServiceError
        else:
            raise ParseError('Unknown output of sc stop: {}'.format(text))

    @staticmethod
    @sim_wrapper
    def config(text: str) -> None:
        if "SUCCESS" in text:
            return
        elif "FAILED 1060" in text:
            raise NoServiceError('sc tried to config a non-existent service {}'.format(text))
        elif "FAILED 5" in text:
            raise AccessDeniedError('Access denied to config service')
        elif "USAGE:" in text:
            raise ParseError('Invalid config string: {}'.format(text))
        else:
            raise ParseError('Unknown output of sc config: {}'.format(text))


class timestomp(object):
    @staticmethod
    @sim_wrapper
    def timestomp(output: str) -> Dict:
        """
        Parses output of the timestomping command. Returns a dictionary containing
        the timestomped file's creation time, last access time, last write time,
        along with a boolean indicating whether timestomping actually occurred.
        Also now contains an entry indicating the file that the timestomp function
        took timestamps from.
        """
        info_dict = {}
        pruned_dict = {}
        important_keys = ["TimestampModified", "TimestompedWith", "CreationTime", "LastAccessTime", "LastWriteTime",
                          "OldCreationTime", "OldAccessTime", "OldWriteTime"]

        # Another form of searching - compare vs. parse_mimikatz_process for relative speed?

        lines = output.splitlines()
        for line in lines:
            m = re.match(r"(\w*)\s*:\s(.*)", line)
            if m is not None and m.groups()[0] is not None and m.groups()[1].strip() is not "":
                info_dict[m.groups()[0]] = m.groups()[1]

        for curr_key in important_keys:
            if curr_key in info_dict:
                pruned_dict[curr_key] = info_dict[curr_key]

        return pruned_dict


class MimikatzSection(object):
    def __init__(self):
        self.session = ""
        self.username = ""
        self.domain = ""
        self.logon_server = ""
        self.logon_time = ""
        self.sid = ""
        self.packages = defaultdict(list)


class mimikatz(object):
    @staticmethod
    @sim_wrapper
    def sekurlsa_pth(output: str) -> Dict:
        """
        Parses mimikatz output with the pth command and returns a dictionary containing
        the process PID and TID, as well as the process executed
        Args:
            output: stdout of "mimikatz.exe privilege::debug sekurlsa::pth [arguments] exit"
        Returns:
            A dictionary with keys: 'Username', 'Password', 'Domain', 'Hash'
        """
        masked_process = {}

        if 'ERROR kuhl_m_sekurlsa_acquireLSA' in output:
            raise AcquireLSAError

        if 'This script contains malicious content and has been blocked by your antivirus software.' in output:
            raise AVBlockError

        # A simple set of regex commands to get the program name, PID, and TID
        program = re.search(r"^\s*program\s*:\s*([^\r\n]*)", output, flags=re.MULTILINE)
        pid = re.search(r"^\s*\|\s*PID\s*(\d*)", output, flags=re.MULTILINE)
        tid = re.search(r"^\s*\|\s*TID\s*(\d*)", output, flags=re.MULTILINE)
        user = re.search(r"^\s*user\s*:\s*([^\r\n]*)", output, flags=re.MULTILINE)
        domain = re.search(r"^\s*domain\s*:\s*([^\r\n]*)", output, flags=re.MULTILINE)

        if program is not None and program.groups()[0] is not None:
            masked_process["program"] = program.groups()[0]
        else:
            raise ParseError('Could not find exploited process. This probably indicates a parser bug')

        if pid is not None and pid.groups()[0] is not None:
            masked_process["pid"] = pid.groups()[0]
        else:
            raise ParseError('Could not find process pid. This probably indicates a parser bug')

        if tid is not None and tid.groups()[0] is not None:
            masked_process["tid"] = tid.groups()[0]
        else:
            raise ParseError('Could not find thread tid. This probably indicates a parser bug')

        if user is not None and user.groups()[0] is not None:
            masked_process["user"] = user.groups()[0]
        else:
            raise ParseError('Could not find user. This probably indicates a parser bug')

        if domain is not None and domain.groups()[0] is not None:
            masked_process["domain"] = domain.groups()[0]
        else:
            raise ParseError('Could not find domain. This probably indicates a parser bug')

        return masked_process

    @staticmethod
    @sim_wrapper
    def sekurlsa_logonpasswords(output: str) -> List[Dict]:
        """
        Parses mimikatz output with the logonpasswords command and returns a list of dicts of the credentials.
        Args:
            output: stdout of "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit"
        Returns:
            A list of MimikatzSection objects
        """
        # split sections using "Authentication Id" as separator
        sections = output.split("Authentication Id")
        creds = []
        for section in sections[1:]:
            mk_section = MimikatzSection()
            package = {}
            package_name = ""
            in_header = True
            for line in section.splitlines():
                line = line.strip()
                if in_header:
                    if line.startswith('msv'):
                        in_header = False
                    else:
                        session = re.match(r"^\s*Session\s*:\s*([^\r\n]*)", line)
                        if session:
                            mk_section.session = session.group(1)
                        username = re.match(r"^\s*User Name\s*:\s*([^\r\n]*)", line)
                        if username:
                            mk_section.username = username.group(1)
                        domain = re.match(r"^\s*Domain\s*:\s*([^\r\n]*)", line)
                        if domain:
                            mk_section.domain = domain.group(1)
                        logon_server = re.match(r"^\s*Logon Server\s*:\s*([^\r\n]*)", line)
                        if logon_server:
                            mk_section.logon_server = logon_server.group(1)
                        logon_time = re.match(r"^\s*Logon Time\s*:\s*([^\r\n]*)", line)
                        if logon_time:
                            mk_section.logon_time = logon_time.group(1)
                        sid = re.match(r"^\s*SID\s*:\s*([^\r\n]*)", line)
                        if sid:
                            mk_section.sid = sid.group(1)
                        continue

                if line.startswith('['):
                    # this might indicate the start of a new account
                    if 'Username' in package and package['Username'] != '(null)' and \
                            (('Password' in package and package['Password'] != '(null)') or 'NTLM' in package):
                        mk_section.packages[package_name].append(package)

                    # reset the package
                    package = {}
                    pass
                elif line.startswith('*'):
                    m = re.match(r"\s*\* (.*?)\s*: (.*)", line)
                    if m:
                        package[m.group(1)] = m.group(2)

                elif line:
                    # parse out the new section name
                    match_group = re.match(r"([a-z]+) :", line)
                    if match_group:
                        # this is the start of a new ssp
                        # save the current ssp if necessary
                        if 'Username' in package and package['Username'] != '(null)' and \
                                (('Password' in package and package['Password'] != '(null)') or 'NTLM' in package):
                            mk_section.packages[package_name].append(package)

                        # reset the package
                        package = {}

                        # get the new name
                        package_name = match_group.group(1)

            # save the current ssp if necessary
            if 'Username' in package and package['Username'] != '(null)' and \
                    (('Password' in package and package['Password'] != '(null)') or 'NTLM' in package):
                mk_section.packages[package_name].append(package)

            # save this section
            if mk_section.packages:
                creds.append(mk_section)

        return creds

    @classmethod
    def sekurlsa_logonpasswords_condensed(cls, output: str) -> List[Dict]:
        """
        Parses mimikatz output with the logonpasswords command and returns a list of dicts of the credentials.
        Args:
            output: stdout of "mimikatz.exe privilege::debug sekurlsa::wdigest exit"
        Returns:
            A list of dictionaries where each dict is a credential, with keys: 'Username', 'Password', 'Domain',
            'NLTM', and 'SHA1'
        """
        accounts = cls.sekurlsa_logonpasswords(output)

        # remove all the weird SSPs
        for account in accounts:
            account.packages = {k: v for k, v in account.packages.items() if k in ('msv', 'tspkg', 'wdigest', 'credman',
                                                                                   'ssp')}

        for account in accounts:
            # order by logon time
            # 4/9/2018 3:58:39 PM
            try:
                logon_datetime = datetime.datetime.strptime(account.logon_time, '%m/%d/%Y %I:%M:%S %p')
            except ValueError:
                log.warning("sekurlsa_logonpasswords_condensed did not recognize the datetime string: {}".format(
                    account.logon_time))
                logon_datetime = datetime.datetime.min
            account.logon_time = logon_datetime

        accounts.sort(key=lambda x: x.logon_time)

        # invert
        flattened = defaultdict(dict)
        for account in accounts:
            for package_name, package in account.packages.items():
                for package_item in package:
                    # this should be a dict with at least the Username and Domain fields
                    if 'Username' in package_item and 'Domain' in package_item:
                        username = package_item['Username'] = package_item['Username'].lower()
                        domain = package_item['Domain'] = package_item['Domain'].lower()

                        # credman formats username and domain in an annoying way
                        if package_name == 'credman' and '\\' in username:
                            domain, username = username.split('\\')
                            package_item['Username'] = username
                            package_item['Domain'] = domain

                        flattened_account = flattened[(username, domain)]
                        for key, val in package_item.items():
                            if key in flattened_account and flattened_account[key] != val:
                                log.warning('There was a repeated {} field in the mimikatz dump for the {}\\{} '
                                            'account, keeping the most recent'.format(key, domain, username))
                            flattened_account[key] = val
                    else:
                        log.warning("Mimikatz package didn't contain both a 'Username' and 'Domain' field")

        flattened = list(flattened.values())

        # remove computer account
        flattened = [x for x in flattened if x and 'Username' in x and not x['Username'].endswith('$')]
        return util.unique_list_of_dicts(flattened)


class reg(object):
    WinRegValue = NamedTuple(typename="WinRegValue", fields=[("name", str), ("type", str), ("data", str)])

    @staticmethod
    @sim_wrapper
    def query(text: str) -> Dict[str, Dict[str, WinRegValue]]:
        if "The system was unable to find the specified registry key or value" in text:
            raise NoRegKeyError
        elif "ERROR" in text:
            raise ParseError("reg query command returned an ERROR: {}".format(text))

        res = {}
        current_key = None
        for line in text.split("\r\n"):
            if not line:
                continue  # skip empty string
            elif line.startswith("    ") and current_key and len(line.split()) == 3:  # Data -- ignore empty defaults
                v_name, v_type, v_data = line.split()
                res[current_key][v_name] = reg.WinRegValue(name=v_name, type=v_type, data=v_data)
            elif line.startswith("HK"):  # New key
                current_key = line
                res[current_key] = {}
        return res

    @staticmethod
    @sim_wrapper
    def add(text: str) -> None:
        if "The system was unable to find the specified registry key or value" in text:
            raise NoRegKeyError
        elif "ERROR: Invalid key name." in text:
            raise NoRegKeyError
        elif "ERROR: The parameter is incorrect." in text:
            raise IncorrectParameterError
        elif "ERROR" in text:
            raise ParseError

        return

    @staticmethod
    @sim_wrapper
    def load(text: str) -> None:
        if "ERROR: Access is denied." in text.strip():
            raise AccessDeniedError
        elif "ERROR: The process cannot access the file because it is being used by another process." in text.strip():
            raise FileInUseError
        elif "ERROR" in text:
            raise ParseError

        return

    @staticmethod
    @sim_wrapper
    def unload(text: str) -> None:
        if "ERROR" in text:
            raise ParseError

        return

    @staticmethod
    @sim_wrapper
    def delete(text: str) -> None:
        if "Invalid key name" in text or 'The system was unable to find the specified registry key or value' in text:
            raise NoRegKeyError
        elif "ERROR" in text:
            raise ParseError

        return


class systeminfo(object):
    @staticmethod
    @sim_wrapper
    def csv_with_headers(text: str) -> Dict:
        """ Return a Dict with systeminfo fields: values. Also, add original stdout text to the dict before returning.
        Could also store this info in a custom object or NamedTuple, but this is fewer lines."""
        if text.startswith("ERROR"):
            raise ParseError("Error encountered running systeminfo: {}".format(text))
        try:
            keys, values = csv_to_list(text)
            res = {keys[i]: values[i] for i in range(len(keys))}
            res['_original_text'] = text

            # parse out version info and add as dict
            version_string = res['OS Version'].split(' ')[0]
            major_version, minor_version, build_number = [int(n) for n in version_string.split('.')]

            # The keys in the dict below are named for easy unpacking into ObservedOSVersion database objects
            res['parsed_version_info'] = dict(os_name="windows", major_version=major_version,
                                              minor_version=minor_version, build_number=build_number)
            return res
        except:
            raise ParseError("Error encountered while trying to parse systeminfo output: {}".format(text))


class tasklist(object):
    _fix_name = {"Image Name": "image_name",
                 "PID": "pid",
                 "Session Name": "session_name",
                 "Session#": "session_number",
                 "Mem Usage": "mem_usage",
                 "Status": "status",
                 "User Name": "username",
                 "CPU Time": "cpu_time",
                 "Window Title": "window_title",
                 "Services": "services",
                 "Modules": "modules"}

    @staticmethod
    @sim_wrapper
    def csv_with_headers(text: str) -> List:
        rows = csv_to_list(text)
        headers = rows.pop(0)

        # Fix headers so that they correspond to field names in objects.ObservedProcess
        for idx, field_name in enumerate(headers):
            headers[idx] = tasklist._fix_name[field_name]

        # Convert PID and Session# to be integers
        for row in rows:
            for index, field in enumerate(row):
                if field.isdigit():
                    row[index] = int(field)

        return [dict(zip(headers, row)) for row in rows]


def csv_to_list(text: str) -> List[List]:
    """
    Converts CSV formatted output from Windows utilities into a list.
    :param text: CSV formatted text output from a Windows utility (e.g. "/FO CSV" )
    :return: A List of lists like so [[r1c1, r1c2, r1c3, ...], [r2c1, r2c2, r2c3, ...] ...]
    """
    return list(csv.reader(io.StringIO(text), delimiter=',', quotechar='"'))
