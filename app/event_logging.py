import uuid
import datetime
from typing import List, Union, Dict

from plugins.adversary.app.engine.database import EncryptedDictField
from plugins.adversary.app.engine.objects import Log
from plugins.adversary.app.util import tz_utcnow

version = 1.1


class Operation(dict):
    def __init__(self):
        super().__init__()
        self['id'] = str(uuid.uuid4())
        self['steps'] = []
        self['nodetype'] = 'operation'


class AttackReference(dict):
    def __init__(self, technique_id, technique_name, tactics):
        super().__init__()
        self['technique_id'] = technique_id
        self['technique_name'] = technique_name
        self["tactic"] = tactics


class Step(dict):
    def __init__(self, attack_info: List[AttackReference], dest_hosts: List[str] = None, description: str = None):
        super().__init__()
        self['id'] = str(uuid.uuid4())
        self['nodetype'] = 'step'
        self['attack_info'] = attack_info
        self['events'] = []
        self['key_technique'] = attack_info[0]['technique_id'] if len(attack_info) else None
        self['key_event'] = None
        self['host'] = None
        self['time'] = None
        if dest_hosts is not None:
            self['dest_hosts'] = dest_hosts
        if description is not None:
            self['description'] = description


class Event(dict):
    def __init__(self, obj, action, host, start_time=None, fields=None):
        if start_time is None:
            start_time = tz_utcnow().isoformat()
        if fields is None:
            fields = {}
        super().__init__()
        self['id'] = str(uuid.uuid4())
        self['nodetype'] = 'event'
        self['host'] = host
        self['object'] = obj
        self['action'] = action
        self['happened_after'] = start_time
        self.update(**fields)

    def end(self, successful):
        self['happened_before'] = tz_utcnow().isoformat()
        # self['successful'] = successful
        if not successful:
            return None

        return self


class ProcessEvent(Event):
    def __init__(self, host, ppid, pid, command_line, action='create'):
        args = {'fqdn': host,
                'ppid': ppid,
                'pid': pid,
                'command_line': command_line}
        super().__init__("process", action, host, fields=args)


class FileEvent(Event):
    def __init__(self, fqdn, file_path, action='create'):
        args = {'fqdn': fqdn,
                'file_path': file_path}
        super().__init__('file', action, fqdn, fields=args)


class CredentialDump(Event):
    def __init__(self, fqdn, pid, typ, usernames):
        args = {'fqdn': fqdn,
                'pid': pid,
                'type': typ,
                'usernames': usernames}
        super().__init__('cred', 'dump', fqdn, fields=args)


class RegistryEvent(Event):
    def __init__(self, fqdn, key, data, value, action="add"):
        args = {'fqdn': fqdn,
                'key': key,
                'value': value,
                'data': data}
        super().__init__('registry', action, fqdn, fields=args)


class ProcessOpen(Event):
    def __init__(self, fqdn, file_path, actor_pid):
        args = {'fqdn': fqdn,
                'file_path': file_path,
                'actor_pid': actor_pid}
        super().__init__('process', 'open', fqdn, fields=args)


class BSFEmitter(object):
    def __init__(self, log: Log):
        """
        An object that handles emitting BSF events
        Args:
            log: the log to emit log entries to
        """
        self.log = log
        self.is_done = False
        self.encrypt = EncryptedDictField.encrypt_dict

    def append_to_log_stream(self, bsf_node):
        enc = self.encrypt(bsf_node)
        self.log.modify(push__event_stream=enc)

    def start_operation(self):
        self.log.modify(active_operation=Operation())

    def _pick_step_key_event(self) -> Union[Dict, None]:
        """
        Select a key event from the active step's events and return that event's id.
        :return: The database ID of the key event
        """
        if not len(self.log.active_step['events']):
            return None

        events = list(filter(lambda e: e['id'] in self.log.active_step['events'], self.log.event_stream))
        new_files = list(filter(lambda e: e['object'] == 'file' and e['action'] == 'create', events))
        new_processes = list(filter(lambda e: e['object'] == 'process' and e['action'] == 'create', events))

        if new_processes:
            # Prefer the first process:create
            return new_processes[0]
        elif new_files:
            # If there are no process:create events, then prefer the first file:create
            return new_files[0]
        elif events:
            # just get the first event if there is one
            return events[0]

    @staticmethod
    def _avg_time(happened_before: str, happened_after: str):
        before = datetime.datetime.fromisoformat(happened_before)
        after = datetime.datetime.fromisoformat(happened_after)
        return (before + (after - before) / 2).isoformat()

    def _push_active_step(self):
        key_event = self._pick_step_key_event()
        if key_event:
            avg_key_time = self._avg_time(key_event['happened_before'], key_event['happened_after'])
            self.log.modify(active_step__key_event=key_event['id'],
                            active_step__host=key_event['host'],
                            active_step__time=avg_key_time)
        self.append_to_log_stream(self.log.active_step)

    def add_step(self, step: Step):
        if self.log.active_step and len(self.log.active_step['events']) > 0:
            self._push_active_step()

        self.log.modify(push__active_operation__steps=step['id'])
        self.log.modify(active_step=step)

    def add_event(self, event):
        if not isinstance(event, CredentialDump):
            self.log.modify(push__active_step__events=event['id'])
            self.append_to_log_stream(event)

    def done(self):
        if self.is_done:
            # This BSF Log has already been marked done.
            return

        if self.log.active_step:
            self._push_active_step()

        if self.log.active_operation:
            self.append_to_log_stream(self.log.active_operation)

        self.is_done = True
