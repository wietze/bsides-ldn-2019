import array
import asyncio
import base64
import logging
import os
import pathlib
from datetime import datetime, timezone

import chardet
import yaml
from aiohttp import web
from bson import ObjectId

import plugins.adversary.app.config as config
from plugins.adversary.app.attack import refresh_attack
from plugins.adversary.app.engine.objects import Agent, Job, Rat
from plugins.adversary.app.extern import load_psexec, obf_rat
from plugins.adversary.app import interface
from plugins.adversary.app import powershell


class ApiLogic:

    def __init__(self, dao, auth_service, op_service):
        self.dao = dao
        self.op_svc = op_service
        self.ssl_cert = auth_service.ssl_cert

    @staticmethod
    async def get_api_jobs(status, agent_id, wait):
        query = {}
        if status:
            query['status'] = status
        agent = Agent.objects.with_id(agent_id)
        if not agent:
            raise web.HTTPForbidden
        agen = Agent.objects.with_id(agent.id)
        agen.modify(**{'check_in': datetime.now(timezone.utc), 'alive': True})
        query.update({'agent': agent.id})
        jobs = list(Job.objects(**query))
        return jobs

    @staticmethod
    async def put_job_details(json, job):
        if type(job) is not Job:
            job = Job.objects(id=ObjectId(job['id']))[0]
        if 'result' in json['action']:
            # decode stdout from new rat
            try:
                temp = json['action']['result']
                if 'stdout' in temp:
                    core = base64.b64decode(temp['stdout'])
                    encoding = chardet.detect(core)['encoding']
                    if encoding is None:
                        logging.info('No encoding was found')
                        temp['stdout'] = ''
                    else:
                        temp['stdout'] = core.decode(encoding)
                job['action']['result'] = temp
            except TypeError:
                # Contains RAT pid number
                pass
        if 'error' in json['action']:
            job['action']['error'] = json['action']['error']
        if 'exception' in json['action']:
            job['action']['exception'] = json['action']['exception']
        job['status'] = json.get('status', job.status)

        if job['status'] == "failed" and 'error' in job['action'] and job['action']['error'] == "no client":
            # Force update the clients list
            interface.get_clients(job.agent.host)
            # find the rat
            try:
                iv_name = job['action']["rats"]["args"][0]
                iv = Rat.objects(agent=job.agent, name=iv_name)
                iv.modify(**{'active': False})
            except KeyError:
                logging.warning("Could not find rat to remove for failed job")
        j = job.save()
        if job.status in ('success', 'failure'):
            Job.wakeup_job(job.id)
        return j

    async def save_rat(self, agent_id, data):
        with self.dao as con:
            # get the current agent
            agent = con.get_agents(ids=[agent_id])[0]
            # get list of all rats for host
            all_rats = con.find('rat', key='host', value=ObjectId(agent['host']))
            # filter list for living rats
            live_rats = []
            for rat in all_rats:
                if rat['active']:
                    live_rats.append(rat)
            active_rats = {x['pid']: x for x in data}
            # Enum active rats and delete dead ones
            for rat in live_rats:
                if rat['name'] not in active_rats:
                    con.update('rat', rat['id'], dict(active=False))
                else:
                    a = active_rats.pop(rat['name'])
                    con.update('rat', rat['id'], dict(elevated=a['elevated'],
                                                      executable=a['executable_path']))
            # Any new rats need to be added
            for key in active_rats:
                con.create('rat', dict(agent=ObjectId(agent['id']),
                                       host=ObjectId(agent['host']),
                                       name=key,
                                       elevated=active_rats[key]['elevated'],
                                       executable=active_rats[key]['executable_path'],
                                       username=active_rats[key]['username'].lower(),
                                       mode=active_rats[key]['params']['rat_mode'],
                                       active=True))

    def _get_file_text(self, script_name):
        return self._get_file_decode(script_name, lambda x: x.decode('utf-8'))

    def _get_file_base64(self, script_name):
        return self._get_file_decode(script_name, lambda x: base64.b64encode(x).decode('utf-8'))

    @staticmethod
    def _get_file_decode(script_name, decode_f):
        file_path = pathlib.Path(config.settings.filestore_path) / script_name
        with file_path.open('rb') as f:
            contents = f.read()
        # decrypt with key
        key = [0x32, 0x45, 0x32, 0xca]
        arr = array.array('B', contents)
        for i, val in enumerate(arr):
            cur_key = key[i % len(key)]
            arr[i] = val ^ cur_key
        return decode_f(arr.tobytes())

    def update_caldera_settings(self, data=None, current_settings=None):
        data['last_attack_update'] = current_settings['last_attack_update']

        if data['recursion_limit'] == '':
            data['recursion_limit'] = current_settings['recursion_limit']

        if data['planner_depth'] == '':
            data['planner_depth'] = current_settings['planner_depth']

        try:
            if data['external_tools'] == 'True' and current_settings['external_tools'] != 'True':
                data['external_tools'] = self.install_psexec_tools()
        except Exception as e:
            logging.error("Settings update [external_tools] encountered an error: {}".format(e))

        try:
            if data['obfuscate'] == 'True' and current_settings['obfuscate'] != 'True':
                obf_rat()
        except Exception as e:
            logging.error("Settings update [obfuscate] encountered an error".format(e))
        return data

    @staticmethod
    def update_attack_definitions():
        try:
            refresh_attack()
        except Exception as e:
            logging.error("Settings update [attack_update] encountered an error: {}".format(e))
            return 'failed'
        return 'updated'

    @staticmethod
    def install_psexec_tools():
        try:
            load_psexec()
        except:
            import traceback
            traceback.print_exc()

            return 'False'
        return 'True'

    def _validate_unique_name(self, data_type, name):
        with self.dao as con:
            existing = con.find(data_type, key='name', value=name)
            return not existing

    def save_network(self, data):
        with self.dao as con:
            if not self._validate_unique_name('network', data['name']):
                return dict(id='', msg='a network with the specified name already exists')

            num_hosts = len(data['hosts'])
            if num_hosts == 0:
                return dict(id='', msg='a network must contain at least one host')
            elif num_hosts > 1:
                obj_ids = list(map(lambda host_id: ObjectId(host_id), data['hosts']));
                host_domains = con.distinct('host', '_id', {'$in': obj_ids}, 'domain')
                if len(host_domains) > 1:
                    return dict(id='', msg='a network can only contain hosts from the same domain')
            new_id = con.create('network', data)
            return dict(id=str(new_id), msg='successfully created network')

    def _get_builtin_adversaries(self):
        with self.dao as con:
            builtin_advs = con.find('adversary', 'protected', True)
            builtin_advs = [builtin_adv['id'] for builtin_adv in builtin_advs]
            return builtin_advs

    def save_adversary(self, data):
        with self.dao as con:
            if not self._validate_unique_name('adversary', data['name']):
                return dict(id='', msg='an adversary with the specified name already exists')

            num_steps = len(data['steps'])
            if num_steps == 0:
                return dict(id='', msg='an adversary must contain at least one step')

            if data.get('exfil_port', None):
                try:
                    port = int(data['exfil_port'])
                except ValueError:
                    return dict(id='', msg='the adversary exfil_port must be a valid port number')

                if port not in range(1, 65536):
                    return dict(id='', msg='the adversary exfil_port must be a valid port number between 1-65535')

            # Implement Defaults for missing values
            if data.get('exfil_port') == "":
                data['exfil_port'] = 8889
            if data.get('exfil_method') == "":
                data['exfil_method'] = "rawtcp"
            if data.get('exfil_address') == "":
                data['exfil_address'] = "x.x.x.x"

            new_id = con.create('adversary', data)
            return dict(id=str(new_id), msg='successfully created adversary')

    def delete_adversary(self, data):
        adversary_id = data.get('id')
        builtin_advs = self._get_builtin_adversaries()
        if adversary_id in builtin_advs:
            return 'built-in adversaries are read-only'

        with self.dao as con:
            con.delete('adversary', adversary_id)
            return 'deleted successfully'

    @staticmethod
    def _transform_to_db_table(name):
        mapping = dict(known_trashed='trashed',
                       jobs='job',
                       known_timedeltas='observed_time_delta',
                       known_os_versions='observed_o_s_version',
                       known_processes='observed_process',
                       known_persistence='observed_persistence')
        if name in mapping.keys():
            return mapping[name]
        return 'observed_%s' % name.split('_')[1][:-1]

    def delete_operation(self, data):
        op_id = data.get('id')
        with self.dao as con:
            op = con.get_operations([op_id])[0]
            # Cleanup operation requires checking for instances of the objects in related documents
            for key in op.keys():
                if 'known_' in key or key == 'jobs':
                    for item in op[key]:
                        con.delete(self._transform_to_db_table(key), item)
            con.delete('operation', op_id)
        return 'deleted %s successfully' % op['name']

    @staticmethod
    def build_errors():
        errors = []
        rat = pathlib.Path(config.settings.exe_rat_path)
        if not rat.exists():
            errors.append('You need to add the Crater RAT for Adversary mode to be functional. '
                          'The simulation domain can be used in the meantime.')
        return errors

    def get_commander_rel_path_file(self):
        if self.dao.get_settings()[0]['obfuscate'] == 'True':
            return os.path.join(config.settings.filestore_path, "crater.exe")
        else:
            return config.settings.exe_rat_path

    def build_download_powershell(self, build_macro: str):
        if 'reflectivepe' in build_macro:
            macro_filename, filename = str.split(build_macro, '.')
            return self._build_download_reflectivepe(macro_filename=macro_filename,
                                                     filename=filename)
        else:
            build_options = dict(powerkatz=self._build_download_powerkatz(filename='invoke-mimi-ps1'),
                                 powerview=self._build_download_powerview(filename='powerview-ps1'),
                                 powerup=self._build_download_powerview(filename='powerup-ps1'),
                                 footprint=self._build_download_powerview(filename='footprint-ps1'),
                                 timestomper=self._build_download_powerview(filename='timestomper-ps1'))
            return build_options[build_macro]

    def _build_download_powerview(self, filename=None):
        powerview = self._get_file_text(filename)
        return self._compress_response(powerview)

    def _build_download_powerkatz(self, filename=None):
        powerkatz_base = self._get_file_text(filename)
        powerkatz = powerkatz_base.replace("[[MIMIKATZ_64_PLACEHOLDER]]", self._get_file_base64("mimi64-dll"))
        powerkatz = powerkatz.replace("[[MIMIKATZ_32_PLACEHOLDER]]", self._get_file_base64("mimi32-dll"))
        return self._compress_response(powerkatz)

    def _build_download_reflectivepe(self, filename=None):
        powersploit = self._get_file_text('invoke-reflectivepe-ps1')
        encoded_ps = self._get_file_base64(filename)
        template = '{script}{endl}$EncodedPE = "{b64pe}"'
        built = template.format(script=powersploit, endl=powershell.remote_endl, b64pe=encoded_ps)
        return self._compress_response(built)

    @staticmethod
    def _compress_response(response):
        compressed = powershell.ps_compressed(response, var_name='expr')
        stdin = ''.join(compressed) + powershell.remote_endl
        return stdin

    async def render_config(self, url_root):
        return yaml.safe_dump({
            'url_root': url_root,
            'verify_hostname': False,
            'cert': self.ssl_cert,
            'logging_level': 'debug'
        }, default_flow_style=False)
