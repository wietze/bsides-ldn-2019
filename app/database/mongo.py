import json

from plugins.adversary.app.database.model import Model
from plugins.adversary.app.utility.general import decrypt, encrypt, string_to_bool_for_entry
from bson import ObjectId
from pymongo import MongoClient


class Mongo(Model):
    """
    This class is a DAO implementation for Mongo
    """
    def __init__(self, host, port, key):
        self.host = host
        self.port = port
        self.key = key
        self.connection = None
        self.cols = None

    def connect(self):
        self.connection = MongoClient(self.host, self.port)
        self.cols = dict(
            custom_logs=self.connection.virts.custom_logs,
            log=self.connection.virts.log,
            network=self.connection.virts.network,
            operation=self.connection.virts.operation,
            adversary=self.connection.virts.adversary,
            step=self.connection.virts.coded_step,
            artifacts=self.connection.virts.artifactlist,
            technique=self.connection.virts.attack_technique,
            tactics=self.connection.virts.attack_tactic,
            domain=self.connection.virts.domain,
            host=self.connection.virts.host,
            agent=self.connection.virts.agent,
            rat=self.connection.virts.rat,
            setting=self.connection.virts.setting,
            job=self.connection.virts.job,
            attack_list=self.connection.virts.attack_list,
            attack_group=self.connection.virts.attack_group,
            observed_credential=self.connection.virts.observed_credential,
            observed_domain=self.connection.virts.observed_domain,
            observed_host=self.connection.virts.observed_host,
            trashed=self.connection.virts.trashed,
            observed_file=self.connection.virts.observed_file,
            observed_share= self.connection.virts.observed_share,
            observed_user=self.connection.virts.observed_user,
            observed_schtask=self.connection.virts.observed_schtask,
            observed_service=self.connection.virts.observed_service,
            observed_time_delta=self.connection.virts.observed_time_delta,
            observed_rat=self.connection.virts.observed_rat,
            observed_device=self.connection.virts.observed_device,
            observed_persistence=self.connection.virts.observed_persistence,
            observed_process=self.connection.virts.observed_process,
            observed_reg_key=self.connection.virts.observed_reg_key,
            observed_o_s_version=self.connection.virts.observed_o_s_version
        )

    def get_techniques(self, ids=[]):
        return [self._map_technique(x) for x in self._query('technique', ids)]

    def get_tactics(self, ids=[]):
        return [self._map_tactic(x) for x in self._query('tactics', ids)]

    def get_domains(self, ids=[]):
        return [self._map_domain(x) for x in self._query('domain', ids)]

    def get_hosts(self, ids=[]):
        return [self._map_host(x) for x in self._query('host', ids)]

    def get_artifacts(self, ids):
        return [self._map_artifact(x) for x in self._query('artifacts', ids)]

    def get_agents(self, ids=[]):
        return [self._map_agent(x) for x in self._query('agent', ids)]

    def get_rats(self, ids=[]):
        return [self._map_rat(x) for x in self._query('rat', ids)]

    def get_settings(self, ids=[]):
        return [self._map_setting(x) for x in self._query('setting', ids)][::-1]

    def get_steps(self, ids=[]):
        return [self._map_step(x) for x in self._query('step', ids)]

    def get_networks(self, ids=[]):
        return [self._map_network(x) for x in self._query('network', ids)]

    def get_adversaries(self, ids=[]):
        return [self._map_adversary(x) for x in self._query('adversary', ids)]

    def get_operations(self, ids=[]):
        return [self._map_operation(x) for x in self._query('operation', ids)]

    def get_jobs(self, ids=[]):
        results = []
        for job in self._query('job', ids):
            job['action'] = json.loads(decrypt(self.key, job['action']))
            results.append(self._map_job(job))
        return results

    def get_raw_jobs(self, ids=[]):
        return [self._map_raw_job(x) for x in self._query('job', ids)]

    def get_attack_groups(self, ids=[]):
        return [self._map_attack_group(x) for x in self._query('attack_group', ids)]

    def get_logs(self, ids=[]):
        results = []
        for log in self._query('log', ids):
            log['event_stream'] = [json.loads(decrypt(self.key, es)) for es in log.get('event_stream', [])]
            results.append(self._map_log(log))
        return results

    def get_observed_credentials(self, ids=[]):
        return [self._map_observed_credential(x) for x in self._query('observed_credential', ids)]

    def find(self, index, key, value, mapper=None):
        cursor = self.cols[index].find({key: value})
        results = []
        if mapper:
            mapper = getattr(Model, mapper)
            return [mapper(doc) for doc in cursor]
        else:
            for doc in cursor:
                doc['id'] = str(doc.get('_id'))
                doc.pop('_id')
                results.append(doc)
        return results

    def distinct(self, index, key, value, distinct_key):
        cursor = self.cols[index].distinct(distinct_key, {key: value})
        return [val for val in cursor]

    def create(self, index, data):
        self._validate(index, data)
        return self.cols[index].save(data, check_keys=False)

    def delete(self, index, id):
        self.cols[index].delete_one({'_id': ObjectId(id)})

    def update(self, index, id, data, validate=False):
        if validate:
            self._validate(index, data)
        self.cols[index].update_one({'_id': ObjectId(id)}, {'$set': data})

    def append(self, index, id, data):
        self.cols[index].update({'_id': ObjectId(id)}, {'$push': data})

    def terminate(self):
        self.connection.drop_database('virts')

    # PRIVATE

    def _query(self, type, ids):
        if len(ids) > 0:
            return self.cols[type].find({'_id': {'$in': [ObjectId(i) for i in ids]}})
        else:
            return self.cols[type].find()

    def _validate(self, index, data):
        """
        This is a temporary hack function to adjust the CREATE data from the GUI
        to store inside our Mongo data model.
        """
        if index == 'network':
            domain = self.find('domain', key='windows_domain', value=data['domain'])
            data['domain'] = ObjectId(domain[0]['id'])
            data['hosts'] = [ObjectId(h) for h in data['hosts']]
        elif index == 'adversary':
            data['artifactlists'] = [ObjectId(s) for s in data.get('artifact_list', [])]
            data.pop("artifact_list", None)
            data['steps'] = [ObjectId(s) for s in data['steps']]
            data['exfil_method'] = data.get('exfil_method', 'http')
            data['exfil_address'] = data.get('exfil_address','0.0.0.0')
            data['exfil_port'] = data.get('exfil_port', 8889)
        elif index == 'rat':
            data['host'] = ObjectId(data['host'])
            data['agent'] = ObjectId(data['agent'])
        elif index == 'job':
            data['action'] = encrypt(self.key, json.dumps(data['action']))
        elif index == 'operation':
            data['adversary'] = ObjectId(data['adversary'])
            data['network'] = ObjectId(data['network'])
            data['start_host'] = ObjectId(data['start_host'])
            data['status'] = 'start'
            if 'delay' not in data:
                data['delay'] = 0
            if 'jitter' not in data:
                data['jitter'] = 0
            data['status_state'] = ''
            data['cleanup_index'] = 0
            data['perform_cleanup'] = string_to_bool_for_entry(data['perform_cleanup'])

            adversary = self.get_adversaries(ids=[data['adversary']])
            data['steps'] = [x['name'] for x in self.get_steps(ids=[s for s in adversary[0]['steps']])]
            for e in ['rat_iv_map', 'known_credentials', 'known_devices', 'known_domains',
                      'known_files', 'known_hosts', 'known_rats', 'known_schtasks', 'known_shares',
                      'known_timedeltas', 'known_users', 'known_persistence', 'known_registry_keys',
                      'known_services', 'known_processes', 'known_trashed', 'known_os_versions',
                      'clean_log', 'jobs', 'performed_steps', 'nonexistent_rats',
                      'ignored_rats']:
                data[e] = []
            data['log'] = self.cols['log'].save(dict(version='1.0'))
        elif index == 'setting':
            data['footprint'] = string_to_bool_for_entry(data['footprint'])
            data['obfuscate'] = string_to_bool_for_entry(data['obfuscate'])
            data['external_tools'] = string_to_bool_for_entry(data['external_tools'])
            data['recursion_limit'] = int(data['recursion_limit'])
            data['planner_depth'] = int(data['planner_depth'])
        return data
