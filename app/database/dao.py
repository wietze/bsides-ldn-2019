from plugins.adversary.app.database.mongo import Mongo


class Dao:
    """
    This class is an interface with all CRUD operations required for CALDERA.
    All database interactions from this application should go through here.
    All responses from here must be in JSON
    """
    def __init__(self, host=None, port=None, key=None):
        self.host = host
        self.port = port
        self.key = key
        self.db = Mongo(host=host, port=port, key=key)

    def __enter__(self):
        self.db.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.db.connection.close()

    def get_techniques(self, ids=[]):
        return self.db.get_techniques(ids)

    def get_tactics(self, ids=[]):
        return self.db.get_tactics(ids)

    def get_attack_groups(self, ids=[]):
        return self.db.get_attack_groups(ids)

    def get_hosts(self, ids=[]):
        return self.db.get_hosts(ids)

    def get_networks(self, ids=[]):
        return self.db.get_networks(ids)

    def get_domains(self, ids=[]):
        return self.db.get_domains(ids)

    def get_adversaries(self, ids=[]):
        return self.db.get_adversaries(ids)

    def get_steps(self, ids=[]):
        return self.db.get_steps(ids)

    def get_artifact_lists(self, ids=[]):
        return self.db.get_artifacts(ids)

    def get_operations(self, ids=[]):
        return self.db.get_operations(ids)

    def get_settings(self, ids=[]):
        return self.db.get_settings(ids)

    def get_rats(self, ids=[]):
        return self.db.get_rats(ids)

    def get_agents(self, ids=[]):
        return self.db.get_agents(ids)

    def get_jobs(self, ids=[]):
        return self.db.get_jobs(ids)

    def get_raw_jobs(self, ids=[]):
        return self.db.get_raw_jobs(ids)

    def get_logs(self, ids=[]):
        return self.db.get_logs(ids)

    def get_observed_credentials(self, ids=[]):
        return self.db.get_observed_credentials(ids)

    def find(self, index, key, value, mapper=None):
        return self.db.find(index, key, value, mapper)
    
    def distinct(self, index, key, value, distinct_key):
        return self.db.distinct(index, key, value, distinct_key)

    def create(self, index, data):
        return self.db.create(index, data)

    def delete(self, index, id):
        return self.db.delete(index, id)

    def update(self, index, id, data, validate = False):
        return self.db.update(index, id, data, validate)

    def append(self, index, id, data):
        return self.db.append(index, id, data)

    def terminate(self):
        return self.db.terminate()

