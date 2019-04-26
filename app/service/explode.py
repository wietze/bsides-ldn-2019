
class Explode:
    """
    This is a helper class to explode JSON object(s) from the database.
    Exploding means filling in references to embedded objects as stored in the DB
    """
    def __init__(self, con):
        self.con = con

    def operation(self, id=None):
        ids = [id] if id else []
        operations = self.con.get_operations(ids)
        for op in operations:
            op['adversary'] = self.con.get_adversaries(ids=[op['adversary']])[0]
            op['network'] = self.con.get_networks(ids=[op['network']])[0]
            op['network']['hosts'] = self.con.get_hosts(ids=op['network']['hosts'])
            op['start_host'] = next(it for it in op['network']['hosts'] if it['id'] == op['start_host'])
            for ps in op['performed_steps']:
                ps['jobs'] = self.con.get_jobs(ids=ps.get('jobs'))
                for ps_job in ps['jobs']:
                    ps_job['agent'] = self.con.get_agents(ids=[ps_job.get('agent')])[0]
                    ps_job['agent']['host'] = self.con.get_hosts(ids=[ps_job['agent']['host']])[0]
            if op['known_credentials']:
                op['known_credentials'] = self.con.get_observed_credentials(ids=op['known_credentials'])
        return operations

    def network(self, id=None):
        ids = [id] if id else []
        networks = self.con.get_networks(ids)
        for n in networks:
            n['domain'] = self.con.get_domains(ids=[n['domain']])[0]
            n['hosts'] = self.con.get_hosts(ids=n['hosts'])
        return networks

    def agent(self, id=None):
        ids = [id] if id else []
        agents = self.con.get_agents(ids)
        for a in agents:
            a['host'] = self.host(id=a['host'])[0]
        return agents

    def host(self, id=None):
        ids = [id] if id else []
        hosts = self.con.get_hosts(ids)
        for h in hosts:
            h['domain'] = self.con.get_domains(ids=[h['domain']])[0]
        return hosts

    def rat(self, id=None):
        ids = [id] if id else []
        rats = self.con.get_rats(ids)
        for r in rats:
            r['host'] = self.con.get_hosts(ids=[r['host']])[0]
        return rats

    def adversary(self, id=None):
        ids = [id] if id else []
        adversaries = self.con.get_adversaries(ids=ids)
        for adv in adversaries:
            if adv['steps']:
                adv['steps'] = self.step(id=adv['steps'])
        return adversaries

    def technique(self, id=None):
        ids = [id] if id else []
        techniques = self.con.get_techniques(ids=ids)
        tactics = self.con.get_tactics()
        for tech in techniques:
            tech['tactics'] = [self._find(tactics, t) for t in tech['tactics']]
        return techniques

    def step(self, id=None):
        ids = id if id else []
        steps = self.con.get_steps(ids=ids)
        techniques = self.con.get_techniques()
        tactics = self.con.get_tactics()
        for step in steps:
            for m in step['mapping']:
                m['technique'] = self._find(techniques, m['technique'])
                m['tactic'] = self._find(tactics, m['tactic'])
        return steps

    @staticmethod
    def _find(objects, id):
        element = list(filter(lambda c: c['id'] == id, objects))
        return element[0]
