from plugins.adversary.app.utility.general import nested_get


class Model:
    """
    This class maps a Mongo database object to its JSON representation.
    """

    @staticmethod
    def _map_technique(t):
        return dict(id=str(t['_id']), name=t['name'], description=t['description'], identifier='technique_id',
                    url=t['url'], tactics=[str(tactic) for tactic in t['tactics']], technique_id=t['technique_id'])

    @staticmethod
    def _map_attack_group(g):
        if g.get('aliases') is None:
            return dict(id=str(g['_id']), name=g['name'], group_id=g['group_id'], url=g['url'],
                        techniques=[str(technique) for technique in g['techniques']])
        else:
            return dict(id=str(g['_id']), name=g['name'], group_id=g['group_id'], url=g['url'], aliases=g['aliases'],
                        techniques=[str(technique) for technique in g['techniques']])

    @staticmethod
    def _map_tactic(t):
        return dict(id=str(t['_id']), name=t['name'], url=t['url'])

    @staticmethod
    def _map_domain(d):
        return dict(id=str(d['_id']), windows_domain=d['windows_domain'], dns_domain=d['dns_domain'],
                    is_simulated=d['is_simulated'])

    @staticmethod
    def _map_host(h):
        return dict(id=str(h['_id']), fqdn=h['fqdn'], ip=h['IP'], last_seen=h['last_seen'].strftime('%Y-%m-%d %H:%M'),
                    hostname=h['hostname'], status=h['status'], domain=str(h['domain']))

    @staticmethod
    def _map_agent(a):
        return dict(id=str(a['_id']), alive=a['alive'], check_in=a['check_in'].strftime('%Y-%m-%d %H:%M'),
                    host=str(a['host']))

    @staticmethod
    def _map_artifact(art):
        return dict(id=str(art['_id']), name=art['name'], description=art['description'],
                    executables=art['executables'],
                    dlls=art['dlls'], services=art['services'], schtasks=art['schtasks'],
                    file_paths=art['file_paths'])

    @staticmethod
    def _map_network(net):
        return dict(id=str(net['_id']), name=net['name'], domain=str(net['domain']),
                    hosts=[str(h) for h in net['hosts']])

    @staticmethod
    def _map_adversary(adv):
        return dict(id=str(adv['_id']), name=adv.get('name'), protected=adv.get('protected'),
                    exfil_method=adv.get('exfil_method'),
                    exfil_address=adv.get('exfil_address'), exfil_port=adv.get('exfil_port'),
                    artifact_list=[str(a) for a in adv.get('artifactlists', [])],
                    steps=[str(a) for a in adv.get('steps')])

    @staticmethod
    def _map_step(s):
        summary = s['summary'] or 'todo'
        return dict(id=str(s['_id']), name=s['name'], summary=summary.replace('\n', '\t').strip(),
                    source_hash=str(s['source_hash']),
                    cddl=s['cddl'], score=s['score'], footprint=s['footprint'],
                    display_name=s['display_name'], deterministic=s['deterministic'],
                    coded_name=s['coded_name'],
                    requirement_terms=[dict(predicate=str(m['predicate']), literals=[l for l in m['literals']]) for m in
                                       s['requirement_terms']],
                    default_mapping=[dict(tactic=str(m['tactic']), technique=str(m['technique'])) for m in
                                     s['default_mapping']],
                    mapping=[dict(tactic=str(m['tactic']), technique=str(m['technique'])) for m in s['mapping']],
                    bindings=s['bindings'], significant_parameters=s['significant_parameters'],
                    remove=s['remove'], requirement_comparisons=s['requirement_comparisons'],
                    add=[dict(predicate=str(m['predicate']), literals=[l for l in m['literals']]) for m in s['add']],
                    parameters=s['parameters'])

    @staticmethod
    def _map_operation(op):
        start = op.get('start_time')
        end = op.get('end_time')
        if start:
            start = start.strftime('%Y-%m-%d %H:%M:%S')
        if end:
            end = end.strftime('%Y-%m-%d %H:%M:%S')
        return dict(id=str(op['_id']), name=op['name'], adversary=str(op['adversary']), network=str(op['network']),
                    status=op['status'], steps=[str(s) for s in op['steps']], status_state=op['status_state'],
                    performed_actions=op.get('performed_actions'), start_host=str(op['start_host']),
                    start_time=start, end_time=end, known_credentials=[str(c) for c in op['known_credentials']],
                    performed_steps=[dict(name=s['name'], description=s['description'], status=s['status'],
                                          jobs=[str(job) for job in s['jobs']]) for s in op['performed_steps']],
                    jobs=[str(job) for job in op['jobs']], log=(str(op['log'])),
                    known_domains=[str(d) for d in op['known_domains']],
                    known_hosts=[str(h) for h in op['known_hosts']],
                    known_trashed=[str(t) for t in op['known_trashed']],
                    known_files=[str(f) for f in op['known_files']],
                    known_shares=[str(s) for s in op['known_shares']],
                    known_users=[str(u) for u in op['known_users']],
                    known_schtasks=[str(s) for s in op['known_schtasks']],
                    known_services=[str(s) for s in op['known_services']],
                    known_timedeltas=[str(td) for td in op['known_timedeltas']],
                    known_rats=[str(r) for r in op['known_rats']],
                    known_devices=[str(d) for d in op['known_devices']],
                    known_persistence=[str(p) for p in op['known_persistence']],
                    known_processes=[str(p) for p in op['known_processes']],
                    known_registry_keys=[str(rk) for rk in op['known_registry_keys']],
                    known_os_versions=[str(osv) for osv in op['known_os_versions']]
                    )

    @staticmethod
    def _map_rat(rat):
        return dict(id=str(rat['_id']), elevated=rat['elevated'], name=rat['name'], host=str(rat['host']),
                    agent=str(rat['agent']), executable=rat['executable'], username=rat['username'],
                    mode=rat['mode'], active=rat['active'])

    @staticmethod
    def _map_setting(s):
        return dict(id=str(s['_id']), footprint=s['footprint'], recursion_limit=s['recursion_limit'],
                    obfuscate=s['obfuscate'], planner_depth=s['planner_depth'], external_tools=s['external_tools'],
                    last_attack_update=s['last_attack_update'])

    @staticmethod
    def _map_job(j):
        created = j.get('create_time')
        if created and type(created) is not str:
            created = created.strftime('%Y-%m-%d %H:%M')
        action = nested_get(j, ['action', 'rats', 'function'])
        stdin = nested_get(j, ['action', 'rats', 'parameters', 'stdin'])
        cmd = nested_get(j, ['action', 'rats', 'parameters', 'command_line'])
        stdout = nested_get(j, ['action', 'result', 'stdout'])
        host = nested_get(j, ['action', 'rats', 'hostname'])
        return dict(id=str(j['_id']), agent=str(j['agent']), create_time=created,
                    status=j['status'], stdout=stdout,
                    stdin=stdin, cmd=cmd, action=action, hostname=host)

    @staticmethod
    def _map_raw_job(j):
        return dict(id=str(j['_id']), agent=str(j['agent']), create_time=j['create_time'].strftime('%Y-%m-%d %H:%M'),
                    status=j['status'], action=str(j['action']))

    @staticmethod
    def _map_log(l):
        return dict(id=str(l['_id']), event_stream=[e for e in l['event_stream']])

    @staticmethod
    def _map_observed_credential(c):
        return dict(id=str(c['_id']), found_on_host=str(c['found_on_host']))
