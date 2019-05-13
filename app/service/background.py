import asyncio
import base64
import hashlib
import inspect
import json
import logging
import random
import socket
import struct
import traceback
from datetime import datetime, timezone

import mongoengine
import yaml

import plugins.adversary.app.config as config
from plugins.adversary.app.engine import database
from plugins.adversary.app.engine.objects import Operation as OldOperation, Artifactlist, Adversary, CodedStep, \
    TechniqueMapping, \
    AttackTactic, AttackTechnique, Agent
from plugins.adversary.app.engine.objects import Setting, ActiveConnection
from plugins.adversary.app.logic import logic, planner
from plugins.adversary.app.operation.operation import ServerOperation
from plugins.adversary.app.service.explode import Explode
from plugins.adversary.app.steps import all_steps
from plugins.adversary.app.utility.general import get_simulated_domain_data


class BackgroundTasks:

    def __init__(self, api_logic):
        self.api_logic = api_logic

    async def tasks(self, app):
        app.loop.create_task(self.database_seed())
        app.loop.create_task(self.start_sim_environment())
        app.loop.create_task(self.heartbeat())
        app.loop.create_task(self.operation_loop())

    @staticmethod
    async def heartbeat():
        """
        Forever-running job to ensure keep agent status accurate
        """
        try:
            while True:
                for agent in Agent.objects():
                    if (datetime.now(timezone.utc) - agent.check_in).total_seconds() > 300:
                        logging.debug('agent %s no longer active' % agent.id)
                        agent.modify(**{'alive': False})
                await asyncio.sleep(30)
        except asyncio.CancelledError:
            pass

    async def start_sim_environment(self, nap=30):
        """
        Start simulation environment
        """
        while True:
            with self.api_logic.dao as con:
                agents = Explode(con).agent()
                sim_agents = [a for domain in get_simulated_domain_data() for a in agents if
                              a['host']['domain']['windows_domain'] == domain['name']]
            for agent in sim_agents:
                jobs = await self.api_logic.get_api_jobs('created', agent.get('id'), False)
                for job in jobs:
                    stdout = base64.b64encode('simulation hosts have no responses'.encode())
                    x = dict(action=dict(result=dict(stdout=stdout)), status='success',
                             create_time=datetime.now(timezone.utc))
                    await self.api_logic.put_job_details(x, job)
            await asyncio.sleep(nap)

    async def operation_loop(self, nap=30):
        """
        Forever-running loop to run operations - requires GUI click to change status to start
        """
        while True:
            with self.api_logic.dao as con:
                operations = con.get_operations()
                for op in operations:
                    if op['status'] not in ['complete', 'failed']:
                        try:
                            operation = OldOperation.objects.with_id(op['id'])
                            so = ServerOperation(con, operation, self.api_logic.op_svc)
                            await so.loop()
                        except Exception as ex:
                            logging.error(ex)
                            traceback.print_exc()
                            con.update(index='operation', id=op['id'], data=dict(status='failed'))
            logging.debug('operation loop cycle complete')
            await asyncio.sleep(nap)

    async def database_seed(self):
        """
        Seed the database with initial values
        """
        logging.debug('1-time seeding of the database')
        database.start(self.api_logic.dao.host, int(self.api_logic.dao.port), self.api_logic.dao.key)
        database.initialize(self.api_logic.dao.host, int(self.api_logic.dao.port), self.api_logic.dao.key)
        if Setting.objects.count() < 1:
            Setting(footprint=False, recursion_limit=3, planner_depth=2, obfuscate=False, external_tools=False,
                    last_attack_update=datetime.now(timezone.utc)).save()
        for connection in ActiveConnection.objects:
            connection.delete()
        with self.api_logic.dao as con:

            # LOAD techniques
            if len(con.get_techniques()) == 0:
                with open('%s/attack_download.json' % config.settings.config_dir) as attack_data:
                    attack_dumped = json.load(attack_data)
                    tactic_name_to_id = {}
                    for t in attack_dumped['tactics']:
                        saved = con.create('tactics', data=dict(name=t['name'], url=t['url']))
                        tactic_name_to_id[t['name']] = saved
                    for technique in attack_dumped['techniques']:
                        tactic_ids = [tactic_name_to_id[x] for x in technique['tactics']]
                        technique['description'] = repr(technique['description']).replace("\\u", "\\\\u")
                        tech = dict(name=technique['name'], url=technique['url'], description=technique['description'],
                                    technique_id=technique['technique_id'], tactics=tactic_ids)
                        con.create('technique', data=tech)
                    con.create('attack_list', data=dict(master_list=attack_dumped['order'][0]['master_list']))

                    for group in attack_dumped['groups']:
                        tech, aliases = [], []
                        for entry in group['techniques']:
                            for db_tech in con.get_techniques():
                                if entry == db_tech['technique_id']:
                                    tech.append(db_tech)
                        for entry in group['aliases']:
                            aliases.append(entry)
                        group = dict(name=group['name'], group_id=group['group_id'], url=group['url'], aliases=aliases,
                                     techniques=tech)
                        con.create('attack_group', data=group)

            # LOAD artifact lists
            with open('%s/artifact_lists.default' % config.settings.config_dir, 'r') as fle:
                data = fle.read()
                core = yaml.safe_load(data)
                artifacts = {}
                for entry in core:
                    test_val = Artifactlist.objects(name=entry).first()
                    if test_val is not None:
                        artifacts[entry] = test_val
                    else:
                        dat = core[entry]
                        art_list = {}
                        for element in dat:
                            if dat[element] != [None]:
                                art_list[element] = dat[element]
                        art_list['name'] = entry
                        try:
                            obj = Artifactlist(**art_list).save()
                            artifacts[entry] = obj
                        except Exception as e:
                            logging.debug('Unable to save artifact list {} - {}'.format(entry, e))

            # LOAD steps
            for step in CodedStep.objects(name__nin=[x.__name__ for x in all_steps]):
                logging.debug("Removing old step {}".format(step.name))
                step.delete()
            for step in all_steps:
                new_step = False
                try:
                    db_step = CodedStep.objects.get(name=step.__name__)
                except mongoengine.errors.DoesNotExist:
                    new_step = True
                    db_step = CodedStep(name=step.__name__).save()

                step_source = inspect.getsource(step)
                sha1 = hashlib.sha1()
                sha1.update(step_source.encode('utf8'))
                update_object = False
                try:
                    if db_step.source_hash != sha1.digest():
                        update_object = True
                except AttributeError:
                    update_object = True

                if update_object:
                    logging.debug("Updating logical definition of step: '{}'".format(step.__name__))
                    action = logic.convert_to_action(step, planner.PlannerContext.unique_count)
                    updates = action.build_database_dict()
                    updates['source_hash'] = sha1.digest()
                    updates['summary'] = step.__doc__
                    updates['display_name'] = step.display_name
                    updates['coded_name'] = step.coded_name
                    updates['footprint'] = step.footprint
                    updates['default_mapping'] = [TechniqueMapping(tactic=AttackTactic.objects.get(name=x[1]),
                                                                   technique=AttackTechnique.objects.get(technique_id=x[0]))
                                                  for x in step.attack_mapping]
                    updates["cddl"] = step.cddl
                    if new_step:
                        updates['mapping'] = updates['default_mapping']
                    db_step.modify(**updates)

            # LOAD adversaries
            with open('%s/adversary_profiles.default' % config.settings.config_dir, 'r') as fle:
                adversaries = yaml.safe_load(fle.read())
                for entry in adversaries:
                    adv = {}
                    dat = adversaries[entry]
                    adv['name'] = entry + " (Built-in)"
                    adv['protected'] = True
                    test_val = Adversary.objects(name=adv['name']).first()
                    if test_val is not None:
                        logging.debug("Adversary with name {} already exists... skipping.".format(entry))
                    else:
                        for key in dat:
                            if key == 'artifactlists':
                                temp_list = []
                                for comp in dat[key]:
                                    if comp == 'None':
                                        pass
                                    elif comp not in artifacts:
                                        logging.debug(
                                            "Unable to locate configured artifact list {} for adversary {}".format(entry,
                                                                                                                   comp))
                                    else:
                                        temp_list.append(artifacts[comp])
                                if temp_list:
                                    adv[key] = temp_list
                                else:
                                    adv[key] = None
                            elif isinstance(dat[key], list):
                                step_list = []
                                for loaded_entry in CodedStep.objects:
                                    if loaded_entry.name in dat[key]:
                                        step_list.append(loaded_entry)
                                adv[key] = step_list
                            else:
                                adv[key] = str(dat[key])

                        try:
                            Adversary(**adv).save()
                        except Exception as e:
                            logging.debug("Unable to save adversary {} - {}".format(entry, e))

            # create simulation environment
            for domain in get_simulated_domain_data():
                if not con.find('domain', key='windows_domain', value=domain['name']):
                    logging.debug('building a new simulation environment: %s' % domain['name'])
                    domain_id = con.create('domain',
                                           dict(windows_domain=domain['name'], dns_domain='%s.local' % domain['name'],
                                                is_simulated=True))
                    for host, data in domain['hosts'].items():
                        ip_address = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
                        host_id = con.create('host', dict(fqdn='%s.%s.local' % (host, domain['name']),
                                                          last_seen=datetime.now(timezone.utc),
                                                          IP=ip_address, domain=domain_id,
                                                          hostname=host, status='active'))
                        con.create('agent', dict(host=host_id, alive=True, check_in=datetime.now(timezone.utc)))
