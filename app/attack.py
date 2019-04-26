import json
import string

import requests
from plugins.adversary.app.engine.objects import AttackTactic, AttackTechnique, AttackList, AttackGroup


def get_techniques_from_group(links, techs, group_id):
    downselect = []
    for entry in links:
        if entry["source_ref"] == group_id:
            downselect.append(entry["target_ref"])
    selected_techs = []
    for entry in downselect:
        for technique in techs:
            if entry == technique["id"]:
                selected_techs.append(technique)
                break
    return selected_techs


def get_techniques_from_group_software(links, techs, group_id):
    mal_list = []
    for entry in links:
        if entry["source_ref"] == group_id and entry["target_ref"][:4] in ['malw','tool']:
            mal_list.append(entry['target_ref'])

    tech_list = []
    for tool in mal_list:
        for entry in links:
            if entry["source_ref"] == tool:
                tech_list.append(entry["target_ref"])

    selected_techs = []
    for entry in tech_list:
        for technique in techs:
            if entry == technique["id"]:
                selected_techs.append(technique)
                break
    return selected_techs


def refresh_attack():
    target = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    global_results = requests.get(target, verify=False) #grab_site(target, params=None, stream=False, mode='attack').json()
    technique_list = []
    group_list = []
    relationships = []

    global_results = json.loads(global_results.text)
    for entry in global_results['objects']:
        if entry["type"] == "attack-pattern":
            technique_list.append(entry)
        if entry["type"] == "intrusion-set":
            group_list.append(entry)
        if entry['type'] == "relationship":
            relationships.append(entry)

    tactics = {}
    for entry in technique_list:
        for phase in entry['kill_chain_phases']:
            if phase['kill_chain_name'] == "mitre-attack":
                temp_p = phase['phase_name'].replace("-", " ")
                name = string.capwords(temp_p)
                if name == "Command And Control":
                    name = "Command and Control"

                tactic = AttackTactic.objects(name=name).first()
                if tactic is None:
                    tactic = AttackTactic(name=name)
                tactic.url = "https://attack.mitre.org/wiki/" + name.replace(" ", "_")
                tactic.save()
                tactics[tactic.name] = tactic

    techniques = {}
    for entry in technique_list:
        for element in entry['external_references']:
            if element["source_name"] == "mitre-attack":
                technique_id = element['external_id']
                technique = AttackTechnique.objects(technique_id=technique_id).first()
                if technique is None:
                    technique = AttackTechnique(technique_id=technique_id)
                technique.url = element['url']
        technique.name = entry['name']
        technique.description = repr(entry['description'])
        technique.description = technique.description.replace("\\u", "\\\\u")  # Patch for unicode instances of \u
        local_list = []
        for phase in entry['kill_chain_phases']:
            if phase['kill_chain_name'] == "mitre-attack":
                temp_p = phase['phase_name'].replace("-", " ")
                t_name = string.capwords(temp_p)
                if t_name == "Command And Control":
                    t_name = "Command and Control"

                local_list.append(tactics[t_name])
        technique.tactics = local_list
        technique.save()
        techniques[technique.name] = technique

    listing = AttackList.objects().first()
    if listing is None:
        listing = AttackTechnique.objects()
    listing.master_list = "Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential " \
                          "Access, Discovery, Lateral Movement, Collection, Exfiltration, Command and Control"
    listing.save()

    for entry in group_list:
        for element in entry['external_references']:
            if element["source_name"] == "mitre-attack":
                group_id = element['external_id']
                group = AttackGroup.objects(group_id=group_id).first()
                if group is None:
                    group = AttackGroup(group_id=group_id)
                group.url = element['url']
        tech_list = []
        tech_g_list = get_techniques_from_group(relationships, technique_list, entry['id'])
        for tech_entry in tech_g_list:
            for res in tech_entry['external_references']:
                if res["source_name"] == "mitre-attack":
                    techg_id = res['external_id']
                    techg = AttackTechnique.objects(technique_id=techg_id).first()
                    tech_list.append(techg)
        soft_g_list = get_techniques_from_group_software(relationships, technique_list, entry["id"])
        for soft_entry in soft_g_list:
            for res in soft_entry['external_references']:
                if res['source_name'] == "mitre-attack":
                    softg_id = res['external_id']
                    softg = AttackTechnique.objects(technique_id=softg_id).first()
                    if softg not in tech_list:
                        tech_list.append(softg)
        group.techniques = tech_list
        group.name = entry['name']
        try:
            group.aliases = entry['aliases']
        except KeyError:
            group.aliases = []
        group.save()


def load_default(attack_data=None):
    """Loads the default attack data into the database
    """
    attack_dumped = json.loads(attack_data)
    tactic_name_to_id = {}
    for tactic in attack_dumped['tactics']:
        saved = AttackTactic(name=tactic['name'], url=tactic['url']).save()
        tactic_name_to_id[tactic['name']] = saved.id

    for technique in attack_dumped['techniques']:
        tactic_ids = [tactic_name_to_id[x] for x in technique['tactics']]
        technique['description'] = repr(technique['description']).replace("\\u", "\\\\u")
        AttackTechnique(name=technique['name'], url=technique['url'], description=technique['description'],
                        technique_id=technique['technique_id'], tactics=tactic_ids, isLinux=technique['isLinux'],
                        isMac=technique['isMac'], isWindows=technique['isWindows']).save()
    listing = AttackList(master_list=attack_dumped['order'][0]['master_list'])
    listing.save()
    for group in attack_dumped['groups']:
        tech = []
        aliases = []
        for entry in group['techniques']:
            for db_tech in AttackTechnique.objects:
                if entry == db_tech.technique_id:
                    tech.append(db_tech)
        for entry in group['aliases']:
                     aliases.append(entry)
        AttackGroup(name=group['name'], group_id=group['group_id'], url=group['url'], aliases=aliases,
                    techniques=tech).save()
