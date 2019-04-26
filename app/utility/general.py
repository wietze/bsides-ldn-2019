import asyncio
import json
import os

import plugins.adversary.app.config as config
from cryptography.fernet import Fernet

"""
This module is designed to hold general utility functions for use across the application
"""


def nested_get(input_dict, nested_key):
    try:
        internal_dict_value = input_dict
        for k in nested_key:
            internal_dict_value = internal_dict_value.get(k, None)
            if internal_dict_value is None:
                return None
        return internal_dict_value
    except Exception:
        return None


def decrypt(key, value):
    prefix = b'$$$$:'
    return Fernet(key).decrypt(value[len(prefix):]).decode('utf-8')


def encrypt(key, value):
    prefix = b'$$$$:'
    return prefix + Fernet(key).encrypt(value.encode('utf-8'))


@asyncio.coroutine
def save_file_async(directory, r):
    data = yield from r.post()
    filename = data['file'].filename
    input_file = data['file'].file
    with open('%s/%s' % (directory, filename), 'wb') as fd:
        while True:
            chunk = input_file.read(1024)
            if not chunk:
                break
            fd.write(chunk)
    return filename


def save_file_sync(directory, r):
    r.save(os.path.join(directory, r.filename))
    return r.filename


def collect_files(directory):
    found = os.listdir(directory)
    return [x for x in found if not x.startswith('.')]


def string_to_bool_for_entry(normalize_string):
    if type(normalize_string) is bool:
        return normalize_string
    if normalize_string.lower() in ('true', 't'):
        return True
    return False


def get_simulated_domain_data(domain=None):
    try:
        with open('%s/simulation.json' % config.settings.config_dir) as sims:
            world = json.load(sims)
            if domain:
                return next(item for item in world['domains'] if item['name'] == domain)
            return world['domains']
    except:
        return None
