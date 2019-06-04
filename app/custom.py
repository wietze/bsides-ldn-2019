import random
import os
import re
import subprocess
import requests
from urllib.parse import urlencode, quote_plus

def random_string(length = None):
    if length is None: length = random.randint(3, 15)
    return ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(length))

def get_image_name(process):
    return process.split('\\')[-1].split(' ')[0]

def get_process(url):
    return  url.split('/')[-1]

def update_software(software_g, x):
    return software_g({ 'host':x.host, 'name':x.name,
                        'installed':x.installed, 'install_command':x.install_command, 'install_loc':x.install_loc,
                        'downloaded':x.downloaded, 'download_url':x.download_url, 'download_loc':x.download_loc
                      })

def get_temp_folder(host, rat):
    if rat is not None and rat.elevated:
        return 'c:\\windows\\temp\\'
    elif rat is not None and rat.username:
        return 'c:\\users\\{}\\AppData\\Local\\Temp\\'.format(rat.username)
    else:
        return '%temp%\\'

def escape(input, source):
    if type(source) is not list:
        source = [source]

    for s in source:
        if s == 'powershell':
            input = input.replace('`', '``').replace('"', '`"').replace('$', '`$')
        elif s == 'cmd':
            input = input.replace('^', '^^').replace('"', '"""').replace('<', '^<').replace('>', '^>').replace('|', '^|').replace('&', '^&').replace('%', '%%')
        elif s == 'vbs':
            input = input.replace('"', '""')
        elif s == 'c#':
            input = input.replace('\\', '\\\\').replace('"', '\\"')
        else:
            raise Exception('Unknown escape type')

    return input
