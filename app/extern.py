import os
import zipfile
import errno
import io
import shutil

import plugins.adversary.app.config as config
from plugins.adversary.app.util import grab_site, relative_path


def load_psexec():
    target_file = config.settings.filestore_path + '/ps.hex'
    pstools = grab_site('https://download.sysinternals.com/files/PSTools.zip', stream=True, params=None, mode='psexec')
    if not os.path.exists(os.path.dirname(target_file)):
        try:
            os.makedirs(os.path.dirname(target_file))
        except OSError as error:
            if error.errno != errno.EEXIST:
                raise
    unload_zip(pstools.content, 'PsExec64.exe', target_file)


def unload_zip(zip_file, target_name: str, target_dest: str):
    with zipfile.ZipFile(io.BytesIO(zip_file)) as z:
        with z.open(target_name) as data:
            with open(target_dest, 'wb') as dest:
                shutil.copyfileobj(data, dest)


def obf_rat():
    dest_path = os.path.join(config.settings.filestore_path, 'crater.exe')
    try:
        with open(config.settings.exe_rat_path, 'rb') as file:
            core = file.read()
        egg = core.find(
            b'\x2A\x20\x3C\x20\x2D\x20\x43\x41\x4C\x44\x45\x52\x41\x20\x43\x41\x4C\x44\x45\x52\x41\x20\x43\x41\x4C\x44\x45\x52\x41\x20\x43\x41\x4C\x44\x45\x52\x41\x20\x43\x41\x4C\x44\x45\x52\x41\x20\x2D\x20\x3E\x20\x2A')
        eggshell = os.urandom(51)
        pan = bytearray(core)
        for i in range(0, 50):
            pan[egg + i] = eggshell[i]
        omelet = bytes(pan)
        with open(dest_path, "wb") as file:
            file.write(omelet)
        return True
    except:
        import traceback
        traceback.print_exc()
        return False