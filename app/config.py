import base64
import configparser
import pathlib
import os

from plugins.adversary.app.database.dao import Dao


class AdversaryPluginSettings:
    def __init__(self, config_obj=None, filestore_path=None):
        self._config = config_obj

        self.plugin_root = pathlib.Path(__file__).parents[1]
        if filestore_path is not None:
            self.filestore_path = filestore_path
        else:
            self.filestore_path = str(self.plugin_root / 'filestore')
        self.exe_rat_path = self.filestore_path + '/CraterMain.exe'
        self.dll_rat_path = self.filestore_path + '/CraterMain.dll'
        self.config_dir = str(self.plugin_root / 'conf')

        if self._config:
            self.dao = Dao(host=self.db_host, port=self.db_port, key=self.db_key)

    @property
    def config(self) -> configparser.ConfigParser:
        if self._config is None:
            raise RuntimeError('AdversaryPluginSettings was not initialized with config ini file.')

        return self._config

    @property
    def db_host(self) -> str:
        return self.config.get('adversary', 'host', fallback='127.0.0.1')

    @property
    def db_port(self) -> int:
        return self.config.getint('adversary', 'port', fallback=27017)

    @property
    def auth_key(self) -> bytes:
        return base64.b64decode(self.config.get('adversary', 'app_key'))

    @property
    def db_key(self) -> str:
        return self.config.get('adversary', 'db_key').encode('utf-8')

    @property
    def http_proxy(self) -> str:
        return self.config.get('adversary', 'http_proxy', fallback=os.environ.get('http_proxy'))

    @property
    def https_proxy(self) -> str:
        return self.config.get('adversary', 'http_proxy', fallback=os.environ.get('https_proxy'))

    @property
    def ssl_cert_file(self) -> str:
        return self.config.get('adversary', 'ssl_cert_file', fallback=os.environ.get('ssl_cert_file'))


settings = AdversaryPluginSettings()


def initialize_settings(config_path=None, config_str=None, filestore_path=None):
    """
    Initialize a settings global variable that will be accessible from the rest of the plugin.
    :param config_path: The path to an .ini config file.
    :param config_str: A string with .ini formatted contents.
    :param filestore_path: The path to the directory where files live.
    :return:
    """
    if (config_path and config_str) or (not config_path and not config_str):
        raise RuntimeError('Must call with one and only one of config_path or config_str')

    config_obj = configparser.ConfigParser()
    if config_path:
        config_obj.read(config_path)
    else:
        config_obj.read_string(config_str)

    global settings
    settings = AdversaryPluginSettings(config_obj, filestore_path=filestore_path)

