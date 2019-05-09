import logging

import plugins.adversary.app.config as config
from plugins.adversary.app.service.adversary_api import AdversaryApi
from plugins.adversary.app.service.api_logic import ApiLogic
from plugins.adversary.app.service.background import BackgroundTasks

name = 'Adversary'
description = 'Adds the full Adversary mode, including REST and GUI components'
address = '/plugin/adversary/gui'
store = 'plugins/adversary/filestore'


async def setup_routes_and_services(app, services):
    auth_svc = services.get('auth_svc') 
    api_logic = ApiLogic(config.settings.dao, auth_svc)
    background = BackgroundTasks(api_logic=api_logic)
    adversary_api = AdversaryApi(api_logic=api_logic, auth_key=config.settings.auth_key)

    app.on_startup.append(background.tasks)
    # Open Human Endpoints
    auth_svc.set_unauthorized_static('/adversary', config.settings.plugin_root / 'static/', append_version=True)
    auth_svc.set_unauthorized_route('GET', '/conf.yml', adversary_api.render_conf)

    # Authorized Human Endpoints
    auth_svc.set_authorized_route('*', '/plugin/adversary/gui', adversary_api.planner)
    auth_svc.set_authorized_route('*', '/adversary', adversary_api.planner)
    auth_svc.set_authorized_route('POST', '/operation/refresh', adversary_api.refresh)
    auth_svc.set_authorized_route('POST', '/operation', adversary_api.start_operation)
    auth_svc.set_authorized_route('*', '/adversary/logs/plan', adversary_api.download_logs)
    auth_svc.set_authorized_route('*', '/adversary/logs/bsf', adversary_api.download_bsf)
    auth_svc.set_authorized_route('*', '/adversary/logs/operation', adversary_api.download_operation)
    auth_svc.set_authorized_route('POST', '/terminate', adversary_api.rebuild_database)
    auth_svc.set_authorized_route('*', '/settings', adversary_api.settings)

    # Open Agent Endpoints
    auth_svc.set_unauthorized_route('GET', '/commander', adversary_api.rat_download)
    auth_svc.set_unauthorized_route('GET', '/deflate_token', adversary_api.deflate_token)
    auth_svc.set_unauthorized_route('GET', '/macro/{macro}', adversary_api.rat_query_macro)
    auth_svc.set_unauthorized_route('POST', '/login', adversary_api.rat_login)

    # Authorized Agent Endpoints (Agents use separate tokens & auth is implemented separately in the plugin)
    auth_svc.set_unauthorized_route('GET', '/api/heartbeat', adversary_api.rat_heartbeat)
    auth_svc.set_unauthorized_route('GET', '/api/jobs', adversary_api.rat_get_jobs)
    auth_svc.set_unauthorized_route('GET', '/api/jobs/{job}', adversary_api.rat_get_job)
    auth_svc.set_unauthorized_route('POST', '/api/clients', adversary_api.rat_clients_checkin)
    auth_svc.set_unauthorized_route('PUT', '/api/jobs/{job}', adversary_api.rat_get_job)
    return app


async def initialize(app, services):
    logging.getLogger('app.engine.database').setLevel(logging.INFO)

    config.initialize_settings(config_path='plugins/adversary/conf/config.ini', filestore_path=store)

    await setup_routes_and_services(app, services)
