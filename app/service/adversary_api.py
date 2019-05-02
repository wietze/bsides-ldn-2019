import json
import socket
import ujson as json_module
from datetime import datetime, timezone
from functools import wraps

from aiohttp_jinja2 import template
from aiohttp import web
from bson import ObjectId

import plugins.adversary.app.authentication as auth
import plugins.adversary.app.util as util
import plugins.adversary.app.config as config
from plugins.adversary.app.engine.database import native_types
from plugins.adversary.app.service.background import BackgroundTasks
from plugins.adversary.app.service.explode import Explode


def require_token(view_function):
    @wraps(view_function)
    def decorated_function(*args, **kwargs):
        try:
            request = args[1]
            token = auth.Token(request.cookies.get('AUTH'), config.settings.auth_key)
            if token.in_group('agent'):
                return view_function(*args, **kwargs)
            return web.HTTPUnauthorized()
        except auth.NotAuthorized:
            return web.HTTPForbidden()
    return decorated_function


class AdversaryApi:

    def __init__(self, api_logic, auth_key):
        self.api_logic = api_logic
        self.auth_key = auth_key
        self.background = BackgroundTasks(api_logic=api_logic)

    async def rat_download(self, request):
        return web.FileResponse(path=self.api_logic.get_commander_rel_path_file())

    async def rat_query_macro(self, request):
        macro = request.rel_url.parts[2]
        return web.Response(text=self.api_logic.build_download_powershell(macro), content_type='text/plain')

    async def deflate_token(self, request):
        if request.cookies.get('AUTH'):
            token = auth.Token(request.cookies.get('AUTH'), self.auth_key)
            return token
        else:
            return web.HTTPNoContent()

    async def rat_login(self, request):
        token = None
        try:
            token = auth.Token(request.cookies.get('AUTH'), self.auth_key)
        except:
            pass

        data = await request.json()
        if "agent" in data:
            ip, port = request.transport.get_extra_info('peername')
            try:
                lookup_hostname = socket.gethostbyaddr(ip)[0].split(".")[0].lower()
            except socket.herror as herr:
                lookup_hostname = data['hostname']

            for x in ("fqdn", "hostname", "windows_domain", "dns_domain"):
                if x in data:
                    data[x] = data[x].lower()

            if "hostname" in data:
                if data["hostname"] != lookup_hostname:
                    print("Agent reported hostname as '{}' but it actually is '{}'".format(data["hostname"],
                                                                                           lookup_hostname))
            else:
                data['hostname'] = lookup_hostname

            domain_dict = {k: data[k] for k in ('windows_domain', 'dns_domain')}
            domain_dict.update({'is_simulated': False})
            with self.api_logic.dao as con:
                # Check if the domain exists, if it doesn't create a new one
                domain = con.find('domain', key='dns_domain', value=domain_dict['dns_domain'])
                if len(domain) == 0:
                    domain = con.create('domain', dict(dns_domain=domain_dict['dns_domain'],
                                                       windows_domain=domain_dict['windows_domain'],
                                                       is_simulated=domain_dict['is_simulated']))
                else:
                    domain = ObjectId(domain[0]['id'])

                # Check if the host exists in the database, if it doesn't create a new object. If it does, update time
                host = con.find('host', key='fqdn', value=data['fqdn'])
                if len(host) == 0:
                    host = con.create('host', dict(hostname=data['hostname'],
                                                   status="active",
                                                   IP=ip,
                                                   last_seen=util.tz_utcnow(),
                                                   fqdn=data['fqdn'],
                                                   domain=domain))
                else:
                    con.update('host', id=host[0]['id'], data=dict(last_seen=datetime.now()))
                    host = ObjectId(host[0]['id'])

                # check if the existing agent is registered, if not, create a new entry
                agent = con.find('agent', key='host', value=host)
                if len(agent) == 0:
                    agent = con.create('agent', dict(host=host,
                                                     alive=True,
                                                     check_in=datetime.now()))
                else:
                    agent = ObjectId(agent[0]['id'])

                token = auth.login_generic(self.auth_key, ["agent"], {'_id': agent})
            if token is not None:
                resp = web.Response(text=token)
                resp.set_cookie('AUTH', value=token, secure=True)
            else:
                resp = web.HTTPForbidden()
            return resp

    @require_token
    async def rat_heartbeat(self, request):
        token = auth.Token(request.cookies.get('AUTH'), self.auth_key)
        with self.api_logic.dao as con:
            con.update('agent', token.session_info['_id'], {'check_in': datetime.now(timezone.utc), 'alive': True})
        return web.Response(body=json.dumps(True))

    @require_token
    async def rat_clients_checkin(self, request):
        token = auth.Token(request.cookies.get('AUTH'), self.auth_key)
        data = await request.json()
        await self.api_logic.save_rat(token.session_info['_id'], data)
        return web.Response(body=None)

    @require_token
    async def rat_get_jobs(self, request):
        token = auth.Token(request.cookies.get('AUTH'), self.auth_key)
        status = request.rel_url.query['status'] if 'status' in request.rel_url.query else None
        wait = request.rel_url.query['wait'] if 'wait' in request.rel_url.query else False
        jobs = await self.api_logic.get_api_jobs(status, token.session_info['_id'], wait)
        resp_json = json_module.dumps(native_types(jobs), sort_keys=True, indent=4)
        return web.Response(text=resp_json, content_type="application/json")

    @require_token
    async def rat_get_job(self, request):
        token = auth.Token(request.cookies.get('AUTH'), self.auth_key)
        resp = {}
        with self.api_logic.dao as con:
            job = con.get_jobs(ids=[request.rel_url.name])[0]
        if job['status'] in ('created', 'pending') and job['agent'] == token.session_info['_id']:
            resp = job
        if request.method == 'PUT':
            if job['status'] in ('created', 'pending') and job['agent'] == token.session_info['_id']:
                data = await request.json()
                resp = await self.api_logic.put_job_details(data, job)
        resp_json = json_module.dumps(native_types(resp), sort_keys=True, indent=4)
        return web.Response(text=resp_json, content_type="application/json")

    @staticmethod
    async def download_logs(request):
        op_id = request.rel_url.query['id']
        headers = dict([('CONTENT-DISPOSITION', 'attachment; filename="%s"' % op_id)])
        with open('.logs/%s' % op_id, 'r') as f:
            return web.Response(body=f.read(), content_type='application/json', headers=headers)

    async def start_operation(self, request):
        with self.api_logic.dao as con:
            data = await request.post()
            con.update('operation', data.get('id'), dict(status='start'))
        return web.json_response('operation started')

    async def rebuild_database(self, request):
        with self.api_logic.dao as con:
            con.terminate()
            await self.background.database_seed()
        return web.json_response('terminated')

    async def download_bsf(self, request):
        op_id = request.rel_url.query['id']
        with self.api_logic.dao as con:
            full_op = con.get_operations(ids=[op_id])[0]
            bsf = con.get_logs(ids=[full_op['log']])[0]['event_stream']
            headers = dict([('CONTENT-DISPOSITION', 'attachment; filename="bsf-%s.json"' % op_id)])
            return web.Response(body=json.dumps(bsf, indent=4), content_type='application/json', headers=headers)

    async def download_operation(self, request):
        op_id = request.rel_url.query['id']
        with self.api_logic.dao as con:
            full_op = Explode(con).operation(id=op_id)[0]
            headers = dict([('CONTENT-DISPOSITION', 'attachment; filename="op-%s.json"' % op_id)])
            return web.Response(body=json.dumps(full_op), content_type='application/json', headers=headers)

    async def refresh(self, request):
        with self.api_logic.dao as con:
            op = None
            exploder = Explode(con)
            data = await request.post()
            if data.get('id'):
                op = exploder.operation(data.get('id'))[0]
            hosts = exploder.host()
            networks = con.get_networks()
            adversaries = con.get_adversaries()
            steps = exploder.step()
            domains = con.get_domains()
            return web.json_response(dict(chosen=op, hosts=hosts, networks=networks, adversaries=adversaries, steps=steps,
                                          domains=domains))

    @template('adversary.html')
    async def planner(self, request):
        with self.api_logic.dao as con:
            if request.method == 'PUT':
                data = dict(await request.json())
                index = data.pop('index')
                if index == 'network':
                    return web.json_response(self.api_logic.save_network(data))
                elif index == 'adversary':
                    return web.json_response(self.api_logic.save_adversary(data))
            elif request.method == 'POST':
                #  only the operations form uses the POST method
                data = dict(await request.post())
                index = data.pop('index')
                new_id = con.create(index, data)
                return web.json_response(dict(id=str(new_id), msg='successfully created %s' % index))
            elif request.method == 'DELETE':
                data = await request.post()
                index = data.get('index')
                if index == 'adversary':
                    return web.json_response(self.api_logic.delete_adversary(data))
                elif index == 'operation':
                    return web.json_response(self.api_logic.delete_operation(data))
                con.delete(index, data.get('id'))
                return web.json_response('deleted successfully')
            elif request.method == 'PATCH':
                data = await request.post()
                index = data.get('index')
                if index == 'operation':
                    return web.json_response(self.api_logic.cancel_operation(data))
                return web.json_response('cancelled successfully')

            # return GET results for GUI
            exploder = Explode(con)
            return dict(active=dict(),
                        techniques=con.get_techniques(),
                        tactics=con.get_tactics(),
                        hosts=con.get_hosts(),
                        steps=exploder.step(),
                        networks=exploder.network(),
                        artifact_lists=con.get_artifact_lists(),
                        settings=con.get_settings()[0],
                        groups=con.get_attack_groups(),
                        adversaries=con.get_adversaries(),
                        operations=con.get_operations(),
                        domains=con.get_domains(),
                        rats=con.get_rats(),
                        errors=self.api_logic.build_errors())

    async def render_conf(self, request):
        file_name = request.rel_url.parts[-1]
        url_root = '{scheme}://{host}'.format(scheme=request.scheme, host=request.host)
        headers = dict([('CONTENT-DISPOSITION', 'attachment; filename="%s"' % file_name)])
        rendered = await self.api_logic.render_config(url_root=url_root)
        return web.HTTPOk(body=rendered, headers=headers)

    @template('settings.html')
    async def settings(self, request):
        with self.api_logic.dao as con:
            if request.method == 'POST':
                data = dict(await request.post())
                data = self.api_logic.update_caldera_settings(data=data, current_settings=con.get_settings()[0])
                con.update('setting', con.get_settings()[0]['id'], data)
            return dict(settings=con.get_settings()[0])

    async def control(self, request):
        data = dict(await request.post())
        target = data['id']
        mode = data['mode']
        result = "ok"
        if mode == 'pause':
            await self.api_logic.op_svc.pause_operation(target)
        elif mode == 'run':
            await self.api_logic.op_svc.run_operation(target)
        elif mode == 'cancel':
            await self.api_logic.op_svc.cancel_operation(target)
        elif mode == 'state':
            result = await self.api_logic.op_svc.get_state(target)
        else:
            result = "unknown"
        return web.json_response(dict(result=result))