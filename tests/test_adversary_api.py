import pathlib
import pytest
import sys
from aiohttp import web


plugin_root = pathlib.Path(__file__).parents[3]
print(plugin_root)
sys.path.append(str(plugin_root))


import plugins.adversary.app.config as config
from plugins.adversary.hook import setup_routes_and_services


async def hello(request):
    return web.Response(body=b'Hello, world')


test_config = """
[adversary]
host = localhost
port = 27017
db_key = vjiuMUuNd8fx7934XF50Vtm2YYXrzZhWl2B2b6G6BUU=
app_key = Qy5pvp1uhfyalpC0CCHCF8VPksweP1Hq48H5Y8ka5vzz4LBYdKU8TTr8ifd0Ns3+YLNvl2JR7kH5i3XLsBh57SY9F7ZzoKh4xMGd7iloFg07Huq40IdN942pk2md9XAyfaJ4bvVkyqwOGR3EwC3duHSJ2yWv4pxJQcSITSAXsEU+UJw3E7a8vJ4pETf/EFGZ0Dzw4tm2iU5ATg1qzffoo+aDu8y3u0HQAjeZWiyO7T2ywtiP6mDYAxV5rWlgHXq56V/rjpqPTH8GruTiZgpY8+9uB/RcnDr8IHus/xPlwrxb0nqOVDMuf/u7qk/4S4m6i5dJyvOyav3Xs6V6d4BTKQ==
"""


class DummyAuthService:
    def __init__(self, dao, app):
        self.dao = dao
        self.ssl_cert = "BLARGHBLARGHHONK"
        self.app_handle = app

    def register(self, username, password):
        pass

    def login(self, username, password):
        return True

    def set_authorized_route(self, *args, **kwargs):
        # don't care about auth provided by core -- we're not testing that here
        self.set_unauthorized_route(*args, **kwargs)

    def set_unauthorized_route(self, allowed_requests, endpoint, target_function):
        if isinstance(allowed_requests, list):
            for ar in allowed_requests:
                self.app_handle.router.add_route(ar, endpoint, target_function)
        else:
            self.app_handle.router.add_route(allowed_requests, endpoint, target_function)

    def set_unauthorized_static(self, *args, **kwargs):
        # ignore static routes for now
        pass


@pytest.fixture
async def app():
    app = web.Application()

    config.initialize_settings(config_str=test_config)

    services = dict(auth_svc=DummyAuthService(config.settings.dao, app))
    await setup_routes_and_services(app, services)

    app.router.add_route('GET', '/', hello)
    yield app


async def test_hello(aiohttp_client, app):
    # sort of a meta test that tests the ability to run tests...
    client = await aiohttp_client(app)
    resp = await client.get('/')
    assert resp.status == 200
    text = await resp.text()
    assert 'Hello, world' in text

