import asyncio
import logging
import aiohttp
import json
import pathlib
import ssl
import base64

from aiohttp_remotes import BasicAuth, Secure, AllowedHosts, setup
from datetime import datetime
from aiohttp import web
from aiocache import cached, Cache
from aiocache.serializers import JsonSerializer
from aiocache.plugins import HitMissRatioPlugin, TimingPlugin, BasePlugin

from foreman_cache.utils import load_config

RESPONSE_OK = [
200,
201,
]

PROJ_ROOT = pathlib.Path(__file__).parent.parent

async def fget(uri, cache, user, password, request, ttl=3600):
    is_cached = await cache.exists(uri)
    if is_cached:
        result = await cache.get(uri)
        if result is not None:
            return result
    json = {}
    json['subtotal'] = -1
    auth = "%s:%s"%(user, password)
    b64_auth = base64.b64encode(auth.encode('ascii')).decode('ascii')
    headers={"Authorization": "Basic %s"%b64_auth,
             'User-Agent': 'foreman-lookup-cache'}

    if request.app['config']['foreman']['scheme'] == 'https':
        if 'cafile' in request.app['config']['foreman']:
            if 'sslverify' in request.app['config']['foreman']:
                if request.app['config']['foreman']['sslverify']:
                    sslcontext = ssl.create_default_context( cafile=request.app['config']['foreman']['cafile'])
                else:
                    sslcontext=False
        else:
            if 'sslverify' in request.app['config']['foreman']:
                if request.app['config']['foreman']['sslverify']:
                    sslcontext=True
                else:
                    sslcontext=False
            else:
                sslcontext=True
    else:
        sslcontext=None

    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get('%s'%uri, ssl=sslcontext) as response:

                json = await response.json()
                if response.status in RESPONSE_OK:
                    await cache.set(uri, json, ttl=ttl)
    except aiohttp.ClientConnectorError as e:
        print("Cannot connect to %s %s"%(uri,e))
        pass

    return json


@cached(ttl=60, serializer=JsonSerializer())
async def fgetp1(request):

    json = {}
    json['subtotal'] = -1
    params = {}

    for qstring in request.rel_url.query:
        params[qstring] = request.rel_url.query[qstring]

    params['per_page'] = 1
    path = request.rel_url.path

    url = '%s://%s:%s'%(request.app['config']['foreman']['scheme'], request.app['config']['foreman']['host'], request.app['config']['foreman']['port'])
    auth = "%s:%s"%(request.app['config']['foreman']['user'], request.app['config']['foreman']['password'])
    b64_auth = base64.b64encode(auth.encode('ascii')).decode('ascii')
    headers={"Authorization": "Basic %s"%b64_auth,
             'User-Agent': 'foreman-lookup-cache'}

    if request.app['config']['foreman']['scheme'] == 'https':
        if 'cafile' in request.app['config']['foreman']:
            if 'sslverify' in request.app['config']['foreman']:
                if request.app['config']['foreman']['sslverify']:
                    sslcontext = ssl.create_default_context( cafile=request.app['config']['foreman']['cafile'])
                else:
                    sslcontext=False
        else:
            if 'sslverify' in request.app['config']['foreman']:
                if request.app['config']['foreman']['sslverify']:
                    sslcontext=True
                else:
                    sslcontext=False
            else:
                sslcontext=True
    else:
        sslcontext=None

    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get('%s%s'%(url, path), params=params, ssl=sslcontext) as response:

                if response.status in RESPONSE_OK:
                    json = await response.json()
    except aiohttp.ClientConnectorError as e:
        print("Cannot connect to %s %s"%(url,e))
        pass

    return json['subtotal']

async def method(request):
    cache = request.app['cache']
    ttl = request.app['config']['cache']['ttl']
    uri = '%s://%s:%s%s'%(request.app['config']['foreman']['scheme'], request.app['config']['foreman']['host'], request.app['config']['foreman']['port'], request.rel_url)
    result = {}
    if request.match_info['item'] not in request.app['config']['allowed_items']:
        return web.Response(status=404)

    subtotalp1 = await fgetp1(request)

    response = await fget(uri, cache, request.app['config']['foreman']['user'], request.app['config']['foreman']['password'], request, ttl=ttl)

    in_cache = await cache.exists(uri)
    if 'subtotal' in response:
        if response['subtotal'] != subtotalp1 and in_cache and subtotalp1 > -1:
            print("need to reload from foreman: %s / %s"%(response['subtotal'], subtotalp1))
            del_id = await cache.delete(uri)
            print("cache remove for %s id: %s"%(uri, del_id))

    foreman_lookup = await fget(uri, cache, request.app['config']['foreman']['user'], request.app['config']['foreman']['password'], request, ttl=ttl)
    if 'subtotal' in foreman_lookup:
        if foreman_lookup['subtotal'] < 0:
            return web.Response(status=502)

    return web.json_response(foreman_lookup)

async def init(loop):
    conf = load_config(PROJ_ROOT / 'config' / 'config.yml')

    app = web.Application(loop=loop)

    app.router.add_route('GET', "/api/v2/{item}", method)
    app.router.add_route('GET', "/api/{item}", method)
    cache = Cache(plugins=[HitMissRatioPlugin(), TimingPlugin()])

    print(conf['allowed_items'])

    if 'host' in conf:
        host = conf['host']
    else:
        host = '127.0.0.1'

    if 'port' in conf:
        port = conf['port']
    else:
        port = '443'

    if 'access_log_format' in conf:
        access_log_format = conf['access_log_format']
    else:
        access_log_format = '%a %t "%r" %s %b "%{Referer}i" "%{User-Agent}i"'

    if 'scheme' in conf:
        if conf['scheme'] == 'https':
            if 'sslcertchain' and 'sslkey' in conf:
                ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ssl_context.load_verify_locations(conf['sslcertchain'], conf['sslkey'])
                ssl_context.load_cert_chain(conf['sslcertchain'], conf['sslkey'])
            else:
                raise NameError('sslcertchain / sslkey missing in the configuration')
        else:
            ssl_context = None 
    else:
        ssl_context = None 
                

    app['config'] = conf

    user, password, realm = conf['authentication']['user'], conf['authentication']['password'], conf['authentication']['realm']
    await setup(app, AllowedHosts(conf['allowed_hosts']), BasicAuth(user, password, realm))
    app['cache'] = cache
    return app, cache, host, port, access_log_format, ssl_context


def main():
    logging.basicConfig(level=logging.INFO)
    loop = asyncio.get_event_loop()
    app, cache, host, port, access_log_format, ssl_context = loop.run_until_complete(init(loop))
    web.run_app(app, host=host, port=port, access_log_format=access_log_format, ssl_context=ssl_context)


if __name__ == '__main__':
    main()
