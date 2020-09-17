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

from foreman_cache.utils import load_config, load_sslcontext

RESPONSE_OK = [
200,
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

    sslcontext = load_sslcontext(request)

    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get('%s'%uri, ssl=sslcontext, allow_redirects=False) as response:

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

    sslcontext = load_sslcontext(request)

    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get('%s%s'%(url, path), params=params, ssl=sslcontext, allow_redirects=False) as response:

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

async def cache():
    conf = load_config(PROJ_ROOT / 'config' / 'config-gunicorn.yml')

    app = web.Application()

    app.router.add_route('GET', "/api/v2/{item}", method)
    app.router.add_route('GET', "/api/{item}", method)
    cache = Cache(plugins=[HitMissRatioPlugin(), TimingPlugin()])

    app['config'] = conf

    user, password, realm = conf['authentication']['user'], conf['authentication']['password'], conf['authentication']['realm']
    await setup(app, AllowedHosts(conf['allowed_hosts']), BasicAuth(user, password, realm))
    app['cache'] = cache
    return app
