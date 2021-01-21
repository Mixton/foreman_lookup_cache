import asyncio
import logging
import aiohttp
import json
import pathlib
import ssl
import base64
import time
import os
import statsd
import socket
import hashlib

from urllib.parse import urlencode, quote
from aiohttp_remotes import BasicAuth, Secure, AllowedHosts, setup
from datetime import datetime
from aiohttp import web
from aiocache import cached, Cache
from aiocache.serializers import JsonSerializer
from aiocache.plugins import HitMissRatioPlugin, TimingPlugin, BasePlugin
from threading import Thread

from foreman_cache.utils import load_config, load_sslcontext, memory_usage

RESPONSE_OK = [
200,
]

SUPPORTED_ITEMS = [
'environments',
'hosts',
'subnets',
'organizations'
]

SPECIAL_ITEMS = [
'fact_values',
]

PROJ_ROOT = pathlib.Path(__file__).parent.parent

from threading import Timer, currentThread

class MetricsTimer(object):
    def __init__(self, interval, function, *args, **kwargs):
        self._timer     = None
        self.interval   = interval
        self.function   = function
        self.args       = args
        self.kwargs     = kwargs
        self.is_running = False
        self.start()

    def _run(self):
        self.is_running = False
        self.start()
        self.function(*self.args, **self.kwargs)

    def start(self):
        if not self.is_running:
            self._timer = Timer(self.interval, self._run)
            self._timer.start()
            self.is_running = True

    def stop(self):
        self._timer.cancel()
        self.is_running = False

def cache_metrics(cache, lookup_type, statsd, hostname):
    if hasattr(cache, 'hit_miss_ratio'):
        hitratio = cache.hit_miss_ratio
        for metric in hitratio:
            statsd.gauge('%s.%i.hitratio.%s'%(hostname, os.getpid(),metric), hitratio[metric])
    if hasattr(cache, 'profiling'):
        profiling = cache.profiling
        for metric in profiling:
            statsd.gauge('%s.%i.profiling.%s'%(hostname, os.getpid(),metric), profiling[metric])

    if 'items' in lookup_type:
        for ltype in lookup_type['items']:
            if 'nb' in lookup_type['items'][ltype]:
                tvalue = lookup_type['items'][ltype]['nb']
                lookup_type['items'][ltype]['nb'] -= tvalue
            else:
                tvalue = 0
            if 'size' in lookup_type['items'][ltype]:
                tsize = lookup_type['items'][ltype]['size']
            else:
                tsize = 0

            statsd.gauge('%s.%i.lookuptype.items.%s.request_nb'%(hostname, os.getpid(),ltype), tvalue, delta=True)
            #statsd.incr('%s.%i.lookuptype.items.%s.request_nb'%(hostname, os.getpid(),ltype), tvalue)
        
            statsd.gauge('%s.%i.lookuptype.items.%s.size'%(hostname, os.getpid(),ltype), tsize)

    if 'not_allowed' in lookup_type:
        for naltype in lookup_type['not_allowed']:
            natvalue = lookup_type['not_allowed'][naltype]
            lookup_type['not_allowed'][naltype] -= natvalue
            statsd.gauge('%s.%i.lookuptype.not_allowed.%s.request_nb'%(hostname, os.getpid(),naltype), natvalue, delta=True)

    if 'env' in lookup_type:
        for env in lookup_type['env']:
            if 'items' in lookup_type['env'][env]:
                for ltype in lookup_type['env'][env]['items']:
                    if 'nb' in lookup_type['env'][env]['items'][ltype]:
                        tvalue = lookup_type['env'][env]['items'][ltype]['nb']
                        lookup_type['env'][env]['items'][ltype]['nb'] -= tvalue

                        statsd.gauge('%s.%i.lookuptype.env.%s.items.%s.request_nb'%(hostname, os.getpid(), env, ltype), tvalue, delta=True)

            if 'pmodules' in lookup_type['env'][env]:
                for pmodule in lookup_type['env'][env]['pmodules']:
                    if 'items' in lookup_type['env'][env]['pmodules'][pmodule]:
                        for ltype in lookup_type['env'][env]['pmodules'][pmodule]['items']:
                            if 'nb' in lookup_type['env'][env]['pmodules'][pmodule]['items'][ltype]:
                                tvalue = lookup_type['env'][env]['pmodules'][pmodule]['items'][ltype]['nb']
                                lookup_type['env'][env]['pmodules'][pmodule]['items'][ltype]['nb'] -= tvalue
                                statsd.gauge('%s.%i.lookuptype.env.%s.pmodules.%s.items.%s.request_nb'%(hostname, os.getpid(), env, pmodule, ltype), tvalue, delta=True)
  
        

    statsd.gauge('%s.%i.profiling.memory.used'%(hostname, os.getpid()), memory_usage())


async def nocache(uri, request):
    auth = "%s:%s"%(request.app['config']['foreman']['user'], request.app['config']['foreman']['password'])
    b64_auth = base64.b64encode(auth.encode('ascii')).decode('ascii')
    headers={"Authorization": "Basic %s"%b64_auth,
             'User-Agent': 'foreman-lookup-cache'}

    sslcontext = load_sslcontext(request)

    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get('%s'%uri, ssl=sslcontext, allow_redirects=False) as response:

                json = await response.json()
    except aiohttp.ClientConnectorError as e:
        print("Cannot connect to %s %s"%(uri,e))
        pass

    return json


async def fget(uri, cache, request, ttl=3600):
    cache_url = hashlib.md5(quote(uri).encode()).hexdigest()
    is_cached = await cache.exists(cache_url)
    if is_cached:
        result = await cache.get(cache_url)
        if result is not None:
            return result
    json = {}
    json['subtotal'] = -1
    #auth = "%s:%s"%(user, password)
    auth = "%s:%s"%(request.app['config']['foreman']['user'], request.app['config']['foreman']['password'])
    b64_auth = base64.b64encode(auth.encode('ascii')).decode('ascii')
    headers={"Authorization": "Basic %s"%b64_auth,
             'User-Agent': 'foreman-lookup-cache'}

    sslcontext = load_sslcontext(request)

    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get('%s'%uri, ssl=sslcontext, allow_redirects=False) as response:

                json = await response.json()
                if response.status in RESPONSE_OK:
                    await cache.set(cache_url, json, ttl=ttl)
    except aiohttp.ClientConnectorError as e:
        print("Cannot connect to %s %s"%(uri,e))
        pass

    return json


#@cached(ttl=60, serializer=JsonSerializer())
#async def fgetp1(request):
async def fgetp1(request, cache, ttl=60):

    params = {}

    for qstring in request.rel_url.query:
        params[qstring] = request.rel_url.query[qstring]

    params['per_page'] = 1
    path = request.rel_url.path

    #url = urlencode('%s://%s:%s'%(request.app['config']['foreman']['scheme'], request.app['config']['foreman']['host'], request.app['config']['foreman']['port']))
    url = '%s://%s:%s'%(request.app['config']['foreman']['scheme'], request.app['config']['foreman']['host'], request.app['config']['foreman']['port'])

    qstr = urlencode(params)
    clean_url = '%s%s?%s'%(url, path, qstr)
    cache_url = hashlib.md5(clean_url.encode()).hexdigest()
    print(cache_url)

    is_cached = await cache.exists(cache_url)
    if is_cached:
        result = await cache.get(cache_url)
        if result is not None:
            return result['subtotal']

    json = {}
    json['subtotal'] = -1
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
                    await cache.set(cache_url, json, ttl=ttl)
    except aiohttp.ClientConnectorError as e:
        print("Cannot connect to %s %s"%(url,e))
        pass

    return json['subtotal']

async def method(request):
    cache = request.app['cache']
    lookup_type = request.app['lookup_type']
    ttl = request.app['config']['cache']['ttl']
    #uri = urlencode('%s://%s:%s%s'%(request.app['config']['foreman']['scheme'], request.app['config']['foreman']['host'], request.app['config']['foreman']['port'], request.rel_url))
    uri = '%s://%s:%s%s'%(request.app['config']['foreman']['scheme'], request.app['config']['foreman']['host'], request.app['config']['foreman']['port'], request.rel_url)
    result = {}

    ## metrics management - TODO create dedicated func

    if request.match_info['item'] not in request.app['config']['allowed_items']:
        if 'not_allowed' not in lookup_type:
            lookup_type['not_allowed'] = {}
            lookup_type['not_allowed'][request.match_info['item']] = 1
        else:
            if request.match_info['item'] not in lookup_type['not_allowed']:
                lookup_type['not_allowed'][request.match_info['item']] = 1
            else:
                lookup_type['not_allowed'][request.match_info['item']] = +1
        return web.Response(status=404)

    if 'items' not in lookup_type:
        lookup_type['items'] = {}

    if request.match_info['item'] not in lookup_type['items']:
        lookup_type['items'][request.match_info['item']] = {}
        lookup_type['items'][request.match_info['item']]['nb'] = 1
        #lookup_type['items'][request.match_info['item']]['size'] = len(str(foreman_lookup).encode('utf-8'))
    else:
        lookup_type['items'][request.match_info['item']]['nb'] += 1
        #lookup_type['items'][request.match_info['item']]['size'] = (lookup_type['items'][request.match_info['item']]['size'] + len(str(foreman_lookup).encode('utf-8'))) / 2

    if 'Env' in request.headers:
        if 'env' not in lookup_type:
            lookup_type['env'] = {}
        if request.headers['Env'] not in lookup_type['env']:
            lookup_type['env'][request.headers['Env']] = {}
            lookup_type['env'][request.headers['Env']]['items'] = {}
            lookup_type['env'][request.headers['Env']]['items'][request.match_info['item']] ={}
            lookup_type['env'][request.headers['Env']]['items'][request.match_info['item']]['nb'] = 1
        else:
            if request.match_info['item'] not in lookup_type['env'][request.headers['Env']]['items']: 
                lookup_type['env'][request.headers['Env']]['items'][request.match_info['item']] ={}
                lookup_type['env'][request.headers['Env']]['items'][request.match_info['item']]['nb'] = 1
            else:
                lookup_type['env'][request.headers['Env']]['items'][request.match_info['item']]['nb'] += 1
        if 'Puppet-Module' in request.headers:
            if 'pmodules' not in lookup_type['env'][request.headers['Env']]:
                lookup_type['env'][request.headers['Env']]['pmodules'] = {}
            if request.headers['Puppet-Module'] not in lookup_type['env'][request.headers['Env']]['pmodules']:
                lookup_type['env'][request.headers['Env']]['pmodules'][request.headers['Puppet-Module']] = {}
                lookup_type['env'][request.headers['Env']]['pmodules'][request.headers['Puppet-Module']]['items'] = {}
                lookup_type['env'][request.headers['Env']]['pmodules'][request.headers['Puppet-Module']]['items'][request.match_info['item']] = {}
                lookup_type['env'][request.headers['Env']]['pmodules'][request.headers['Puppet-Module']]['items'][request.match_info['item']]['nb'] = 1
            else:
                if request.match_info['item'] not in lookup_type['env'][request.headers['Env']]['pmodules'][request.headers['Puppet-Module']]['items']:
                    lookup_type['env'][request.headers['Env']]['pmodules'][request.headers['Puppet-Module']]['items'][request.match_info['item']] = {}
                    lookup_type['env'][request.headers['Env']]['pmodules'][request.headers['Puppet-Module']]['items'][request.match_info['item']]['nb'] = 1
                else:
                    lookup_type['env'][request.headers['Env']]['pmodules'][request.headers['Puppet-Module']]['items'][request.match_info['item']]['nb'] += 1

    if request.match_info['item'] in SPECIAL_ITEMS:
        foreman_lookup = await fget(uri, cache, request, ttl=ttl)
        if 'subtotal' in foreman_lookup:
            if foreman_lookup['subtotal'] < 0:
                return web.Response(status=502)

        return web.json_response(foreman_lookup)

    if request.match_info['item'] not in SUPPORTED_ITEMS:
        return web.json_response(await nocache(uri, request))  

    subtotalp1 = await fgetp1(request, cache)

    response = await fget(uri, cache, request, ttl=ttl)

    cache_url = hashlib.md5(quote(uri).encode()).hexdigest()
    in_cache = await cache.exists(cache_url)
    if 'subtotal' in response:
        if response['subtotal'] != subtotalp1 and in_cache and subtotalp1 > -1:
            print("need to reload from foreman: %s / %s"%(response['subtotal'], subtotalp1))
            del_id = await cache.delete(cache_url)
            print("cache remove for %s id: %s"%(uri, del_id))

    foreman_lookup = await fget(uri, cache, request, ttl=ttl)

    if 'subtotal' in foreman_lookup:
        if foreman_lookup['subtotal'] < 0:
            return web.Response(status=502)

    return web.json_response(foreman_lookup)

async def cache():
    conf = load_config(PROJ_ROOT / 'config' / 'config-gunicorn.yml')

    logging.basicConfig(level=logging.DEBUG)
    app = web.Application()

    app.router.add_route('GET', "/api/v2/{item}", method)
    app.router.add_route('GET', "/api/v2/{item}/{domain}", method)
    app.router.add_route('GET', "/api/{item}", method)
    app.router.add_route('GET', "/api/{item}/{domain}", method)
    memcached_host = conf['cache']['memcached_host']
    memcached_port = conf['cache']['memcached_port']
    #cache = Cache(plugins=[HitMissRatioPlugin(), TimingPlugin()])
    lookup_type = {}
    cache = Cache(Cache.MEMCACHED, endpoint=memcached_host, port=memcached_port, serializer=JsonSerializer(), plugins=[HitMissRatioPlugin(), TimingPlugin()])

    if 'statsd' in conf:
        if conf['statsd']['enable']:
            hostname = socket.gethostname().split('.', 1)[0]
            c = statsd.StatsClient(conf['statsd']['host'], conf['statsd']['port'], prefix=conf['statsd']['prefix'])
            t = MetricsTimer(conf['statsd']['interval'], cache_metrics, cache, lookup_type, c, hostname)

    app['config'] = conf

    user, password, realm = conf['authentication']['user'], conf['authentication']['password'], conf['authentication']['realm']
    await setup(app, AllowedHosts(conf['allowed_hosts']), BasicAuth(user, password, realm))
    app['cache'] = cache
    app['lookup_type'] = lookup_type
    return app
