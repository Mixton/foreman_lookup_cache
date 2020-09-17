import asyncio
import logging
import json
import ssl
from aiohttp_remotes import BasicAuth, setup
from datetime import datetime
from aiohttp import web
from aiocache import cached
from aiocache.serializers import JsonSerializer
from random import randrange

async def method(request):
    ## here how to get query parameters
    #param1 = request.rel_url.query['name']
    #param2 = request.rel_url.query['age']
    #result = "name: {}, age: {}".format(param1, param2)
    result = {}
    if request.match_info['item']:
        if int(request.rel_url.query['per_page']) == 1:
            with open('hosts-perpage1.json') as json_file:
                result = json.load(json_file)
        else:
            await asyncio.sleep(randrange(0, 20))
            with open('hosts-perpagefull.json') as json_file:
                result = json.load(json_file)
    #return web.json_response(await time())
    #return web.Response(text=str(result))
    return web.json_response(result)

if __name__ == '__main__':
    app = web.Application()
    app.router.add_route('GET', "/api/v2/{item}", method)
    app.router.add_route('GET', "/api/{item}", method)
    logging.basicConfig(level=logging.DEBUG)
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_verify_locations('ssl/foreman_cache-localhost.crt', 'ssl/foreman_cache-localhost.key')
    ssl_context.load_cert_chain('ssl/foreman_cache-localhost.crt', 'ssl/foreman_cache-localhost.key')
    setup(app, BasicAuth('foreman', 'foreman', 'fback'))
    web.run_app(app,host='localhost', port=8233, ssl_context=ssl_context)
