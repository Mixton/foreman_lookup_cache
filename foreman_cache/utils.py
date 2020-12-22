import yaml


def load_config(fname):
    with open(fname, 'rt') as f:
        data = yaml.full_load(f)
    # TODO: add config validation
    return data

def load_sslcontext(request):

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

    return sslcontext

def memory_usage():
    # return the memory usage in Bytes
    import psutil
    import os
    process = psutil.Process(os.getpid())
    #mem = process.memory_info()
    mem = psutil.virtual_memory().used
    return mem
