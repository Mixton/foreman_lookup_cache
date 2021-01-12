import multiprocessing

#bind = "127.0.0.1:8223"
workers = multiprocessing.cpu_count()
#workers = 1
worker_class = 'aiohttp.GunicornWebWorker'
keyfile = 'ssl/foreman_cache-localhost.key'
certfile = 'ssl/foreman_cache-localhost.crt'
accesslog = 'log/access.log'
access_log_format = '%a %t "%r" %s %b "%{Referer}i" "%{User-Agent}i" %Tf' 
errorlog = 'log/error.log'
log_level = 'debug'
