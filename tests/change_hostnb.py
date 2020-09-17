import json

def inc_hosts(path):
    with open(path, 'rt') as f:
        queryfile = json.load(f)
    queryfile['subtotal'] += 1
    print(queryfile['subtotal'])
    with open(path, 'w') as f:
        f.write(json.dumps(queryfile))

if __name__ == '__main__':
    inc_hosts('hosts-perpage1.json')
    inc_hosts('hosts-perpagefull.json')
