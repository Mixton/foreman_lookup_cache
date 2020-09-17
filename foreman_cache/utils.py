import yaml


def load_config(fname):
    with open(fname, 'rt') as f:
        data = yaml.full_load(f)
    # TODO: add config validation
    return data
