import yaml

settings = None

def get():
    global settings
    return settings

def load():
    global settings
    try:
        settings = yaml.load(open('settings.yaml'))
    except IOError:
        settings = {}

def save():
    global settings
    with open('settings.yaml', 'w') as f:
        f.write(yaml.dump(settings))

load()
