import os
import logging.config

logging.config.fileConfig('logging.conf', disable_existing_loggers=False)
log = logging.getLogger(__name__)
log.setLevel(logging.WARNING)

config = {}

# List of all required env variables
env_vars = [
    "JWT_PRIVATE_KEY_PATH",
    "JWT_PUBLIC_KEY_PATH"
]

# Lets check them and then assign them
for var in env_vars:
    try:
        assert len(os.environ.get(var, "")) > 0, f"Environment variable '{var}' not set!"
        config[var] = os.environ[var]
    except AssertionError as e:
        raise e

# configure keys
with open(config['JWT_PRIVATE_KEY_PATH']) as file:
    config['JWT_PRIVATE_KEY'] = file.read()

with open(config['JWT_PUBLIC_KEY_PATH']) as file:
    config['JWT_PUBLIC_KEY'] = file.read()

config['JWT_ALGORITHM'] = 'RS256'
