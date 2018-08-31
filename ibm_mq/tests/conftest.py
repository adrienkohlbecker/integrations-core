# (C) Datadog, Inc. 2018
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)

import os
import pytest
import subprocess
import copy

from tempfile import mkdtemp

from datadog_checks.dev import docker_run  # , temp_dir
from datadog_checks.ibm_mq import IbmMqCheck

from . import common


@pytest.fixture
def check():
    return IbmMqCheck('ibm_mq', {}, {})


@pytest.fixture
def instance():
    return common.INSTANCE


@pytest.fixture
def seed_data():
    publish = os.path.join(common.HERE, 'python', 'publish.py')
    consume = os.path.join(common.HERE, 'python', 'consume.py')

    env = copy.deepcopy(os.environ)

    os.environ['HOST'] = common.HOST
    os.environ['PORT'] = common.PORT
    os.environ['USERNAME'] = common.USERNAME
    os.environ['PASSWORD'] = common.PASSWORD
    os.environ['CHANNEL'] = common.CHANNEL
    os.environ['QUEUE_MANAGER'] = common.QUEUE_MANAGER
    os.environ['QUEUE'] = common.QUEUE

    subprocess.check_call(['python', publish])
    subprocess.check_call(['python', consume])

    # reset the environment
    os.environ = env


@pytest.fixture(scope='session')
def spin_up_ibmmq():

    if common.MQ_VERSION == '9':
        log_pattern = "AMQ5026I: The listener 'DEV.LISTENER.TCP' has started. ProcessId"
    elif common.MQ_VERSION == '8':
        log_pattern = r".*QMNAME\(datadog\)\s*STATUS\(Running\).*"

    def down():
        pass

    temp = mkdtemp()

    # with temp_dir() as temp:
    env = {
        'COMPOSE_DIR': common.COMPOSE_DIR,
        'TEMP_DIR': temp
    }

    with docker_run(
        common.COMPOSE_FILE_PATH,
        env_vars=env,
        log_patterns=log_pattern,
        # down=down,
        sleep=10
    ):
        yield
