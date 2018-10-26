# (C) Datadog, Inc. 2018
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)

from __future__ import division

from datadog_checks.checks import AgentCheck
from datadog_checks.base import ConfigurationError
from datadog_checks.config import is_affirmative

from six import iteritems

try:
    import pymqi
except ImportError:
    pymqi = None

from . import errors, metrics


class IbmMqCheck(AgentCheck):

    METRIC_PREFIX = 'ibm_mq'

    SERVICE_CHECK = 'ibm_mq.can_connect'

    QUEUE_MANAGER_SERVICE_CHECK = 'ibm_mq.queue_manager'
    QUEUE_SERVICE_CHECK = 'ibm_mq.queue'

    def check(self, instance):
        if not pymqi:
            self.log.error("You need to install pymqi")
            raise errors.PymqiException("You need to install pymqi")

        config = IBMMQConfig(instance)

        config.check_properly_configured()

        tags = [
            "queue_manager:{}".format(config.queue_manager_name),
            "host:{}".format(config.host),
            "port:{}".format(config.port),
            "channel:{}".format(config.channel)
        ]

        tags += config.custom_tags

        queue_manager = self.get_queue_manager_connection(config)

        self.queue_manager_stats(queue_manager, tags)
        self.channel_stats(queue_manager, tags)

        for queue_name in config.queues:
            queue_tags = tags + ["queue:{}".format(queue_name)]
            try:
                queue = pymqi.Queue(queue_manager, queue_name)
                self.queue_stats(queue, queue_tags)
                self.service_check(self.QUEUE_SERVICE_CHECK, AgentCheck.OK, queue_tags)
            except Exception as e:
                self.warning('Cannot connect to queue {}: {}'.format(queue_name, e))
                self.service_check(self.QUEUE_SERVICE_CHECK, AgentCheck.CRITICAL, queue_tags)

    def queue_manager_stats(self, queue_manager, tags):
        for mname, pymqi_value in iteritems(metrics.QUEUE_MANAGER_METRICS):
            try:
                m = queue_manager.inquire(pymqi_value)

                mname = '{}.queue_manager.{}'.format(self.METRIC_PREFIX, mname)
                self.log.info("name={} value={} tags={}".format(mname, m, tags))
                self.gauge(mname, m, tags=tags)
                self.service_check(self.QUEUE_MANAGER_SERVICE_CHECK, AgentCheck.OK, tags)
            except pymqi.Error as e:
                self.log.warning("Error getting queue manager stats: {}".format(e))
                self.service_check(self.QUEUE_MANAGER_SERVICE_CHECK, AgentCheck.CRITICAL, tags)

    def queue_stats(self, queue, tags):
        for mname, pymqi_value in iteritems(metrics.QUEUE_METRICS):
            try:
                m = queue.inquire(pymqi_value)
                mname = '{}.queue.{}'.format(self.METRIC_PREFIX, mname)
                self.log.info("name={} value={} tags={}".format(mname, m, tags))
                self.gauge(mname, m, tags=tags)
            except pymqi.Error as e:
                self.log.info("Error getting queue stats: {}".format(e))

        for mname, func in iteritems(metrics.QUEUE_METRICS_FUNCTIONS):
            try:
                m = func(queue)
                mname = '{}.queue.{}'.format(self.METRIC_PREFIX, mname)
                self.log.info("name={} value={} tags={}".format(mname, m, tags))
                self.gauge(mname, m, tags=tags)
            except pymqi.Error as e:
                self.log.info("Error getting queue stats: {}".format(e))

    def channel_stats(self, queue_manager, tags):
        for mname, pymqi_value in iteritems(metrics.CHANNEL_METRICS):
            try:
                m = queue_manager.inquire(pymqi_value)
                mname = '{}.channel.{}'.format(self.METRIC_PREFIX, mname)
                self.log.info("name={} value={} tags={}".format(mname, m, tags))
                self.gauge(mname, m, tags=tags)
            except pymqi.Error as e:
                self.log.info("Error getting queue stats: {}".format(e))

    def get_queue_manager_connection(self, config):
        if config.ssl:
            return self.get_ssl_connection(config)
        else:
            return self.get_normal_connection(config)

    def get_normal_connection(self, config):
        try:
            if config.username and config.password:
                self.log.debug("connecting with username and password")
                queue_manager = pymqi.connect(
                    config.queue_manager_name,
                    config.channel,
                    config.host_and_port,
                    config.username,
                    config.password
                )
            elif username:
                self.log.debug("connecting with username only")
                queue_manager = pymqi.connect(
                    config.queue_manager_name,
                    config.channel,
                    config.host_and_port,
                    config.username,
                    config.password
                )
            else:
                self.log.debug("connecting without a username and password")
                queue_manager = pymqi.connect(
                    config.queue_manager_name,
                    config.channel,
                    config.host_and_port,
                )
            # if we've reached here, send the service check
            self.service_check(self.SERVICE_CHECK, AgentCheck.OK, tags)
        except Exception as e:
            self.warning("cannot connect to queue manager: {}".format(e))
            self.service_check(self.SERVICE_CHECK, AgentCheck.CRITICAL, tags)
            # if it cannot connect to the queue manager, the rest of the check won't work
            # abort the check here
            raise

        return queue_manager

    def get_ssl_connection(self, config):
        try:
            cd = pymqi.CD()
            cd.ChannelName = config.channel
            cd.ConnectionName = self.host_and_port
            cd.ChannelType = pymqi.CMQC.MQCHT_CLNTCONN
            cd.TransportType = pymqi.CMQC.MQXPT_TCP
            cd.SSLCipherSpec = config.ssl_cipher_spec

            sco = pymqi.SCO()
            sco.KeyRepository = config.key_repo_location

            queue_manager = pymqi.QueueManager(None)
            queue_manager.connect_with_options(config.queue_manager, cd, sco)
        except Exception as e:
            self.warning("cannot connect to queue manager: {}".format(e))
            self.service_check(self.SERVICE_CHECK, AgentCheck.CRITICAL, tags)
            # if it cannot connect to the queue manager, the rest of the check won't work
            # abort the check here
            raise

        return queue_manager


class IBMMQConfig:
    def __init__(self, instance):
        self.channel = instance.get('channel')
        self.queue_manager_name = instance.get('queue_manager', 'default')

        self.host = instance.get('host')
        self.port = instance.get('port')
        self.host_and_port = "{}({})".format(host, port)

        self.username = instance.get('username')
        self.password = instance.get('password')

        self.queues = instance.get('queues', [])

        self.custom_tags = instance.get('tags', [])

        self.ssl = is_affirmative(instance.get('ssl_auth', False))

        self.ssl_cipher_spec = instance.get('ssl_cipher_spec', 'TLS_RSA_WITH_AES_256_CBC_SHA')

        self.key_repository_location = instance.get(
            'key_repository_location',
            '/var/mqm/ssl-db/client/KeyringClient'
        )

    def check_properly_configured(self):
        if not self.channel or not self.queue_manager_name or not self.host or not self.port:
            msg = "channel, queue_manager, host and port are all required configurations"
            raise ConfigurationError(msg)

    def get_tags(self):
        return [
            "queue_manager:{}".format(self.queue_manager_name),
            "host:{}".format(self.host),
            "port:{}".format(self.port),
            "channel:{}".format(self.channel)
        ]
