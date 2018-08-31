# (C) Datadog, Inc. 2018
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)

from __future__ import division

from datadog_checks.checks import AgentCheck
from datadog_checks.base import ConfigurationError

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

        channel = instance.get('channel')
        queue_manager_name = instance.get('queue_manager', 'default')

        host = instance.get('host')
        port = instance.get('port')

        if not channel or not queue_manager_name or not host or not port:
            msg = "channel, queue_manager, host and port are all required configurations"
            raise ConfigurationError(msg)

        host_and_port = "{}({})".format(host, port)

        username = instance.get('username')
        password = instance.get('password')

        custom_tags = instance.get('tags', [])

        tags = [
            "queue_manager:{}".format(queue_manager_name),
            "host:{}".format(host),
            "port:{}".format(port),
            "channel:{}".format(channel)
        ]

        tags += custom_tags

        try:
            if username and password:
                self.log.debug("connecting with username and password")
                queue_manager = pymqi.connect(queue_manager_name, channel, host_and_port, username, password)
            elif username:
                self.log.debug("connecting with username only")
                queue_manager = pymqi.connect(queue_manager_name, channel, host_and_port, username, password)
            else:
                self.log.debug("connecting without a username and password")
                queue_manager = pymqi.connect(queue_manager_name, channel, host_and_port)
            # if we've reached here, send the service check
            self.service_check(self.SERVICE_CHECK, AgentCheck.OK, tags)
        except Exception as e:
            self.warning("cannot connect to queue manager: {}".format(e))
            self.service_check(self.SERVICE_CHECK, AgentCheck.CRITICAL, tags)
            # if it cannot connect to the queue manager, the rest of the check won't work
            # abort the check here
            raise

        self.queue_manager_stats(queue_manager, tags)
        self.channel_stats(queue_manager, tags)

        queues = instance.get('queues', [])

        for queue_name in queues:
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
