# stdlib
import urlparse

# 3rd party
import requests

from checks import CheckException
from checks.prometheus_check import PrometheusCheck
from config import _is_affirmative
from util import headers

# This list is up-to-date with Gitlab v10.3
default_metrics = [
    # Metrics from regular prometheus endpoint
    # Get this with `curl http://localhost:9090/metrics | grep -v "^#" | cut -d" " -f1 | cut -d"{" -f1 | sort | uniq`
    'go_gc_duration_seconds',
    'go_gc_duration_seconds_count',
    'go_gc_duration_seconds_sum',
    'go_goroutines',
    'go_memstats_alloc_bytes',
    'go_memstats_alloc_bytes_total',
    'go_memstats_buck_hash_sys_bytes',
    'go_memstats_frees_total',
    'go_memstats_gc_cpu_fraction',
    'go_memstats_gc_sys_bytes',
    'go_memstats_heap_alloc_bytes',
    'go_memstats_heap_idle_bytes',
    'go_memstats_heap_inuse_bytes',
    'go_memstats_heap_objects',
    'go_memstats_heap_released_bytes',
    'go_memstats_heap_sys_bytes',
    'go_memstats_last_gc_time_seconds',
    'go_memstats_lookups_total',
    'go_memstats_mallocs_total',
    'go_memstats_mcache_inuse_bytes',
    'go_memstats_mcache_sys_bytes',
    'go_memstats_mspan_inuse_bytes',
    'go_memstats_mspan_sys_bytes',
    'go_memstats_next_gc_bytes',
    'go_memstats_other_sys_bytes',
    'go_memstats_stack_inuse_bytes',
    'go_memstats_stack_sys_bytes',
    'go_memstats_sys_bytes',
    'go_threads',
    'http_request_duration_microseconds',
    'http_request_duration_microseconds_count',
    'http_request_duration_microseconds_sum',
    'http_request_size_bytes',
    'http_request_size_bytes_count',
    'http_request_size_bytes_sum',
    'http_requests_total',
    'http_response_size_bytes',
    'http_response_size_bytes_count',
    'http_response_size_bytes_sum',
    'process_cpu_seconds_total',
    'process_max_fds',
    'process_open_fds',
    'process_resident_memory_bytes',
    'process_start_time_seconds',
    'process_virtual_memory_bytes',
    'prometheus_build_info',
    'prometheus_config_last_reload_successful',
    'prometheus_config_last_reload_success_timestamp_seconds',
    'prometheus_engine_queries',
    'prometheus_engine_queries_concurrent_max',
    'prometheus_engine_query_duration_seconds',
    'prometheus_engine_query_duration_seconds_count',
    'prometheus_engine_query_duration_seconds_sum',
    'prometheus_evaluator_duration_seconds',
    'prometheus_evaluator_duration_seconds_count',
    'prometheus_evaluator_duration_seconds_sum',
    'prometheus_evaluator_iterations_missed_total',
    'prometheus_evaluator_iterations_skipped_total',
    'prometheus_evaluator_iterations_total',
    'prometheus_local_storage_checkpoint_duration_seconds_count',
    'prometheus_local_storage_checkpoint_duration_seconds_sum',
    'prometheus_local_storage_checkpointing',
    'prometheus_local_storage_checkpoint_last_duration_seconds',
    'prometheus_local_storage_checkpoint_last_size_bytes',
    'prometheus_local_storage_checkpoint_series_chunks_written_count',
    'prometheus_local_storage_checkpoint_series_chunks_written_sum',
    'prometheus_local_storage_chunk_ops_total',
    'prometheus_local_storage_chunks_to_persist',
    'prometheus_local_storage_fingerprint_mappings_total',
    'prometheus_local_storage_inconsistencies_total',
    'prometheus_local_storage_indexing_batch_duration_seconds',
    'prometheus_local_storage_indexing_batch_duration_seconds_count',
    'prometheus_local_storage_indexing_batch_duration_seconds_sum',
    'prometheus_local_storage_indexing_batch_sizes',
    'prometheus_local_storage_indexing_batch_sizes_count',
    'prometheus_local_storage_indexing_batch_sizes_sum',
    'prometheus_local_storage_indexing_queue_capacity',
    'prometheus_local_storage_indexing_queue_length',
    'prometheus_local_storage_ingested_samples_total',
    'prometheus_local_storage_maintain_series_duration_seconds',
    'prometheus_local_storage_maintain_series_duration_seconds_count',
    'prometheus_local_storage_maintain_series_duration_seconds_sum',
    'prometheus_local_storage_memory_chunkdescs',
    'prometheus_local_storage_memory_chunks',
    'prometheus_local_storage_memory_dirty_series',
    'prometheus_local_storage_memory_series',
    'prometheus_local_storage_non_existent_series_matches_total',
    'prometheus_local_storage_open_head_chunks',
    'prometheus_local_storage_out_of_order_samples_total',
    'prometheus_local_storage_persistence_urgency_score',
    'prometheus_local_storage_persist_errors_total',
    'prometheus_local_storage_queued_chunks_to_persist_total',
    'prometheus_local_storage_rushed_mode',
    'prometheus_local_storage_series_chunks_persisted_bucket',
    'prometheus_local_storage_series_chunks_persisted_count',
    'prometheus_local_storage_series_chunks_persisted_sum',
    'prometheus_local_storage_series_ops_total',
    'prometheus_local_storage_started_dirty',
    'prometheus_local_storage_target_heap_size_bytes',
    'prometheus_notifications_alertmanagers_discovered',
    'prometheus_notifications_dropped_total',
    'prometheus_notifications_queue_capacity',
    'prometheus_notifications_queue_length',
    'prometheus_rule_evaluation_failures_total',
    'prometheus_sd_azure_refresh_duration_seconds',
    'prometheus_sd_azure_refresh_duration_seconds_count',
    'prometheus_sd_azure_refresh_duration_seconds_sum',
    'prometheus_sd_azure_refresh_failures_total',
    'prometheus_sd_consul_rpc_duration_seconds',
    'prometheus_sd_consul_rpc_duration_seconds_count',
    'prometheus_sd_consul_rpc_duration_seconds_sum',
    'prometheus_sd_consul_rpc_failures_total',
    'prometheus_sd_dns_lookup_failures_total',
    'prometheus_sd_dns_lookups_total',
    'prometheus_sd_ec2_refresh_duration_seconds',
    'prometheus_sd_ec2_refresh_duration_seconds_count',
    'prometheus_sd_ec2_refresh_duration_seconds_sum',
    'prometheus_sd_ec2_refresh_failures_total',
    'prometheus_sd_file_read_errors_total',
    'prometheus_sd_file_scan_duration_seconds',
    'prometheus_sd_file_scan_duration_seconds_count',
    'prometheus_sd_file_scan_duration_seconds_sum',
    'prometheus_sd_gce_refresh_duration',
    'prometheus_sd_gce_refresh_duration_count',
    'prometheus_sd_gce_refresh_duration_sum',
    'prometheus_sd_gce_refresh_failures_total',
    'prometheus_sd_kubernetes_events_total',
    'prometheus_sd_marathon_refresh_duration_seconds',
    'prometheus_sd_marathon_refresh_duration_seconds_count',
    'prometheus_sd_marathon_refresh_duration_seconds_sum',
    'prometheus_sd_marathon_refresh_failures_total',
    'prometheus_sd_openstack_refresh_duration_seconds',
    'prometheus_sd_openstack_refresh_duration_seconds_count',
    'prometheus_sd_openstack_refresh_duration_seconds_sum',
    'prometheus_sd_openstack_refresh_failures_total',
    'prometheus_sd_triton_refresh_duration_seconds',
    'prometheus_sd_triton_refresh_duration_seconds_count',
    'prometheus_sd_triton_refresh_duration_seconds_sum',
    'prometheus_sd_triton_refresh_failures_total',
    'prometheus_target_interval_length_seconds',
    'prometheus_target_interval_length_seconds_count',
    'prometheus_target_interval_length_seconds_sum',
    'prometheus_target_scrape_pool_sync_total',
    'prometheus_target_scrapes_exceeded_sample_limit_total',
    'prometheus_target_skipped_scrapes_total',
    'prometheus_target_sync_length_seconds',
    'prometheus_target_sync_length_seconds_count',
    'prometheus_target_sync_length_seconds_sum',
    'prometheus_treecache_watcher_goroutines',
    'prometheus_treecache_zookeeper_failures_total',

    # Metrics from the Experimental Prometheus endpoint
    # Get this with `curl -k https://localhost/-/metrics | grep -v "^#" | cut -d" " -f1 | cut -d"{" -f1 | sort | uniq`
    'db_ping_latency_seconds',
    'db_ping_success',
    'db_ping_timeout',
    'gitlab_cache_operation_duration_seconds_bucket',
    'gitlab_cache_operation_duration_seconds_count',
    'gitlab_cache_operation_duration_seconds_sum',
    'gitlab_rails_queue_duration_seconds_bucket',
    'gitlab_rails_queue_duration_seconds_count',
    'gitlab_rails_queue_duration_seconds_sum',
    'gitlab_sql_duration_seconds_bucket',
    'gitlab_sql_duration_seconds_count',
    'gitlab_sql_duration_seconds_sum',
    'gitlab_transaction_allocated_memory_bytes_bucket',
    'gitlab_transaction_allocated_memory_bytes_count',
    'gitlab_transaction_allocated_memory_bytes_sum',
    'gitlab_transaction_cache_read_hit_count_total',
    'gitlab_transaction_duration_seconds_bucket',
    'gitlab_transaction_duration_seconds_count',
    'gitlab_transaction_duration_seconds_sum',
    'gitlab_transaction_new_redis_connections_total',
    'gitlab_transaction_rails_queue_duration',
    'gitlab_transaction_view_duration_total',
    'gitlab_view_rendering_duration_seconds_bucket',
    'gitlab_view_rendering_duration_seconds_count',
    'gitlab_view_rendering_duration_seconds_sum',
    'http_request_duration_seconds_bucket',
    'http_request_duration_seconds_count',
    'http_request_duration_seconds_sum',
    'http_requests_total',
    'redis_cache_ping_latency_seconds',
    'redis_cache_ping_success',
    'redis_cache_ping_timeout',
    'redis_ping_latency_seconds',
    'redis_ping_success',
    'redis_ping_timeout',
    'redis_queues_ping_latency_seconds',
    'redis_queues_ping_success',
    'redis_queues_ping_timeout',
    'redis_shared_state_ping_latency_seconds',
    'redis_shared_state_ping_success',
    'redis_shared_state_ping_timeout',
    'ruby_file_descriptors_total',
    'ruby_gc_count',
    'ruby_gc_heap_allocatable_pages',
    'ruby_gc_heap_allocated_pages',
    'ruby_gc_heap_available_slots',
    'ruby_gc_heap_eden_pages',
    'ruby_gc_heap_final_slots',
    'ruby_gc_heap_free_slots',
    'ruby_gc_heap_live_slots',
    'ruby_gc_heap_marked_slots',
    'ruby_gc_heap_sorted_length',
    'ruby_gc_heap_swept_slots',
    'ruby_gc_heap_tomb_pages',
    'ruby_gc_major_gc_count',
    'ruby_gc_malloc_increase_bytes',
    'ruby_gc_malloc_increase_bytes_limit',
    'ruby_gc_minor_gc_count',
    'ruby_gc_oldmalloc_increase_bytes',
    'ruby_gc_oldmalloc_increase_bytes_limit',
    'ruby_gc_old_objects',
    'ruby_gc_old_objects_limit',
    'ruby_gc_remembered_wb_unprotected_objects',
    'ruby_gc_remembered_wb_unprotected_objects_limit',
    'ruby_gc_time_total',
    'ruby_gc_total_allocated_objects',
    'ruby_gc_total_allocated_pages',
    'ruby_gc_total_freed_objects',
    'ruby_gc_total_freed_pages',
    'ruby_memory_usage_total',
    'ruby_sampler_duration_seconds_bucket',
    'ruby_sampler_duration_seconds_count',
    'ruby_sampler_duration_seconds_sum',
    'unicorn_active_connections',
    'unicorn_queued_connections',
]

class GitlabCheck(PrometheusCheck):

    # Readiness signals ability to serve traffic, liveness that Gitlab is healthy overall
    ALLOWED_SERVICE_CHECKS = ['readiness', 'liveness']
    EVENT_TYPE = SOURCE_TYPE_NAME = 'gitlab'
    DEFAULT_CONNECT_TIMEOUT = 5
    DEFAULT_RECEIVE_TIMEOUT = 15

    PROMETHEUS_SERVICE_CHECK_NAME = 'gitlab.prometheus_endpoint_up'
    PROMETHEUS_INTERNAL_SERVICE_CHECK_NAME = 'gitlab.prometheus_internal_endpoint_up'

    """
    Collect Gitlab metrics from Prometheus and validates that the connectivity with Gitlab
    """
    def __init__(self, name, init_config, agentConfig, instances=None):
        super(GitlabCheck, self).__init__(name, init_config, agentConfig, instances)
        # Mapping from Prometheus metrics names to Datadog ones
        # For now it's a 1:1 mapping
        # TODO: mark some metrics as rate
        metrics = default_metrics

        allowed_metrics = init_config.get('allowed_metrics')
        if allowed_metrics:
            metrics += allowed_metrics

        metrics = list(set(metrics))

        self.metrics_mapper = dict(zip(metrics, metrics))
        self.NAMESPACE = 'gitlab'

    def check(self, instance):
        #### Metrics collection
        self._check_prometheus(instance)
        self._check_prometheus_internal(instance)

        #### Service check to check Gitlab's health endpoints
        for check_type in self.ALLOWED_SERVICE_CHECKS:
            self._check_health_endpoint(instance, check_type)

    def _check_prometheus(self, instance):
        endpoint = instance.get('prometheus_endpoint')
        if endpoint is None:
            raise CheckException("Unable to find prometheus_endpoint in config file.")

        # By default we send the buckets
        send_buckets = _is_affirmative(instance.get('send_histograms_buckets', True))

        try:
            self.process(endpoint, send_histograms_buckets=send_buckets, instance=instance)
            self.service_check(self.PROMETHEUS_SERVICE_CHECK_NAME, PrometheusCheck.OK)
        except requests.exceptions.ConnectionError as e:
            # Unable to connect to the metrics endpoint
            self.service_check(self.PROMETHEUS_SERVICE_CHECK_NAME, PrometheusCheck.CRITICAL,
                               message="Unable to retrieve Prometheus metrics from endpoint %s: %s" % (endpoint, e.message))

    def _check_prometheus_internal(self, instance):
        endpoint = instance.get('prometheus_endpoint_internal')
        if endpoint is None:
            return

        # By default we send the buckets
        send_buckets = _is_affirmative(instance.get('send_histograms_buckets', True))

        try:
            self.process(endpoint, send_histograms_buckets=send_buckets, instance=instance)
            self.service_check(self.PROMETHEUS_INTERNAL_SERVICE_CHECK_NAME, PrometheusCheck.OK)
        except requests.exceptions.ConnectionError as e:
            # Unable to connect to the metrics endpoint
            self.service_check(self.PROMETHEUS_INTERNAL_SERVICE_CHECK_NAME, PrometheusCheck.CRITICAL,
                               message="Unable to retrieve internal Prometheus metrics from endpoint %s: %s" % (endpoint, e.message))


    def _verify_ssl(self, instance):
        ## Load the ssl configuration
        ssl_params = {
            'ssl_cert_validation': _is_affirmative(instance.get('ssl_cert_validation', True)),
            'ssl_ca_certs': instance.get('ssl_ca_certs'),
        }

        for key, param in ssl_params.items():
            if param is None:
                del ssl_params[key]

        return ssl_params.get('ssl_ca_certs', True) if ssl_params['ssl_cert_validation'] else False

    def _service_check_tags(self, url):
        parsed_url = urlparse.urlparse(url)
        gitlab_host = parsed_url.hostname
        gitlab_port = 443 if parsed_url.scheme == 'https' else (parsed_url.port or 80)
        return ['gitlab_host:%s' % gitlab_host, 'gitlab_port:%s' % gitlab_port]

    # Validates an health endpoint
    #
    # Valid endpoints are:
    # - /-/readiness
    # - /-/liveness
    #
    # https://docs.gitlab.com/ce/user/admin_area/monitoring/health_check.html
    def _check_health_endpoint(self, instance, check_type):
        if check_type not in self.ALLOWED_SERVICE_CHECKS:
            raise CheckException("Health endpoint %s is not a valid endpoint" % check_type)

        url = instance.get('gitlab_url')
        if url is None:
            # Simply ignore this service check if not configured
            self.log.debug("gitlab_url not configured, service check %s skipped" % check_type)
            return

        service_check_tags = self._service_check_tags(url)
        verify_ssl = self._verify_ssl(instance)

        ## Timeout settings
        timeouts = (int(instance.get('connect_timeout', GitlabCheck.DEFAULT_CONNECT_TIMEOUT)),
                    int(instance.get('receive_timeout', GitlabCheck.DEFAULT_RECEIVE_TIMEOUT)))

        ## Auth settings
        auth = None
        if 'gitlab_user' in instance and 'gitlab_password' in instance:
            auth = (instance['gitlab_user'], instance['gitlab_password'])

        # These define which endpoint is hit and which type of check is actually performed
        # TODO: parse errors and report for single sub-service failure?
        service_check_name = "gitlab.%s" % check_type
        check_url = "%s/-/%s" % (url, check_type)

        try:
            self.log.debug('checking %s against %s' % (check_type, check_url))
            r = requests.get(check_url, auth=auth, verify=verify_ssl, timeout=timeouts,
                             headers=headers(self.agentConfig))
            if r.status_code != 200:
                self.service_check(service_check_name, PrometheusCheck.CRITICAL,
                                   message="Got %s when hitting %s" % (r.status_code, check_url),
                                   tags=service_check_tags)
                raise Exception("Http status code {0} on check_url {1}".format(r.status_code, check_url))
            else:
                r.raise_for_status()

        except requests.exceptions.Timeout:
            # If there's a timeout
            self.service_check(service_check_name, PrometheusCheck.CRITICAL,
                               message="Timeout when hitting %s" % check_url,
                               tags=service_check_tags)
            raise
        except Exception as e:
            self.service_check(service_check_name, PrometheusCheck.CRITICAL,
                               message="Error hitting %s. Error: %s" % (check_url, e.message),
                               tags=service_check_tags)
            raise
        else:
            self.service_check(service_check_name, PrometheusCheck.OK, tags=service_check_tags)
        self.log.debug("gitlab check %s succeeded" % check_type)
