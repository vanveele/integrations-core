# (C) Datadog, Inc. 2018
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)

from .mixins import PrometheusScraperMixin

from .. import AgentCheck
from ...errors import CheckException


class GenericPrometheusCheck(PrometheusScraperMixin, AgentCheck):
    """
    GenericPrometheusCheck is a class that helps instantiating PrometheusCheck only
    with YAML configurations. As each check has it own states it maintains a map
    of all checks so that the one corresponding to the instance is executed

    Minimal example configuration:
    instances:
    - prometheus_url: http://foobar/endpoint
        namespace: "foobar"
        metrics:
        - bar
        - foo
    """
    def __init__(self, name, init_config, agentConfig, instances=None, default_instances=None, default_namespace=None):
        super(GenericPrometheusCheck, self).__init__(name, init_config, agentConfig, instances)
        self.config_map = {}
        self.default_instances = {} if default_instances is None else default_instances
        self.default_namespace = default_namespace

        if instances is not None:
            for instance in instances:
                endpoint = instance['prometheus_url']
                self.config_map[endpoint] = self.get_scraper_config(instance)

    def check(self, instance):
        # Get the configuration for this specific instance
        scraper_config = self.get_scraper_config(instance)

        self.process(scraper_config)

    def get_scraper_config(self, instance):
        endpoint = instance.get('prometheus_url', None)

        if endpoint is None:
            raise CheckException("Unable to find prometheus URL in config file.")

        # If we've already created the corresponding scraper configuration, return it
        if endpoint in self.config_map:
            return self.config_map[endpoint]

        # Otherwise, we create the scraper configuration
        config = self.create_mixin_configuration(instance)

        if not config['metrics_mapper']:
            raise CheckException("You have to collect at least one metric from the endpoint: {}".format(endpoint))

        # Add this configuration to the config_map
        self.config_map[endpoint] = config

        return config

    def _finalize_tags_to_submit(self, _tags, metric_name, val, metric, custom_tags=None, hostname=None):
        """
        Format the finalized tags
        This is generally a noop, but it can be used to change the tags before sending metrics
        """
        return _tags
