# (C) Datadog, Inc. 2018
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)

import random
from requests import Request, Session
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


class SessionWrapper:
    def __init__(self, aci_url, session, apic_cookie=None, username=None, cert_name=None, cert=None, verify=None, timeout=None, log=None, appcenter=False):
        self.session = session
        self.aci_url = aci_url
        self.verify = verify
        self.timeout = timeout
        self.log = log

        if apic_cookie:
            self.apic_cookie = apic_cookie

        if appcenter:
            self.appcenter = appcenter

        if self.appcenter:
            self.certDn = 'uni/userext/appuser-{}/usercert-{}'.format(username, cert_name)
        else:
            self.certDn = 'uni/userext/user-{}/usercert-{}'.format(username, cert_name)

        self.cert = serialization.load_pem_private_key(cert, backend=default_backend())

    def send(self, req):
        req.headers['Cookie'] = self.apic_cookie
        return self.session.send(req, verify=self.verify, timeout=self.timeout)

    def close(self):
        self.session.close()

    def make_request(self, path, raw_response=False):
        url = "{}{}".format(self.aci_url, path)
        req = Request('get', url)
        prepped = req.prepare()
        if self.apic_cookie:
            prepped.headers['Cookie'] = self.apic_cookie
        else:
            cookie = ('APIC-Request-Signature={}; '
                      'APIC-Certificate-Algorithm=v1.0; '
                      'APIC-Certificate-Fingerprint=fingerprint; '
                      'APIC-Certificate-DN={}').format(self.signature, self.certDn)
            prepped_request.headers['Cookie'] = cookie

        response = self.session.send(prepped, verify=self.verify, timeout=self.timeout)
        try:
            response.raise_for_status()
        except Exception as e:
            self.log.warning("Error making request: {}".format(e))
            raise
        try:
            if raw_response:
                return response
            else:
                return response.json()
        except Exception as e:
            self.log.warning("Exception in json parsing, returning nothing: {}".format(e))
            raise


class Api:
    def __init__(self, aci_urls, username, cert_name=None, cert=None, password=None, verify=False, timeout=10, log=None):
        self.aci_urls = aci_urls
        self.username = username
        self.timeout = timeout
        self.verify = verify
        self.sessions = []
        if log:
            self.log = log
        else:
            import logging
            self.log = logging.getLogger('cisco_api')
        # This is used in testing
        self._refresh_sessions = True

        if password:
            self.password = password

        if cert_name and cert:
            self.cert_name = cert_name
            self.cert = cert
        elif not password:
            raise

    def close(self):
        for session in self.sessions:
            session.close()``

    def setup_cert_login(self):
        if self._refresh_sessions:
            # ensure sessions are an empty array
            self.sessions = []
        for aci_url in self.aci_urls:
            if not self._refresh_sessions:
                for session_wrapper in self.sessions:
                    if session_wrapper.aci_url == aci_url:
                        session = session_wrapper.session
                        break
            else:
                session = Session()

            if self._refresh_sessions:
                session_wrapper = SessionWrapper(aci_url, session,
                                                 cert_name=self.cert_name,
                                                 cert=self.cert,
                                                 verify=self.verify,
                                                 timeout=self.timeout,
                                                 log=self.log)
                self.sessions.append(session_wrapper)
            else:
                session_wrapper.apic_cookie = apic_cookie


    def login(self):
        # this is a path for testing, allowing the object to be patched with fake request responses
        if self._refresh_sessions:
            # ensure sessions are an empty array
            self.sessions = []
        for aci_url in self.aci_urls:
            if not self._refresh_sessions:
                for session_wrapper in self.sessions:
                    if session_wrapper.aci_url == aci_url:
                        session = session_wrapper.session
                        break
            else:
                session = Session()

            data = '<aaaUser name="{}" pwd="{}"/>\n'.format(self.username, self.password)
            url = "{}{}".format(aci_url, '/api/aaaLogin.xml')
            req = Request('post', url, data=data)
            prepped_request = req.prepare()
            response = session.send(prepped_request, verify=self.verify, timeout=self.timeout)
            response.raise_for_status()
            apic_cookie = 'APIC-Cookie={}'.format(response.cookies.get('APIC-cookie'))
            if self._refresh_sessions:
                session_wrapper = SessionWrapper(aci_url, session,
                                                 apic_cookie=apic_cookie,
                                                 verify=self.verify,
                                                 timeout=self.timeout,
                                                 log=self.log)
                self.sessions.append(session_wrapper)
            else:
                session_wrapper.apic_cookie = apic_cookie

    def make_request(self, path, raw_response=False):
        # allow for multiple APICs in a cluster to be included in one check so that the check
        # does not bombard a single APIC with dozens of requests and cause it to slow down
        session = random.choice(self.sessions)
        return session.make_request(path, raw_response=raw_response)

    def get_apps(self, tenant, raw_response=False):
        path = "/api/mo/uni/tn-{}.json?query-target=subtree&target-subtree-class=fvAp".format(tenant)
        response = self.make_request(path, raw_response)
        # return only the list of apps
        return self._parse_response(response, raw_response)

    def get_app_stats(self, tenant, app, raw_response=False):
        path = "/api/mo/uni/tn-{}/ap-{}.json?rsp-subtree-include=stats,no-scoped".format(tenant, app)
        response = self.make_request(path, raw_response)
        # return only the list of stats
        return self._parse_response(response, raw_response)

    def get_epgs(self, tenant, app, raw_response=False):
        path = "/api/mo/uni/tn-{}/ap-{}.json".format(tenant, app)
        query = '?query-target=subtree&target-subtree-class=fvAEPg'
        path = path + query
        response = self.make_request(path, raw_response)

        return self._parse_response(response, raw_response)

    def get_epg_stats(self, tenant, app, epg, raw_response=False):
        query = 'rsp-subtree-include=stats,no-scoped'
        path = "/api/mo/uni/tn-{}/ap-{}/epg-{}.json?{}"
        path = path.format(tenant, app, epg, query)

        response = self.make_request(path, raw_response)
        return self._parse_response(response, raw_response)

    def get_epg_meta(self, tenant, app, epg, raw_response=False):
        query = 'query-target=subtree&target-subtree-class=fvCEp'
        path = "/api/mo/uni/tn-{}/ap-{}/epg-{}.json?{}"
        path = path.format(tenant, app, epg, query)
        response = self.make_request(path, raw_response)

        return self._parse_response(response, raw_response)

    def get_eth_list_for_epg(self, tenant, app, epg, raw_response=False):
        query = 'query-target=subtree&target-subtree-class=fvRsCEpToPathEp'
        path = "/api/mo/uni/tn-{}/ap-{}/epg-{}.json?{}"
        path = path.format(tenant, app, epg, query)
        response = self.make_request(path, raw_response)

        return self._parse_response(response, raw_response)

    def get_tenant_stats(self, tenant, raw_response=False):
        path = "/api/mo/uni/tn-{}.json?rsp-subtree-include=stats,no-scoped".format(tenant)
        response = self.make_request(path, raw_response)
        # return only the list of stats
        return self._parse_response(response, raw_response)

    def get_tenant_events(self, tenant, page=0, page_size=15, raw_response=False):
        query1 = 'rsp-subtree-include=event-logs,no-scoped,subtree'
        query2 = 'order-by=eventRecord.created|desc'
        query3 = 'page={}&page-size={}'.format(page, page_size)
        query = '{}&{}&{}'.format(query1, query2, query3)
        path = "/api/node/mo/uni/tn-{}.json?{}".format(tenant, query)
        response = self.make_request(path, raw_response)
        # return only the list of stats
        return self._parse_response(response, raw_response)

    def get_fabric_pods(self, raw_response=False):
        path = '/api/mo/topology.json?query-target=subtree&target-subtree-class=fabricPod'
        response = self.make_request(path, raw_response)
        return self._parse_response(response, raw_response)

    def get_fabric_pod(self, pod, raw_response=False):
        path = '/api/mo/topology/pod-{}.json'.format(pod)
        response = self.make_request(path, raw_response)
        return self._parse_response(response, raw_response)

    def get_pod_stats(self, pod, raw_response=False):
        query = 'rsp-subtree-include=stats,no-scoped&page-size=20'
        path = '/api/mo/topology/pod-{}.json?{}'.format(pod, query)
        response = self.make_request(path, raw_response)
        return self._parse_response(response, raw_response)

    def get_fabric_nodes(self, raw_response=False):
        path = '/api/mo/topology.json?query-target=subtree&target-subtree-class=fabricNode'
        response = self.make_request(path, raw_response)
        return self._parse_response(response, raw_response)

    def get_fabric_node(self, pod, node, raw_response=False):
        path = '/api/mo/topology/pod-{}/node-{}.json'.format(pod, node)
        response = self.make_request(path, raw_response)
        return self._parse_response(response, raw_response)

    def get_node_stats(self, pod, node, raw_response=False):
        query = 'rsp-subtree-include=stats,no-scoped&page-size=20'
        path = '/api/mo/topology/pod-{}/node-{}/sys.json?{}'.format(pod, node, query)
        response = self.make_request(path, raw_response)
        return self._parse_response(response, raw_response)

    def get_controller_proc_metrics(self, pod, node, raw_response=False):
        query = 'rsp-subtree-include=stats,no-scoped&rsp-subtree-class={}'
        query = query.format('procMemHist5min,procCPUHist5min')
        path_base = '/api/node/mo/topology/pod-{}/node-{}/sys/proc.json?{}'
        path = path_base.format(pod, node, query)

        response = self.make_request(path, raw_response)
        return self._parse_response(response, raw_response)

    def get_spine_proc_metrics(self, pod, node, raw_response=False):
        query = 'rsp-subtree-include=stats,no-scoped&rsp-subtree-class={}'
        query = query.format('procSysMemHist5min,procSysCPUHist5min')
        path_base = '/api/node/mo/topology/pod-{}/node-{}/sys/procsys.json?{}'
        path = path_base.format(pod, node, query)

        response = self.make_request(path, raw_response)
        return self._parse_response(response, raw_response)

    def get_eth_list(self, pod, node, raw_response=False):
        query = 'query-target=subtree&target-subtree-class=l1PhysIf'
        path = '/api/mo/topology/pod-{}/node-{}/sys.json?{}'.format(pod, node, query)
        response = self.make_request(path, raw_response)
        return self._parse_response(response, raw_response)

    def get_eth_stats(self, pod, node, eth, raw_response=False):
        query = 'rsp-subtree-include=stats,no-scoped&page-size=50'
        path = '/api/mo/topology/pod-{}/node-{}/sys/phys-[{}].json?{}'.format(pod, node, eth, query)
        response = self.make_request(path, raw_response)
        return self._parse_response(response, raw_response)

    def get_eqpt_capacity(self, eqpt, raw_response=False):
        base_path = '/api/class/eqptcapacityEntity.json'
        base_query = 'query-target=self&rsp-subtree-include=stats&rsp-subtree-class='
        path_template = "{}?{}{}"
        path = path_template.format(base_path, base_query, eqpt)
        response = self.make_request(path, raw_response)
        return self._parse_response(response, raw_response)

    def get_capacity_contexts(self, context, raw_response=False):
        path_template = "/api/node/class/ctxClassCnt.json?rsp-subtree-class={}"
        path = path_template.format(context)
        response = self.make_request(path, raw_response)
        return self._parse_response(response, raw_response)

    def get_apic_capacity_limits(self, raw_response=False):
        base_path = "/api/mo/uni/fabric/compcat-default/fvsw-default/capabilities.json"
        query = "query-target=children&target-subtree-class=fvcapRule"
        path = "{}?{}".format(base_path, query)
        response = self.make_request(path, raw_response)
        return self._parse_response(response, raw_response)

    def get_apic_capacity_metrics(self, capacity_metric, query=None, raw_response=False):
        if not query:
            query = "rsp-subtree-include=count"
        base_path = "/api/class/"
        path = "{}{}.json?{}".format(base_path, capacity_metric, query)
        response = self.make_request(path, raw_response)
        return self._parse_response(response, raw_response)

    def _parse_response(self, response, raw_response=False):
        if raw_response:
            return response
        else:
            return response.get('imdata')
