# Copyright 2018 Mathew Odden <mathewrodden@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import urllib.parse

import requests
import requests.auth

from redstone import auth


class TokenAuth(requests.auth.AuthBase):

    def __init__(self, apikey):
        self._token_manager = auth.TokenManager(apikey)

    def __call__(self, req):
        req.headers['Authorization'] = \
            "Bearer %s" % self._token_manager.get_token()
        return req


class BaseClient(object):

    def __init__(self, region=None, service_instance_id=None,
        iam_api_key=None, verify=True, endpoint_url=None):

        self.session = requests.Session()
        self.session.verify = verify
        self.session.auth = TokenAuth(iam_api_key)

        self.service_instance_id = service_instance_id
        self.region = region

        if endpoint_url:
            if endpoint_url.endswith('/'):
                endpoint_url = endpoint_url[:-1]
            self.endpoint_url = endpoint_url
        else:
            self.endpoint_url = self.endpoint_for_region(region)


class IKS(BaseClient):

    name = "iks"

    def endpoint_for_region(self, region):
        return "https://containers.bluemix.net"

    def get_clusters(self):

        """
        GET /v1/clusters HTTP/1.1
        Host: containers.bluemix.net
        Accept: application/json
        Authorization: [PRIVATE DATA HIDDEN]
        Content-Type: application/json
        X-Region: au-syd
        """
        # returns 200 OK on success

        resp = self.session.get(
            "{0}/v1/clusters".format(self.endpoint_url),
            headers={
                "X-Region": self.region,
                "Accept": "application/json"
            }
        )

        if resp.status_code != 200:
            raise Exception("error getting clusters: code=%d body=%r" % (resp.status_code, resp.text))

        return resp.json()

    def get_workers(self, cluster):

        """
        GET /v1/clusters/<cluster_name_or_id>/workers?showDeleted=false HTTP/1.1
        Host: containers.bluemix.net
        Accept: application/json
        Authorization: [PRIVATE DATA HIDDEN]
        Content-Type: application/json
        X-Region: au-syd
        """
        # returns 200 OK on success

        resp = self.session.get(
            "{0}/v1/clusters/{1}/workers?showDeleted=false".format(cluster),
            headers={
                "X-Region": self.region,
                "Accept": "application/json"
            }
        )

        if resp.status_code != 200:
            raise Exception("error getting workers: code=%d body=%r" % (resp.status_code, resp.text))

        return resp.json()

    def update_worker(self, cluster, worker):

        """
        PUT /v1/clusters/<cluster_name_or_id>/workers/<worker_name_or_id> HTTP/1.1
        Host: containers.bluemix.net
        Accept: application/json
        Authorization: [PRIVATE DATA HIDDEN]
        Content-Type: application/json
        X-Region: au-syd

        {"action":"update"}
        OR
        {"action":"update", "force": true}
        """
        # returns 204 No Content on success

        resp = self.session.put(
            "{0}/v1/clusters/{1}/workers/{2}".format(self.endpoint_url, cluster, worker),
            headers={
                "X-Region": self.region,
                "Accept": "application/json"
            },
            json={"action": "update"}
        )

        if resp.status_code != 204:
            raise Exception("error getting workers: code=%d body=%r" % (resp.status_code, resp.text))


class ResourceController(BaseClient):

    name = "rc"

    def endpoint_for_region(self, region):
        return "https://resource-controller.bluemix.net"

    def create_instance(self, name, region=None):
        """Create an service instance.

        :returns: tuple of (service_GUID, service_CRN) if successful
        :raises: Exception if there is an error
        """

        # original request used to reverse engineer this for reference
        """
        POST /v1/resource_instances HTTP/1.1
        Host: resource-controller.bluemix.net
        Accept: application/json
        Accept-Language: en-US
        Accept-Language: en
        Authorization: [PRIVATE DATA HIDDEN]
        Content-Type: application/json
        User-Agent: IBM Cloud CLI 0.12.1 / linux

        {"name":"mrodden-test-deleteme","resource_plan_id":"eedd3585-90c6-4c8f-be3d-062069e99fc3","resource_group_id":"f75c4280361947448dfe59b99dc02368","target_crn":"crn:v1:bluemix:public:globalcatalog::::deployment:eedd3585-90c6-4c8f-be3d-062069e99fc3%3Aus-south"}
        """
        # returns 201 on success

        # NOTE(mrodden): these are hardcoded because it requires another lookup to the catalog/IAM,
        # and we aren't really changing test accounts much
        resource_group_id = "f75c4280361947448dfe59b99dc02368"

        if not region:
            region = self.region

        # seems like the target_crn is the region selector, and its just the price plan ID with the region stuck at the end
        target_crn = "crn:v1:bluemix:public:globalcatalog::::deployment:eedd3585-90c6-4c8f-be3d-062069e99fc3%3A" + region

        body = {
            "name": name,
            "resource_plan_id": "eedd3585-90c6-4c8f-be3d-062069e99fc3",  # tiered-pricing ID
            "resource_group_id": resource_group_id,
            "target_crn": target_crn
        }

        resp = self.session.post(
            "{0}/v1/resource_instances".format(self.endpoint_url),
            json=body
        )

        if resp.status_code != 201:
            raise Exception("Create instance failed: code=%d body=%s" % (resp.status_code, resp.text))

        return resp.json().get("guid"), resp.json().get("id")


    def delete_instance(self, instance_crn):

        """
        DELETE /v1/resource_instances/crn:v1:bluemix:public:kms:us-south:a%2F7609edf6db359a81a1dde8f44b1a8278:b938bb81-e96e-4613-a262-db1286b1daec:: HTTP/1.1
        Host: resource-controller.bluemix.net
        Accept: application/json
        Accept-Language: en-US
        Accept-Language: en
        Authorization: [PRIVATE DATA HIDDEN]
        Content-Type: application/json
        User-Agent: IBM Cloud CLI 0.12.1 / linux
        """
        # returns 204 No Content on success

        safe_crn = urllib.quote(instance_crn, "")
        resp = self.session.delete(
            "{0}/v1/resource_instances/{1}".format(self.endpoint_url, safe_crn)
        )

        if resp.status_code != 204:
            raise Exception("Delete instance failed: code=%d body=%s" % (resp.status_code, resp.text))


class KeyProtect(BaseClient):

    name = "kms"

    def __init__(self, *args, **kwargs):
        super(KeyProtect, self).__init__(*args, **kwargs)

        if not self.service_instance_id:
            raise ValueError("KeyProtect service requires 'service_instance_id' to be set!")

        self.sesion.headers['Bluemix-Instance'] = self.service_instance_id

    def endpoint_for_region(self, region):
        return "https://keyprotect.{0}.bluemix.net".format(region)

    def _validate_resp(self, resp):

        def log_resp(resp):
            resp_str = StringIO.StringIO()
            print("%s %s" % (resp.status_code, resp.reason), file=resp_str)

            for k, v in resp.headers.items():
                if k.lower() == 'authorization':
                    v = 'REDACTED'
                print("%s: %s" % (k, v), file=resp_str)

            print(resp.content, end='', file=resp_str)
            return resp_str.getvalue()

        try:
            LOG.debug(log_resp(resp))
            resp.raise_for_status()
        except requests.HTTPError as http_err:
            http_err.raw_response = log_resp(resp)
            raise http_err

    def keys(self):
        resp = self.session.get(
            "%s/api/v2/keys" % self.endpoint_url,
            headers=self._headers)

        self._validate_resp(resp)

        return resp.json().get('resources', [])

    def get(self, key_id):
        resp = self.session.get(
            "%s/api/v2/keys/%s" % (self.endpoint_url, key_id),
            headers=self._headers)

        self._validate_resp(resp)

        return resp.json().get('resources')[0]

    def create(self, name, payload=None, raw_payload=None, root=False):

        data = {
            "metadata": {
                "collectionType": "application/vnd.ibm.kms.key+json",
                "collectionTotal": 1},
            "resources": [
                {
                    "type": "application/vnd.ibm.kms.key+json",
                    "extractable": not root,
                    "name": name
                }
            ]
        }

        # use raw_payload if given, else assume payload needs some base64 love
        if raw_payload is not None:
            data['resources'][0]['payload'] = raw_payload
        elif payload is not None:
            data['resources'][0]['payload'] = base64.b64encode(payload)

        resp = self.session.post(
            "%s/api/v2/keys" % self.endpoint_url,
            headers=self._headers,
            json=data)
        self._validate_resp(resp)
        return resp.json().get('resources')[0]

    def delete(self, key_id):
        resp = self.session.delete(
            "%s/api/v2/keys/%s" % (self.endpoint_url, key_id),
            headers=self._headers)
        self._validate_resp(resp)

    def _action(self, key_id, action, jsonable):
        resp = self.session.post(
            "%s/api/v2/keys/%s" % (self.endpoint_url, key_id),
            headers=self._headers,
            params={"action": action},
            json=jsonable)
        self._validate_resp(resp)
        return resp.json()

    def wrap(self, key_id, plaintext, aad=None):
        data = {'plaintext': base64.b64encode(plaintext)}

        if aad:
            data['aad'] = aad

        return self._action(key_id, "wrap", data)

    def unwrap(self, key_id, ciphertext, aad=None):
        data = {'ciphertext': ciphertext}

        if aad:
            data['aad'] = aad

        resp = self._action(key_id, "unwrap", data)
        return base64.b64decode(resp['plaintext'])


class CISAuth(requests.auth.AuthBase):

    def __init__(self, apikey):
        self._token_manager = auth.TokenManager(apikey)

    def __call__(self, req):
        req.headers['x-auth-user-token'] = \
            "Bearer %s" % self._token_manager.get_token()
        return req


class CIS(BaseClient):

    def __init__(self, *args, **kwargs):
        super(CIS, self).__init__(*args, **kwargs)
        self.session.auth = CISAuth(apikey=kwargs.get("iam_api_key"))
        self.safe_crn = urllib.parse.quote(self.service_instance_id, safe="")

    def endpoint_for_region(self, region):
        return "https://api.cis.cloud.ibm.com"

    def pools(self):
        path = "{0}/v1/{1}/load_balancers/pools"
        resp = self.session.get(path.format(self.endpoint_url, self.safe_crn))
        resp.raise_for_status()
        return resp.json().get("result")

    def get_pool(self, pool_id):
        path = "{0}/v1/{1}/load_balancers/pools/{2}"
        resp = self.session.get(path.format(self.endpoint_url, self.safe_crn, pool_id))
        resp.raise_for_status()
        return resp.json().get("result")

    def update_pool(self, pool):
        pool_id = pool.get('id')

        del pool['created_on']
        del pool['modified_on']
        del pool['healthy']
        del pool['id']

        path = "{0}/v1/{1}/load_balancers/pools/{2}"
        resp = self.session.put(
            path.format(self.endpoint_url, self.safe_crn, pool_id),
            json=pool)
        resp.raise_for_status()
        return resp.json().get("result")
