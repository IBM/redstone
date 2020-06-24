# Copyright 2019 Mathew Odden <mathewrodden@gmail.com>
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

"""
This module holds the service specific client classes, as well
as the BaseClient class that they extend from for shared business function.

If you wish to add or extend functionality to a client or service, this is
where the concrete classes and logic are for those purposes.
"""

import base64
import io
import logging
import re
from typing import List, Dict
import urllib.parse
import zipfile

import requests
import requests.adapters
import requests.auth
from requests.packages.urllib3.util.retry import Retry

from redstone import auth


LOG = logging.getLogger(__name__)


class TokenAuth(requests.auth.AuthBase):
    def __init__(self, credentials):
        self._token_manager = credentials

    def __call__(self, req):
        req.headers["Authorization"] = "Bearer %s" % self._token_manager.get_token()
        return req


class BaseClient(object):
    def __init__(
        self,
        region=None,
        service_instance_id=None,
        iam_api_key=None,
        verify=True,
        endpoint_url=None,
        credentials=None,
    ):

        self.session = requests.Session()
        self.session.verify = verify

        self.credentials = credentials
        # respect old path if user builds us directly with API key
        if iam_api_key:
            LOG.warn(
                "'iam_api_key' keyword arg is deprecated. use 'credentials' instead."
            )
            self.credentials = auth.TokenManager(iam_api_key)

        self.session.auth = TokenAuth(self.credentials)

        self.service_instance_id = service_instance_id
        self.region = region

        if endpoint_url:
            if endpoint_url.endswith("/"):
                endpoint_url = endpoint_url[:-1]
            self.endpoint_url = endpoint_url
        else:
            self.endpoint_url = self.endpoint_for_region(region)


class IKS(BaseClient):

    names = ["iks"]

    def __init__(self, *args, **kwargs):
        super(IKS, self).__init__(*args, **kwargs)

        # IKS likes to throw back random 503s at times, but retrying generally works fine
        # requests default is Retry(0, read=False); see requests/adapters.py
        retry_conf = Retry(
            total=5, read=False, backoff_factor=1, status_forcelist=[502, 503]
        )
        self.session.mount(
            "https://", requests.adapters.HTTPAdapter(max_retries=retry_conf)
        )
        self.session.mount(
            "http://", requests.adapters.HTTPAdapter(max_retries=retry_conf)
        )

    def endpoint_for_region(self, region):
        return "https://containers.bluemix.net"

    def get_clusters(self) -> List[Dict]:
        """
        List the current IKS clusters in a specific region.

        Returns:
            A list of dict objects representing the cluster metadata.
        """

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
            headers={"X-Region": self.region, "Accept": "application/json"},
        )

        if resp.status_code != 200:
            raise Exception(
                "error getting clusters: code=%d body=%r"
                % (resp.status_code, resp.text)
            )

        return resp.json()

    def get_workers(self, cluster):
        """List the workers in an IKS cluster."""

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
            "{0}/v1/clusters/{1}/workers?showDeleted=false".format(
                self.endpoint_url, cluster
            ),
            headers={"X-Region": self.region, "Accept": "application/json"},
        )

        if resp.status_code != 200:
            raise Exception(
                "error getting workers: code=%d body=%r" % (resp.status_code, resp.text)
            )

        return resp.json()

    def update_worker(self, cluster, worker):
        """
        Initiate an update on a worker node.

        The worker node will update to the latest revision that matches the
        master/API server version. i.e. If the master is at 1.16.x, the worker
        will update to the latest 1.16.x series.
        """

        # PUT /v1/clusters/<cluster_name_or_id>/workers/<worker_name_or_id> HTTP/1.1
        # Host: containers.bluemix.net
        # Accept: application/json
        # Authorization: [PRIVATE DATA HIDDEN]
        # Content-Type: application/json
        # X-Region: au-syd

        # {"action":"update"}
        # OR
        # {"action":"update", "force": true}
        # returns 204 No Content on success

        resp = self.session.put(
            "{0}/v1/clusters/{1}/workers/{2}".format(
                self.endpoint_url, cluster, worker
            ),
            headers={"X-Region": self.region, "Accept": "application/json"},
            json={"action": "update"},
        )

        if resp.status_code != 204:
            raise Exception(
                "error updating workers: code=%d body=%r"
                % (resp.status_code, resp.text)
            )

    def update_master(self, cluster, version):
        """Initate an update on the master nodes of a cluster."""

        resp = self.session.put(
            "{0}/v1/clusters/{1}".format(self.endpoint_url, cluster),
            headers={"X-Region": self.region, "Accept": "application/json"},
            json={"action": "update", "version": version},
        )

        if resp.status_code != 204:
            raise Exception(
                "error updating master: code=%d body=%r" % (resp.status_code, resp.text)
            )

    def get_kube_versions(self):
        resp = self.session.get(
            "{0}/v1/kube-versions".format(self.endpoint_url),
            headers={"X-Region": self.region, "Accept": "application/json"},
        )

        if resp.status_code != 200:
            raise Exception(
                "error getting kube-versions: code=%d body=%r"
                % (resp.status_code, resp.text)
            )

        return resp.json()

    def get_cluster_config(self, cluster):
        """
        Retrieve a KubeConfig that can be used with kubectl to
        interact with the given IKS cluster.

        Returns:
            base64 encoded file data; can be decode and written to file,
            or used with the python kubernetes client to interact in the same process
        """
        output_format = "yaml"

        # NOTE(mrodden): no idea why this one API needs the refresh token,
        # but it certainly gives an HTTP 400 when you don't have it
        # this is a pretty hacky way of getting one, but we shouldn't even
        # need it either so... idk. /shrug

        # do a get token before, to make sure we get a valid refresh token.
        _token = self.session.auth._token_manager.get_token()
        refresh_token = self.session.auth._token_manager._token_info.get(
            "refresh_token"
        )

        # pure yaml output was added sometime after our original code to deal with the zipfile,
        # leaving both in because maybe its useful for someone to use the zip path still
        params = {}
        if output_format == "yaml":
            params["format"] = "yaml"

        path = "{0}/v1/clusters/{1}/config"
        resp = self.session.get(
            path.format(self.endpoint_url, cluster),
            params=params,
            headers={"X-Region": self.region, "X-Auth-Refresh-Token": refresh_token},
        )

        resp.raise_for_status()

        if output_format == "yaml":
            config_yaml = resp.content
        else:
            zip_data = io.BytesIO()
            zip_data.write(resp.content)
            zip_file = zipfile.ZipFile(zip_data)

            files = zip_file.namelist()
            for file_name in files:
                if file_name.endswith("yml"):
                    kube_yaml = zip_file.read(file_name)
                elif file_name.endswith("pem"):
                    ca_data = zip_file.read(file_name)

            ca_b64 = base64.b64encode(ca_data)

            config_yaml = re.sub(
                b"certificate-authority: .+",
                b"certificate-authority-data: " + ca_b64,
                kube_yaml,
            )

        return base64.b64encode(config_yaml)


class ResourceController(BaseClient):
    """
    Client class for interacting with the Resource Controller service,
    which is used for managing service instances within the cloud account.

    API Docs:
      - https://console.bluemix.net/apidocs/resource-manager
      - https://console.bluemix.net/apidocs/resource-controller
    """

    names = ["rc"]
    KEYPROTECT_PLAN_ID = "eedd3585-90c6-4c8f-be3d-062069e99fc3"  # keyprotect tiered-pricing ID

    def __init__(self, *args, **kwargs):
        super(ResourceController, self).__init__(*args, **kwargs)

        # add retries for RC, since it has issues communicating with global catalog
        # and will throw a 504 in this case
        retry_conf = Retry(
            total=5, read=False, backoff_factor=1, status_forcelist=[502, 503, 504]
        )
        self.session.mount(
            "https://", requests.adapters.HTTPAdapter(max_retries=retry_conf)
        )
        self.session.mount(
            "http://", requests.adapters.HTTPAdapter(max_retries=retry_conf)
        )

    def endpoint_for_region(self, region):
        return "https://resource-controller.cloud.ibm.com"

    def get_default_resource_group(self):
        default_rg = next(
            filter(
                lambda x: x.get("name") in ["Default", "default"],
                self.resource_groups().get("resources", []),
            ),
            None,
        )

        if not default_rg:
            raise Exception("No default resource group found!")

        return default_rg

    def resource_groups(self):
        # resource-manager used to be independent when it was bluemix,
        # but any recent endpoint will be the same for controller and manager
        if "bluemix" in self.endpoint_url:
            netloc = self.endpoint_url.replace("controller", "manager")
        else:
            netloc = self.endpoint_url

        # apparently it doesn't complain if we drop query params,
        # didn't want to have to look up the account ID anyway, so +2
        resp = self.session.get("{0}/v2/resource_groups".format(netloc),)

        if resp.status_code != 200:
            raise Exception(
                "Failed to get resource groups: url=%r code=%d body=%r"
                % (resp.request.url, resp.status_code, resp.text)
            )

        return resp.json()

    def create_instance(self, name, plan_id, region=None, resource_group=None):
        """
        Create/provision a service instance.

        Returns:
            tuple of (service_GUID, service_CRN) if successful

        Raises:
            Exception if there is an error
        """

        if resource_group is None:
            resource_group_id = self.get_default_resource_group().get("id")
        else:
            resource_group_id = resource_group

        if not region:
            region = self.region

        return self._create_instance_v2(name, region, resource_group_id, plan_id)

    def _create_instance_v2(self, name, region, resource_group_id, resource_plan_id):
        body = {
            "name": name,
            "resource_plan_id": resource_plan_id,
            "resource_group": resource_group_id,
            "target": region,
        }

        resp = self.session.post(
            "{0}/v2/resource_instances".format(self.endpoint_url), json=body
        )

        if resp.status_code != 201:
            raise Exception(
                "Create instance failed: code=%d body=%s"
                % (resp.status_code, resp.text)
            )

        return resp.json().get("guid"), resp.json().get("id")

    def _create_instance_v1(self, name, region, resource_group_id, resource_plan_id):

        # seems like the target_crn is the region selector, and its just the price plan ID with the region stuck at the end
        target_crn = "crn:v1:bluemix:public:globalcatalog::::deployment:{0}%3A{1}".format(
            resource_plan_id, region
        )

        body = {
            "name": name,
            "resource_plan_id": resource_plan_id,
            "resource_group_id": resource_group_id,
            "target_crn": target_crn,
        }

        resp = self.session.post(
            "{0}/v1/resource_instances".format(self.endpoint_url), json=body
        )

        if resp.status_code != 201:
            raise Exception(
                "Create instance failed: code=%d body=%s"
                % (resp.status_code, resp.text)
            )

        return resp.json().get("guid"), resp.json().get("id")

    def delete_instance(self, instance_crn):
        """Delete/deprovision a service instance identified by the given CRN or UUID."""

        safe_crn = urllib.parse.quote(instance_crn, "")
        resp = self.session.delete(
            "{0}/v2/resource_instances/{1}".format(self.endpoint_url, safe_crn)
        )

        if resp.status_code != 204:
            raise Exception(
                "Delete instance failed: code=%d body=%s"
                % (resp.status_code, resp.text)
            )

    def list_instances(self):
        """
        Retrieve a list of all the service and resource instances in the current account.

        Note this will return an iterator that will handle the underlying pagination of
        large sets of instances returned.

        Returns:
            a generator type that iterates over the collection of instances returned from
            the API request
        """
        resp = self.session.get("{0}/v2/resource_instances".format(self.endpoint_url))
        resp.raise_for_status()

        while True:
            for res in resp.json()["resources"]:
                yield res

            next_url = resp.json().get("next_url")
            if not next_url:
                break

            resp = self.session.get("{0}{1}".format(self.endpoint_url, next_url))
            resp.raise_for_status()

    def get_instance(self, instance_id):
        resp = self.session.get(
            "{0}/v2/resource_instances/{1}".format(self.endpoint_url, instance_id)
        )
        if resp.status_code == 404:
            return None

        resp.raise_for_status()
        return resp.json()


class KeyProtect(BaseClient):
    """
    API Docs: https://cloud.ibm.com/apidocs/key-protect
    """
    class KeyProtectError(Exception):
        @staticmethod
        def wrap(http_error):
            try:
                message = http_error.response.json()["resources"][0]["errorMsg"]
            except KeyError:
                message = http_error.response.text
            err = KeyProtect.KeyProtectError(message)
            err.http_error = http_error
            err.__suppress_context__ = True
            return err

    names = ["kms"]

    def __init__(self, *args, **kwargs):
        super(KeyProtect, self).__init__(*args, **kwargs)

        if not self.service_instance_id:
            raise ValueError(
                "KeyProtect service requires 'service_instance_id' to be set!"
            )

        self.session.headers["Bluemix-Instance"] = self.service_instance_id

    def endpoint_for_region(self, region):
        return "https://keyprotect.{0}.bluemix.net".format(region)

    def _validate_resp(self, resp):
        def log_resp(resp):
            resp_str = io.StringIO()
            print("%s %s" % (resp.status_code, resp.reason), file=resp_str)

            for k, v in resp.headers.items():
                if k.lower() == "authorization":
                    v = "REDACTED"
                print("%s: %s" % (k, v), file=resp_str)

            print(resp.content.decode(), end="", file=resp_str)
            return resp_str.getvalue()

        try:
            LOG.debug(log_resp(resp))
            resp.raise_for_status()
        except requests.HTTPError as http_err:
            http_err.raw_response = log_resp(resp)
            raise KeyProtect.KeyProtectError.wrap(http_err)

    def keys(self):
        resp = self.session.get("%s/api/v2/keys" % self.endpoint_url)

        self._validate_resp(resp)

        return resp.json().get("resources", [])

    def get(self, key_id):
        resp = self.session.get("%s/api/v2/keys/%s" % (self.endpoint_url, key_id))

        self._validate_resp(resp)

        return resp.json().get("resources")[0]

    def create(self, name, payload=None, raw_payload=None, root=False):

        data = {
            "metadata": {
                "collectionType": "application/vnd.ibm.kms.key+json",
                "collectionTotal": 1,
            },
            "resources": [
                {
                    "type": "application/vnd.ibm.kms.key+json",
                    "extractable": not root,
                    "name": name,
                }
            ],
        }

        # use raw_payload if given, else assume payload needs some base64 love
        if raw_payload is not None:
            data["resources"][0]["payload"] = raw_payload
        elif payload is not None:
            data["resources"][0]["payload"] = base64.b64encode(payload).decode("utf-8")

        resp = self.session.post("%s/api/v2/keys" % self.endpoint_url, json=data)
        self._validate_resp(resp)
        return resp.json().get("resources")[0]

    def delete(self, key_id):
        resp = self.session.delete("%s/api/v2/keys/%s" % (self.endpoint_url, key_id))
        self._validate_resp(resp)

    def _action(self, key_id, action, jsonable):
        resp = self.session.post(
            "%s/api/v2/keys/%s" % (self.endpoint_url, key_id),
            params={"action": action},
            json=jsonable,
        )
        self._validate_resp(resp)
        return resp.json()

    def wrap(self, key_id, plaintext, aad=None):
        if plaintext:
            data = {"plaintext": base64.b64encode(plaintext).decode("utf-8")}
        else:
            data = {}

        if aad:
            data["aad"] = aad

        return self._action(key_id, "wrap", data)

    def unwrap(self, key_id, ciphertext, aad=None):
        # json body needs to be a UTF-8 string
        if isinstance(ciphertext, bytes):
            ciphertext = ciphertext.decode("utf-8")

        data = {"ciphertext": ciphertext}

        if aad:
            data["aad"] = aad

        resp = self._action(key_id, "unwrap", data)
        return base64.b64decode(resp["plaintext"].encode("utf-8"))

    def rotate(self, key_id, payload=None):
        data = None
        if payload:
            data = {"payload": base64.b64encode(payload).decode("utf-8")}

        return self._action(key_id, "rotate", data)


class CISAuth(requests.auth.AuthBase):
    def __init__(self, credentials):
        self._token_manager = credentials

    def __call__(self, req):
        req.headers["x-auth-user-token"] = "Bearer %s" % self._token_manager.get_token()
        return req


class CIS(BaseClient):

    names = ["cis"]

    def __init__(self, *args, **kwargs):
        super(CIS, self).__init__(*args, **kwargs)
        self.session.auth = CISAuth(self.credentials)
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
        pool_id = pool.get("id")

        keys_to_remove = ["created_on", "modified_on", "healthy", "id"]

        for key in keys_to_remove:
            try:
                del pool[key]
            except KeyError:
                pass

        path = "{0}/v1/{1}/load_balancers/pools/{2}"
        resp = self.session.put(
            path.format(self.endpoint_url, self.safe_crn, pool_id), json=pool
        )
        resp.raise_for_status()
        return resp.json().get("result")
