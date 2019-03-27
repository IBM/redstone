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

import os

from redstone import client

# free to set/override if user wants
DEFAULT_SESSION = None


class Session(object):

    def __init__(self, region=None, iam_api_key=None):
        self.region = region
        self.iam_api_key = iam_api_key

    def service(self, service_name, **kwargs):
        client_cls = getattr(client, service_name, None)
        if not client_cls:
            raise ValueError("No client for service '%s'" % service_name)

        if not kwargs.get('region'):
            kwargs['region'] = self.region

        if not kwargs.get('iam_api_key'):
            kwargs['iam_api_key'] = self.iam_api_key

        return client_cls(**kwargs)


def get_default_session():
    global DEFAULT_SESSION

    if DEFAULT_SESSION is None:
        DEFAULT_SESSION = Session(
            iam_api_key=os.environ.get("IBMCLOUD_API_KEY"),
            region=os.environ.get("IBMCLOUD_REGION")
        )

    return DEFAULT_SESSION


def service(service_name, **kwargs):
    return get_default_session().service(service_name, **kwargs)
