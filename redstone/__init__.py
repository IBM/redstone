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
The :mod:`redstone` module is used to interact with various IBM Cloud services.

Basic usage involves getting a :py:class:`Session` object, which can
be used to build a client for interacting with a specific service.

For example, to interact with Resource Controller, we can use the default session to
get a client to talk to Resource Controller::

    >>> import redstone
    >>> session = redstone.get_default_session()
    >>> rc = session.service("ResourceController")

The :py:func:`service` function at the top level can be used as a shortcut for
accessing the default session to build clients. This is equivalent to the above::

    >>> import redstone
    >>> rc = redstone.service("ResourceController")


The default session is constructed lazily on first access and looks for
the environment variable `IBMCLOUD_API_KEY` to use as a credential for
interacting with services.

The default session can be overriden or created manually if desired.
Any clients created using the default session will then use that session
instead.

    >>> import redstone
    >>> redstone.DEFAULT_SESSION = redstone.Session(iam_api_key="...")
    >>> rc = redstone.service("ResourceController")
"""

import os
from typing import Optional  # noqa: F401

from redstone import auth
from redstone import client


DEFAULT_SESSION = None  # Optional[Session]
"""
Holds the current default :py:class:`Session` or
None if no session has been built yet.
"""


class Session(object):
    """
    Session objects are used to create clients used to interact with various services.
    They hold region endpoint information and a credential object that is used
    by the clients for authentication. It's main purpose for sharing and caching
    credentials for use between multiple clients/services.

    A Session can be created manually, but there is also a default session that can
    be accessed by using the :py:func:`get_default_session` function.
    """

    def __init__(self, region=None, iam_api_key=None):
        self.region = region
        self.iam_api_key = iam_api_key
        self.credentials = auth.TokenManager(self.iam_api_key)

    def service(self, service_name, **kwargs):
        client_cls = getattr(client, service_name, None)
        if not client_cls:
            raise ValueError("No client for service '%s'" % service_name)

        if kwargs.get("iam_api_key"):
            del kwargs["iam_api_key"]

        if not kwargs.get("region"):
            kwargs["region"] = self.region

        if not kwargs.get("credentials"):
            kwargs["credentials"] = self.credentials

        return client_cls(**kwargs)


def get_default_session() -> Session:
    """
    Returns the current default session for building clients objects.
    """

    global DEFAULT_SESSION

    if DEFAULT_SESSION is None:
        DEFAULT_SESSION = Session(
            iam_api_key=os.environ.get("IBMCLOUD_API_KEY"),
            region=os.environ.get("IBMCLOUD_REGION"),
        )

    return DEFAULT_SESSION


def service(service_name, **kwargs):
    """Create and return a new client using the :const:`DEFAULT_SESSION`."""
    return get_default_session().service(service_name, **kwargs)
