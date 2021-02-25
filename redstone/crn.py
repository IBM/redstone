# Copyright 2020 Mathew Odden <mathewrodden@gmail.com>
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

# flake8: noqa E501
"""IBM Cloud CRN types and functions.

Parsing a CRN from a (possibly urlencoded) string::

    >>> import redstone.crn
    >>> mycrn = redstone.crn.loads("crn%3Av1%3Astaging%3Apublic%3Aexampleservice%3Aglobal%3Aa%2Fe5d5b304e0f3469f9145bed817f2efe1%3A6fc68009-12f6-4f9e-be69-02cb3b7e0a8d%3A%3A")
    >>> mycrn
    redstone.crn.CRN(prefix='crn', version='v1', cname='staging', ctype='public', service_name='exampleservice', location='global', scope='a/e5d5b304e0f3469f9145bed817f2efe1', service_instance='6fc68009-12f6-4f9e-be69-02cb3b7e0a8d', resource_type='', resource='')
    >>> str(mycrn)
    'crn:v1:staging:public:exampleservice:global:a/e5d5b304e0f3469f9145bed817f2efe1:6fc68009-12f6-4f9e-be69-02cb3b7e0a8d::'
"""

import sys
import urllib.parse


SEGMENTS = [
    "prefix",
    "version",
    "cname",
    "ctype",
    "service_name",
    "location",
    "scope",
    "service_instance",
    "resource_type",
    "resource",
]


class CRN(object):
    def __init__(self, **kwargs):
        for segment in SEGMENTS:
            setattr(self, segment, kwargs.get(segment, ""))

        if not self.prefix:
            self.prefix = "crn"

        if not self.version:
            self.version = "v1"

    def __repr__(self):
        kv_pairs = ["%s=%r" % (seg, getattr(self, seg)) for seg in SEGMENTS]
        return "%s.%s(%s)" % (
            self.__class__.__module__,
            self.__class__.__qualname__,
            ", ".join(kv_pairs),
        )

    def __str__(self):
        return ":".join([getattr(self, seg) for seg in SEGMENTS])


def loads(crn_string):
    if not crn_string.startswith("crn"):
        raise ValueError("Invalid crn prefix: %r" % crn_string)

    if "%3A" in crn_string:
        crn_string = urllib.parse.unquote(crn_string)

    vals = crn_string.split(":")
    if len(vals) != 10:
        raise ValueError("Invalid crn string, must have exactly 10 segments")

    kv_pairs = zip(SEGMENTS, vals)
    return CRN(**dict(kv_pairs))


if __name__ == "__main__":
    print(loads(sys.argv[1]))
