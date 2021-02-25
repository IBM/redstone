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

import base64
import json
import logging
import os
from typing import List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import redstone
import redstone.crn


LOG = logging.getLogger(__name__)


class MessageHeader(object):

    version = 1

    def __init__(self, data_keys, aad, algorithm):
        self.data_keys = data_keys
        self.aad = aad
        self.algorithm = algorithm

    def _pack(self):
        message_header_data = {
            "data_keys": self.data_keys,
            "aad": self.aad,
            "algorithm": self.algorithm,
        }
        message_header = base64.b64encode(
            json.dumps(message_header_data).encode("utf-8")
        )
        message_header = (
            _message_version_to_bytes(self.version)
            + len(message_header).to_bytes(8, byteorder="big")
            + message_header
        )
        return message_header

    @staticmethod
    def from_message_with_body(message: bytes) -> "Tuple[MessageHeader, bytes]":
        version = get_message_version(message)
        if version != MessageHeader.version:
            raise Exception(
                "Invalid message version. Expecting %d, found %d"
                % (MessageHeader.version, version)
            )

        header_len = int.from_bytes(message[1:9], byteorder="big")
        header_bytes = message[9 : header_len + 9]
        header_dict = json.loads(base64.b64decode(header_bytes).decode("utf-8"))
        return MessageHeader(**header_dict), message[header_len + 9 :]

    def __repr__(self):
        prop_strs = [
            "%s=%r" % (key, getattr(self, key))
            for key in ["version", "data_keys", "aad", "algorithm"]
        ]
        return "<%s %s>" % (type(self).__name__, ", ".join(prop_strs))


def encrypt(
    source: bytes,
    key_crns: List[str],
    aad: Optional[str] = None,
    session: Optional[redstone.Session] = None,
) -> Tuple[bytes, MessageHeader]:
    """Encrypt byte data using a given set of keys from KeyProtect."""

    if session is None:
        session = redstone.get_default_session()

    # generate deks with keyprotect master keys
    data_keys = []
    pt_data_key = b""
    for key_crn in key_crns:
        crn = redstone.crn.loads(key_crn)
        kp = session.service(
            "KeyProtect", region=crn.location, service_instance_id=crn.service_instance
        )

        dek_data = kp.wrap(crn.resource, pt_data_key, aad=[aad])
        if not pt_data_key:
            # plaintext is returned as a utf8 string of base64 in the `plaintext` field
            pt_data_key = base64.b64decode(dek_data["plaintext"].encode("utf-8"))

        # ciphertext is also a utf8 string,
        # but we don't need to do anything but store it for now
        data_keys.append(
            {
                "ciphertext": dek_data["ciphertext"],
                "key_crn": key_crn,
            }
        )

    # we now have all the data keys and plaintext form to do some encryption with

    # bail if we didn't get a 32 byte key from keyprotect,
    # this shouldn't happen but...
    # if it ever does we don't EVER want to go forward with a weak key
    if len(pt_data_key) != 32:
        raise Exception("Plaintext key from KMS was not 256 bits!")

    gcm = AESGCM(pt_data_key)

    # use standard 12 byte nonce
    nonce = os.urandom(
        12
    )  # see: https://cryptography.io/en/latest/random-numbers/#random-number-generation

    # tag is the last 16 bytes
    ciphertext_and_tag = gcm.encrypt(
        nonce, source, aad.encode("utf-8") if aad else None
    )

    # prepend nonce to ct and tag
    encrypted_message = nonce + ciphertext_and_tag

    message_header = MessageHeader(data_keys=data_keys, aad=aad, algorithm="AES256-GCM")

    return message_header._pack() + encrypted_message, message_header


def decrypt(
    source: bytes, session: Optional[redstone.Session] = None
) -> Tuple[bytes, MessageHeader]:
    """Decrypt data previously encrypted with the encrypt function."""

    if session is None:
        session = redstone.get_default_session()

    # unpack headers to get crypto information
    header, message = MessageHeader.from_message_with_body(source)

    pt_data_key = None
    for data_key in header.data_keys:
        # NOTE(mrodden): might be good to prefer a local region here sometime
        crn = redstone.crn.loads(data_key["key_crn"])
        LOG.info("Decrypting data key with master key: %s" % crn)
        kp = session.service(
            "KeyProtect", region=crn.location, service_instance_id=crn.service_instance
        )
        try:
            pt_data_key = kp.unwrap(
                crn.resource, data_key["ciphertext"], aad=[header.aad]
            )
        except Exception as ex:
            LOG.warning("Exception while attempting unwap: %s" % str(ex))
            continue
        if pt_data_key:
            LOG.info("Decrypted data key.")
            break

    if pt_data_key is None:
        raise Exception("Failed to unwrap any keys!")

    # got key, decrypt
    gcm = AESGCM(pt_data_key)
    plaintext_message = gcm.decrypt(
        message[:12], message[12:], header.aad.encode("utf-8") if header.aad else None
    )

    return plaintext_message, header


def get_message_version(message_header: bytes) -> int:
    return int.from_bytes(message_header[:1], byteorder="big")


def _message_version_to_bytes(version: int) -> bytes:
    return version.to_bytes(1, byteorder="big")
