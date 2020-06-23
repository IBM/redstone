# redstone - A Pythonic IBM Cloud SDK

[![Documentation Status](https://readthedocs.org/projects/redstone-py/badge/?version=latest)](https://redstone-py.readthedocs.io/en/latest/?badge=latest)
[![Gitter](https://badges.gitter.im/python-redstone/community.svg)](https://gitter.im/python-redstone/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

Redstone is a Python library for interacting with IBM Cloud services.

It currently includes support for IBM KeyProtect, IBM Kubernetes Service (IKS), and some
platform services like ResourceController and IAM.

Contributions in the form of feedback, patches, or bugs are appreciated. A [Gitter Channel](https://gitter.im/python-redstone/community?utm_source=share-link&utm_medium=link&utm_campaign=share-link) is available for questions and development discussion.


* [Installation](#installation)
* [Usage](#usage)
* [rs-crypto](#encrypting-data-using-redstonecrypto-with-keyprotect)
* [rs-keyprotect](#using-the-rs-keyprotect-cli)


# Installation

You can install `redstone` with:

```sh
$ pip3 install redstone

# alternatively, you can do a user install if you are not an admin on your box
$ pip3 install --user redstone
```

# Usage

A default session is created for you on first access, which can be used to access service interfaces scoped to that account.
Default sessions will read an API key from the conventional `IBMCLOUD_API_KEY` environment variable.

Using the default session to get a CIS (Cloud Internet Services) client:

```python
>>> import redstone
>>> import os
>>> cis = redstone.service("CIS", service_instance_id=os.environ.get("CIS_CRN"))
>>> cis
<redstone.client.CIS object at 0x...>
>>> sorted(map(lambda x: x.get("name"), cis.pools()))
['au-syd', 'eu-de', 'eu-de-ams', 'eu-de-fra', 'eu-de-private', 'eu-gb', 'eu-gb-private', 'eu-syd-private', 'jp-tok', 'jp-tok-02', 'jp-tok-04', 'preprod', 'private-jp-tok', 'private-us-south', 'us-east', 'us-east-private', 'us-south']
>>>
```

Build your own session for interacting with multiple regions and/or accounts within the same Python context:

```python
>>> production = redstone.Session(
...     region="us-south",
...     iam_api_key=os.environ.get("IBMCLOUD_API_KEY")
... )
>>> production
<redstone.Session object at 0x...>
>>> rc = production.service("ResourceController")
>>> rc
<redstone.client.ResourceController object at 0x...>
>>> instance_id, instance_crn = rc.create_instance(name="mykpinstance")
>>> instance_crn
'crn:v1:bluemix:public:kms:us-south:a/...::'
>>> kp = production.service("KeyProtect", service_instance_id=instance_id)
>>> key = kp.create(name="mykey")
>>> key.get("name")
'mykey'
>>> kp.delete(key.get("id"))
>>> rc.delete_instance(instance_crn)
>>>
```

# Encrypting data using redstone.crypto with KeyProtect

Redstone includes support for directly encrypting and decrypting files or other data using IBM KeyProtect as a key provider.
There are two ways to use the crypto functionality, a CLI tool and the python module.

## rs-crypto CLI tool

Upon installing the redstone module with pip, it will also install a command-line script under `rs-crypto` that can
be used to encrypt and decrypt.

The script will read the API key used to interact with KeyProtect from the `IBMCLOUD_API_KEY` environment variable.

Encrypting a file is straight forward with the `encrypt` commmand. The encrypted data will be printed to stdout, and
can be redirected to a file.

```sh
IBMCLOUD_API_KEY=... rs-crypto encrypt --key-crns "crn:v1... crn:v1..." my-super-secret-file.txt > my-encrypted-file
```

Decrypting is similar. Note that the tool will print raw bytes to stdout, so you will probably want
to redirect to a file if the original data was binary.

```sh
IBMCLOUD_API_KEY=... rs-crypto decrypt my-encrypted-file > my-decrypted-file
```

The output of encrypt can be fed directly back to decrypt.

```sh
# you can also pipe directly to stdin by specifying the file as '-'
echo "some-secret-data" | rs-crypto encrypt --key-crns "crn:v1... crn:v1..." - | rs-crypto decrypt -
```


## using redstone.crypto

The python module is designed to be easy to use, even for those not familiar with python.

```python
import os
import sys

from redstone import crypto

# NOTE: here we demonstrate how we can use several keys that come from different instances and even different regions
# only one of the keys needs to be available for the decrypt operation to succeed
crns = [
    "crn:v1:bluemix:public:kms:us-south:a/...:415ba6f3-43f9-4996-0000-123456789:key:94e2639b-af2f-4f4f-a415-bb63820cf976",
    "crn:v1:bluemix:public:kms:us-east:a/...:077a4670-c2f2-415c-0000-123456789:key:1f5ead7e-a1f4-4d15-9641-80e9aa5c7e12",
]

if not os.getenv("IBMCLOUD_API_KEY"):
    print("Remember to set 'IBMCLOUD_API_KEY' as the internal client uses that for authentication", file=sys.stderr)
    sys.exit(1)

# read bytes from stdin and encrypt
message, meta = crypto.encrypt(sys.stdin.buffer.read(), key_crns=crns)
print("Encrypted value: %r" % message)

message, meta = crypto.decrypt(message)

print("%r" % message)
print("%r" % meta)
```


## Finding Key CRNs

KeyProtect CRKs to be used for encryption are specified via `--key-crns` as a space separated list, or the `RSCRYPTO_KEY_CRNS` environment variable.
Key CRNs can be found via the IBM Cloud Console (KeyProtect UI) or the IBM Cloud CLI. (You will need the kp plugin.)

```sh
# Using the ic kp plugin to find a CRN
ic kp get -o json -i $instance_uuid $key_uuid
{
        "id": "94e2639b-af2f-4f4f-a415-bb63820cf976",
        "name": "the-one-key",
        "type": "application/vnd.ibm.kms.key+json",
        "extractable": false,
        "state": 1,
        "crn": "crn:v1:bluemix:public:kms:us-south:a/....:415ba6f3-43f9-4996-abcd-1234346:key:94e2639b-af2f-4f4f-a415-bb63820cf976"
}
```

# Using the rs-keyprotect CLI

rs-keyprotect is a quick stand-alone CLI utility for interacting with KeyProtect via terminal or shell scripts.

```sh
# set an API for the account you wish to interact with
export IBMCLOUD_API_KEY=...

# list KeyProtect instances in the account
rs-keyprotect list-instances
ID                                      NAME              REGION
07096bd5-6e6f-4b75-9978-9cbb18ce9a16    keyptest1         us-south
143ac075-31ad-4bcc-bc9f-c352ea6bd213    Key Protect-y6    us-south

# list the keys of an instance
rs-keyprotect -i fb680ac4-e2d7-40c3-8b64-be59b13236cd list
ID                                      NAME                     EXTRACTABLE
52c3eea1-6db7-4dd8-8540-5d95af8c621b    kpregress_at_pass_key    False   
e5931fa2-5830-4f12-9cfa-3d0099f79929    kpregress_at_pass_key    False   
```

For more usage, run `rs-keyprotect -h` and `rs-keyprotect <command> -h`
