# redstone - A Pythonic IBM Cloud SDK

Redstone is a Python library for interacting with IBM Cloud services.
Its main objectives are to make consuming the many services easier
and more consistent across the entire set of IBM Cloud services.

The current state is very incomplete, but there are some common service
clients that many people within IBM would probably find useful, 
so I have published them here in a consumable form.

Contributions in the form of feedback, patches, or bugs are appreciated.

# usage

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
