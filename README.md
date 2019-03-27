# redstone - A Pythonic IBM Cloud SDK

Redstone is a Python library for interacting with IBM Cloud services.
It's goals are to make consuming the many services easier
and more consistent across the entire set of IBM Cloud services.

The current state is very incomplete, as it is built as a side effect of service testing,
but there are some common service clients that many people
within IBM would probably find useful, so I have published them here
in a consumable form.

Contributions in the form of feedback, patches, or bugs are appreciated.

# sample usage

Using the default session to get a KeyProtect client:

``` {.sourceCode python}
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

``` {.sourceCode python}
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
