import logging
import unittest
import os
import warnings

import redstone
from redstone import auth as bxauth


logging.basicConfig(level=logging.INFO)


class KeyProtectTestCase(unittest.TestCase):

    def setUp(self):
        # filter out the resource warning message
        warnings.simplefilter("ignore", ResourceWarning)

        apikey = os.environ.get('IBMCLOUD_API_KEY')
        tm = bxauth.TokenManager(api_key=apikey)
        self.rc = redstone.service("ResourceController")
        self.instance_id, self.crn = self.rc.create_instance(name="test-instance", plan_id=self.rc.KEYPROTECT_PLAN_ID,
                                                             region="us-south")
        self.kp = redstone.service("KeyProtect",
                                   credentials=tm,
                                   region="us-south",
                                   service_instance_id=self.instance_id,
                                   )

    def tearDown(self):
        try:
            for key in self.kp.keys():
                self.kp.delete(key.get('id'))
        finally:
            self.rc.delete_instance(self.instance_id)

    def test_key_alias(self):

        # test creating key alias
        self.key = self.kp.create(name="test-key", root=True)
        resp = self.kp.create_key_alias(self.key['id'], "testKeyAlias")
        self.assertEqual(resp['resources'][0]['keyId'], self.key['id'])
        self.assertEqual(resp['resources'][0]['alias'], "testKeyAlias")

        # test getting key by using the key alias
        resp = self.kp.get("testKeyAlias")
        self.assertEqual(resp['id'], self.key['id'])
        self.assertEqual(resp['aliases'][0], "testKeyAlias")

        # test deleting key alias
        resp = self.kp.delete_key_alias(self.key['id'], "testKeyAlias")
        self.assertEqual(resp, None)

        # clean up
        self.kp.delete(self.key.get('id'))


if __name__ == "__main__":
    unittest.main()