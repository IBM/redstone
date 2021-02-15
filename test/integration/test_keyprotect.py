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

    def test_key_ring(self):
        # test creating key ring
        resp = self.kp.create_key_ring(self.instance_id, "testKeyRingIdPython")
        self.assertEqual(resp, 201)

        # test getting list of key ring
        resp = self.kp.get_key_rings(self.instance_id)
        for resource in resp['resources']:
            if resource['id'] != 'default':
                self.assertEqual(resource['id'], "testKeyRingIdPython")

        # test deleting key ring
        resp = self.kp.delete_key_ring(self.instance_id, "testKeyRingIdPython")
        self.assertEqual(resp, 204)


if __name__ == "__main__":
    unittest.main()