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

    def test_get_registrations(self):
        # create a key to be used for test
        key = self.kp.create(name="test-key", root=True)

        # get registrations associated with a key
        resp1 = self.kp.get_registrations(key['id'])
        self.assertEqual(resp1['metadata']['collectionTotal'], 0)

        #  get registrations associated with an instance
        resp2 = self.kp.get_registrations()
        self.assertGreaterEqual(resp2['metadata']['collectionTotal'], resp1['metadata']['collectionTotal'])

        # clean up
        self.kp.delete(key.get('id'))


if __name__ == "__main__":
    unittest.main()