import logging
import unittest
import os
import warnings
import time

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

    def test_disable_enable_key(self):
        # create a key to be used for test
        self.key = self.kp.create(name="test-key", root=True)

        # disable
        self.kp.disable_key(self.key.get('id'))
        resp = self.kp.get(self.key.get('id'))
        self.assertEqual(resp['state'], 2)

        # enable, must wait 30 sec or more before sending an enable
        time.sleep(30)
        self.kp.enable_key(self.key.get('id'))
        resp = self.kp.get(self.key.get('id'))
        self.assertEqual(resp['state'], 1)

        # clean up
        self.kp.delete(self.key.get('id'))


if __name__ == "__main__":
    unittest.main()