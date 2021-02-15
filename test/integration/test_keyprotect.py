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

    def test_import_token(self):
        # create import token
        resp = self.kp.create_import_token(86400, 50)
        self.assertEqual(resp['maxAllowedRetrievals'], 50)
        self.assertEqual(resp['remainingRetrievals'], 50)

        # get import token
        resp = self.kp.get_import_token()
        self.assertEqual(resp['maxAllowedRetrievals'], 50)
        self.assertEqual(resp['remainingRetrievals'], 49)


if __name__ == "__main__":
    unittest.main()