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
        self.rc.delete_instance(self.instance_id)
        self.kp.session.close()

    def test_key_policies(self):
        # create a key to be used for test
        self.key = self.kp.create(name="test-key", root=True)

        # test key rotation policy
        resp = self.kp.set_key_rotation_policy(self.key['id'], 2)
        self.assertEqual(resp['resources'][0]['rotation']['interval_month'], 2)

        # test key dual auth delete policy, set to False so that it can be cleaned up
        resp = self.kp.set_key_dual_auth_policy(self.key['id'], False)
        self.assertFalse(resp['resources'][0]['dualAuthDelete']['enabled'])

        # test get key policies
        resp = self.kp.get_key_policies(self.key['id'])
        if 'rotation' in resp['resources'][0]:
            self.assertEqual(resp['resources'][0]['rotation']['interval_month'], 2)
            self.assertFalse(resp['resources'][1]['dualAuthDelete']['enabled'])
        else:
            self.assertEqual(resp['resources'][1]['rotation']['interval_month'], 2)
            self.assertFalse(resp['resources'][0]['dualAuthDelete']['enabled'])

        # clean up
        self.kp.delete(self.key.get('id'))

    def test_instance_policies(self):
        # set instance dual auth delete policy
        self.kp.set_instance_dual_auth_policy(True)

        # set instance allowed network policy
        self.kp.set_instance_allowed_network_policy(True, "public-and-private")

        # get instance policies
        resp = self.kp.get_instance_policies()
        valid_policy_types = ['dualAuthDelete', 'allowedNetwork']
        self.assertIn(resp['resources'][0]['policy_type'], valid_policy_types)
        self.assertIn(resp['resources'][1]['policy_type'], valid_policy_types)
        if resp['resources'][0]['policy_type'] == 'dualAuthDelete':
            self.assertTrue(resp['resources'][0]['policy_data']['enabled'])
            self.assertTrue(resp['resources'][1]['policy_data']['enabled'])
            self.assertEqual(resp['resources'][1]['policy_data']['attributes']['allowed_network'], 'public-and-private')
        else:
            self.assertTrue(resp['resources'][1]['policy_data']['enabled'])
            self.assertTrue(resp['resources'][0]['policy_data']['enabled'])
            self.assertEqual(resp['resources'][0]['policy_data']['attributes']['allowed_network'], 'public-and-private')


if __name__ == "__main__":
    unittest.main()