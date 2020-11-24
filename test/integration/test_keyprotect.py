import logging
import unittest
import os
import time
import warnings

import redstone
from redstone import auth as bxauth


logging.basicConfig(level=logging.INFO)


class KeyProtectTestCase(unittest.TestCase):

    def setUp(self):
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
        self.key = self.kp.create(name="test-key", root=True)
        self.import_key = self.kp.create(name="test-imported-key", payload=b"Payload for test", root=True)

    def tearDown(self):
        for key in self.kp.keys():
            self.kp.delete(key.get('id'))

        self.rc.delete_instance(self.instance_id)
        self.kp.session.close()

    def test_wrap_unwrap_rotate_rewrap(self):
        # wrapping message
        message = b'This is a really important message.'
        wrapped = self.kp.wrap(self.key.get('id'), message)
        ciphertext = wrapped.get("ciphertext")
        # unwrapping
        unwrapped = self.kp.unwrap(self.key.get('id'), ciphertext)
        self.assertEqual(message, unwrapped)
        # rotate key
        rotated = self.kp.rotate(self.key.get('id'))
        # rewrapping
        rewrapped = self.kp.rewrap(self.key.get('id'), ciphertext)
        self.assertNotEqual(rewrapped['ciphertext'], ciphertext)
        self.assertNotEqual(rewrapped['rewrappedKeyVersion']['id'], self.key.get('id'))

    def test_wrap_unwrap_rotate_rewrap_with_aad(self):
        # wrapping message
        message = b'This is a really important message.'
        wrapped = self.kp.wrap(self.key.get('id'), message, aad=['python-keyprotect'])
        ciphertext = wrapped.get("ciphertext")
        # unwrapping
        unwrapped = self.kp.unwrap(self.key.get('id'), ciphertext, aad=['python-keyprotect'])
        self.assertEqual(message, unwrapped)
        # rotate key
        self.kp.rotate(self.key.get('id'))
        # rewrapping
        rewrapped = self.kp.rewrap(self.key.get('id'), ciphertext, aad=['python-keyprotect'])
        self.assertNotEqual(rewrapped['ciphertext'], ciphertext)
        self.assertNotEqual(rewrapped['rewrappedKeyVersion']['id'], self.key.get('id'))

    def test_restore_key(self):
        self.kp.delete(self.import_key.get('id'))
        resp = self.kp.get(self.import_key.get('id'))
        self.assertEqual(resp['state'], 5)

        # restore, must wait 30 sec or more before sending an restore
        time.sleep(30)
        self.kp.restore(self.import_key.get('id'), payload=b"Payload for test")
        resp = self.kp.get(self.import_key.get('id'))
        self.assertEqual(resp['state'], 1)

    def test_disable_enable_key(self):
        # disable
        self.kp.disable_key(self.key.get('id'))
        resp = self.kp.get(self.key.get('id'))
        self.assertEqual(resp['state'], 2)

        # enable, must wait 30 sec or more before sending an enable
        time.sleep(30)
        self.kp.enable_key(self.key.get('id'))
        resp = self.kp.get(self.key.get('id'))
        self.assertEqual(resp['state'], 1)

    def test_import_get_token(self):
        # create import token
        resp = self.kp.create_import_token(86400, 50)
        self.assertEqual(resp['maxAllowedRetrievals'], 50)
        self.assertEqual(resp['remainingRetrievals'], 50)

        # get import token
        resp = self.kp.get_import_token()
        self.assertEqual(resp['maxAllowedRetrievals'], 50)
        self.assertEqual(resp['remainingRetrievals'], 49)

    def test_get_registrations(self):
        # get registrations associated with a key
        resp1 = self.kp.get_registrations(self.key['id'])
        self.assertEqual(resp1['metadata']['collectionTotal'], 0)

        #  get registrations associated with an instance
        resp2 = self.kp.get_registrations()
        self.assertGreaterEqual(resp2['metadata']['collectionTotal'], resp1['metadata']['collectionTotal'])

    def test_key_policies(self):
        # test key rotation policy
        resp = self.kp.set_key_rotation_policy(self.key['id'], 2)
        self.assertEqual(resp['resources'][0]['rotation']['interval_month'], 2)
        # test key dual auth delete policy, set to False so that it can be cleaned up
        resp = self.kp.set_key_dual_auth_policy(self.key['id'], False)
        self.assertEqual(resp['resources'][0]['dualAuthDelete']['enabled'], False)
        # test get key policies
        resp = self.kp.get_key_policies(self.key['id'])
        if 'rotation' in resp['resources'][0]:
            self.assertEqual(resp['resources'][0]['rotation']['interval_month'], 2)
            self.assertEqual(resp['resources'][1]['dualAuthDelete']['enabled'], False)
        else:
            self.assertEqual(resp['resources'][1]['rotation']['interval_month'], 2)
            self.assertEqual(resp['resources'][0]['dualAuthDelete']['enabled'], False)

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
            self.assertEqual(resp['resources'][0]['policy_data']['enabled'], True)
            self.assertEqual(resp['resources'][1]['policy_data']['enabled'], True)
            self.assertEqual(resp['resources'][1]['policy_data']['attributes']['allowed_network'], 'public-and-private')
        else:
            self.assertEqual(resp['resources'][1]['policy_data']['enabled'], True)
            self.assertEqual(resp['resources'][0]['policy_data']['enabled'], True)
            self.assertEqual(resp['resources'][0]['policy_data']['attributes']['allowed_network'], 'public-and-private')


if __name__ == "__main__":
    unittest.main()
