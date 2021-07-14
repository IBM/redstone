import logging
import time
import unittest

import redstone


class KeyProtectTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rc = redstone.service("ResourceController")
        cls.instance_id, cls.crn = cls.rc.create_instance(
            name="redstone-keyprotect-integration-tests",
            plan_id=cls.rc.KEYPROTECT_PLAN_ID,
            region="us-south",
        )

        cls.kp = redstone.service(
            "KeyProtect", region="us-south", service_instance_id=cls.instance_id
        )

    @classmethod
    def tearDownClass(cls):
        try:
            for key in cls.kp.keys():
                cls.kp.delete(key.get("id"))
        finally:
            cls.rc.delete_instance(cls.instance_id)

    def test_create_key(self):
        # create a key
        resp = self.kp.create(name="test-key", root=True)
        self.addCleanup(self.kp.delete, resp.get("id"))
        self.assertEqual(resp["state"], 1)
        self.assertEqual(resp["name"], "test-key")

    def test_create_key_with_alias(self):
        # create a key with aliases
        resp = self.kp.create(
            name="test-key",
            root=True,
            alias_list=["key_alias_1", "key_alias_2", "key_alias_3"],
        )
        self.addCleanup(self.kp.delete, resp.get("id"))
        self.assertEqual(resp["state"], 1)
        self.assertEqual(resp["name"], "test-key")
        self.assertEqual(len(resp["aliases"]), 3)
        self.assertEqual(resp["aliases"][0], "key_alias_1")

    def test_create_key_with_more_then_5_alias(self):
        # create a key with more than 5 aliases, should raise ValueError
        with self.assertRaises(ValueError):
            self.kp.create(
                name="test-key",
                root=True,
                alias_list=[
                    "key_alias_1",
                    "key_alias_2",
                    "key_alias_3",
                    "key_alias_4",
                    "key_alias_5",
                    "key_alias_6",
                ],
            )

    def test_get_key(self):
        # create a key to be used for test
        key = self.kp.create(name="test-key", root=True)
        self.addCleanup(self.kp.delete, key.get("id"))
        resp = self.kp.get_key(key_id_or_alias=key.get("id"))
        self.assertEqual(resp["state"], 1)
        self.assertEqual(resp["name"], "test-key")

    def test_get_key_using_alias(self):
        # create a key to be used for test
        key = self.kp.create(name="test-key", root=True, alias_list=["key_alias"])
        self.addCleanup(self.kp.delete, key.get("id"))
        resp = self.kp.get_key(key_id_or_alias="key_alias")
        self.assertEqual(resp["state"], 1)
        self.assertEqual(resp["name"], "test-key")
        self.assertEqual(resp["aliases"][0], "key_alias")

    def test_wrap_unwrap(self):
        # create a key to be used for test
        key = self.kp.create(name="test-key", root=True)
        self.addCleanup(self.kp.delete, key.get("id"))
        # wrap
        message = b"This is a really important message."
        wrapped = self.kp.wrap(key.get("id"), message)
        ciphertext = wrapped.get("ciphertext")
        # unwrap
        unwrapped = self.kp.unwrap(key.get("id"), ciphertext)
        self.assertEqual(message, unwrapped)

    def test_wrap_unwrap_with_aad(self):
        # create a key to be used for test
        key = self.kp.create(name="test-key", root=True)
        self.addCleanup(self.kp.delete, key.get("id"))
        # wrap
        message = b"This is a really important message."
        wrapped = self.kp.wrap(key.get("id"), message, aad=["python-keyprotect"])
        ciphertext = wrapped.get("ciphertext")
        # unwrap
        unwrapped = self.kp.unwrap(key.get("id"), ciphertext, aad=["python-keyprotect"])
        self.assertEqual(message, unwrapped)

    def test_disable_enable_key(self):
        # create a key to be used for test
        key = self.kp.create(name="test-key", root=True)
        self.addCleanup(self.kp.delete, key.get("id"))

        # disable
        self.kp.disable_key(key.get("id"))
        resp = self.kp.get(key.get("id"))
        self.assertEqual(resp["state"], 2)

        # enable, must wait 30 sec or more before sending an enable
        time.sleep(30)

        self.kp.enable_key(key.get("id"))
        resp = self.kp.get(key.get("id"))
        self.assertEqual(resp["state"], 1)

    def test_restore_key(self):
        # create a key to be used for test
        key = self.kp.create(name="test-key", root=True)
        key_id = key.get("id")
        self.addCleanup(self.kp.delete, key_id)

        # delete the key
        self.kp.delete(key_id)
        resp = self.kp.get(key_id)
        # state Destroyed = 5
        self.assertEqual(resp["state"], 5)

        # restore, must wait 30 sec or more before sending an restore
        time.sleep(30)

        self.kp.restore_key(key_id)
        resp = self.kp.get(key_id)
        # state Active = 1
        self.assertEqual(resp["state"], 1)

    def test_key_ring(self):
        # test creating key ring
        resp = self.kp.create_key_ring("testKeyRingIdPython")

        # test getting list of key ring
        resp = self.kp.get_key_rings()
        for resource in resp["resources"]:
            if resource["id"] != "default":
                self.assertEqual(resource["id"], "testKeyRingIdPython")

        # test deleting key ring
        resp = self.kp.delete_key_ring("testKeyRingIdPython")

    def test_import_token(self):
        # create import token
        resp = self.kp.create_import_token(expiration=86400, max_allowed_retrievals=50)
        self.assertEqual(resp["maxAllowedRetrievals"], 50)
        self.assertEqual(resp["remainingRetrievals"], 50)

        # get import token
        resp = self.kp.get_import_token()
        self.assertEqual(resp["maxAllowedRetrievals"], 50)
        self.assertEqual(resp["remainingRetrievals"], 49)

    def test_key_alias(self):
        # create a key to be used for test
        key = self.kp.create(name="test-key", root=True)
        self.addCleanup(self.kp.delete, key.get("id"))

        # test creating key alias
        resp = self.kp.create_key_alias(key["id"], "testKeyAlias")
        self.assertEqual(resp["resources"][0]["keyId"], key["id"])
        self.assertEqual(resp["resources"][0]["alias"], "testKeyAlias")

        # test getting key by using the key alias
        resp = self.kp.get("testKeyAlias")
        self.assertEqual(resp["id"], key["id"])
        self.assertEqual(resp["aliases"][0], "testKeyAlias")

        # test deleting key alias
        resp = self.kp.delete_key_alias(key["id"], "testKeyAlias")
        self.assertEqual(resp, None)

    def test_get_registrations(self):
        # create a key to be used for test
        key = self.kp.create(name="test-key", root=True)
        self.addCleanup(self.kp.delete, key.get("id"))

        # get registrations associated with a key
        resp1 = self.kp.get_registrations(key["id"])
        self.assertEqual(resp1["metadata"]["collectionTotal"], 0)

        #  get registrations associated with an instance
        resp2 = self.kp.get_registrations()
        self.assertGreaterEqual(
            resp2["metadata"]["collectionTotal"], resp1["metadata"]["collectionTotal"]
        )

    def test_key_policies(self):
        # create a key to be used for test
        key = self.kp.create(name="test-key", root=True)
        self.addCleanup(self.kp.delete, key.get("id"))

        # test key rotation policy
        resp = self.kp.set_key_rotation_policy(key["id"], rotation_interval=2)
        self.assertEqual(resp["resources"][0]["rotation"]["interval_month"], 2)

        # test key dual auth delete policy, set to False so that it can be cleaned up
        resp = self.kp.set_key_dual_auth_policy(key["id"], dual_auth_enable=False)
        self.assertFalse(resp["resources"][0]["dualAuthDelete"]["enabled"])

        # test get key policies
        resp = self.kp.get_key_policies(key["id"])

        self.assertEqual(len(resp["resources"]), 2)
        for resource in resp["resources"]:
            if "rotation" in resource:
                self.assertEqual(resource["rotation"]["interval_month"], 2)
            else:
                self.assertFalse(resource["dualAuthDelete"]["enabled"])

    def test_instance_policies(self):
        # set instance dual auth delete policy
        self.kp.set_instance_dual_auth_policy(dual_auth_enable=False)

        # set instance allowed network policy
        self.kp.set_instance_allowed_network_policy(
            allowed_network_enable=True, network_type="public-and-private"
        )

        # set instance metrics policy
        self.kp.set_instance_metrics_policy(metrics_enable=True)

        # set instance keyCreateImportAccess policy
        self.kp.set_instance_key_create_import_access_policy(
            key_create_import_access_enable=True,
            create_root_key=True,
            create_standard_key=True,
            import_root_key=True,
            import_standard_key=True,
            enforce_token=False,
        )

        # get instance policies
        resp = self.kp.get_instance_policies()

        self.assertEqual(len(resp["resources"]), 4)
        for resource in resp["resources"]:
            if "dualAuthDelete" in resource["policy_type"]:
                self.assertFalse(resource["policy_data"]["enabled"])
            elif "allowedNetwork" in resource["policy_type"]:
                self.assertTrue(resource["policy_data"]["enabled"])
                self.assertEqual(
                    resource["policy_data"]["attributes"]["allowed_network"],
                    "public-and-private",
                )
            elif "metrics" in resource["policy_type"]:
                self.assertTrue(resource["policy_data"]["enabled"])
            elif "keyCreateImportAccess" in resource["policy_type"]:
                self.assertTrue(resource["policy_data"]["enabled"])
                self.assertTrue(
                    resource["policy_data"]["attributes"]["create_root_key"]
                )
                self.assertTrue(
                    resource["policy_data"]["attributes"]["create_standard_key"]
                )
                self.assertTrue(
                    resource["policy_data"]["attributes"]["import_root_key"]
                )
                self.assertTrue(
                    resource["policy_data"]["attributes"]["import_standard_key"]
                )
                self.assertFalse(resource["policy_data"]["attributes"]["enforce_token"])

    def test_set_keyring(self):
        # create a key to be used for test, the key will by default be created in the 'default' key ring
        key = self.kp.create(name="test-key", root=True)
        key_id = key.get("id")
        self.addCleanup(self.kp.delete, key_id)

        # create a key ring to be used for test
        new_key_ring_id = "testKeyRingIdPython"
        self.kp.create_key_ring(new_key_ring_id)

        # transfer key to associate with new key ring
        self.kp.set_key_ring(
            key_id=key_id, key_ring_id="default", new_key_ring_id=new_key_ring_id
        )
        resp = self.kp.get_key(key_id_or_alias=key_id)
        self.assertEqual(resp["keyRingID"], "testKeyRingIdPython")

    def test_purge_key_fail_too_early(self):
        # create a key to be used for test
        key = self.kp.create(name="test-key", root=True)
        key_id = key.get("id")
        # delete the key
        self.kp.delete(key_id)
        with self.assertRaises(redstone.client.KeyProtect.KeyProtectError) as cm:
            self.kp.purge_key(key_id=key_id)
        self.assertIn("REQ_TOO_EARLY_ERR", str(cm.exception))

    def test_purge_key_fail_invalid_state(self):
        # create a key to be used for test
        key = self.kp.create(name="test-key", root=True)
        key_id = key.get("id")
        self.addCleanup(self.kp.delete, key_id)
        with self.assertRaises(redstone.client.KeyProtect.KeyProtectError) as cm:
            self.kp.purge_key(key_id=key_id)
        self.assertIn("KEY_ACTION_INVALID_STATE_ERR", str(cm.exception))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    unittest.main()
