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

    def test_disable_enable_key(self):
        # create a key to be used for test
        self.key = self.kp.create(name="test-key", root=True)
        self.addCleanup(self.kp.delete, self.key.get("id"))

        # disable
        self.kp.disable_key(self.key.get("id"))
        resp = self.kp.get(self.key.get("id"))
        self.assertEqual(resp["state"], 2)

        # enable, must wait 30 sec or more before sending an enable
        time.sleep(30)

        self.kp.enable_key(self.key.get("id"))
        resp = self.kp.get(self.key.get("id"))
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
        self.key = self.kp.create(name="test-key", root=True)
        self.addCleanup(self.kp.delete, self.key.get("id"))

        # test creating key alias
        resp = self.kp.create_key_alias(self.key["id"], "testKeyAlias")
        self.assertEqual(resp["resources"][0]["keyId"], self.key["id"])
        self.assertEqual(resp["resources"][0]["alias"], "testKeyAlias")

        # test getting key by using the key alias
        resp = self.kp.get("testKeyAlias")
        self.assertEqual(resp["id"], self.key["id"])
        self.assertEqual(resp["aliases"][0], "testKeyAlias")

        # test deleting key alias
        resp = self.kp.delete_key_alias(self.key["id"], "testKeyAlias")
        self.assertEqual(resp, None)

    def test_get_registrations(self):
        # create a key to be used for test
        self.key = self.kp.create(name="test-key", root=True)
        self.addCleanup(self.kp.delete, self.key.get("id"))

        # get registrations associated with a key
        resp1 = self.kp.get_registrations(self.key["id"])
        self.assertEqual(resp1["metadata"]["collectionTotal"], 0)

        #  get registrations associated with an instance
        resp2 = self.kp.get_registrations()
        self.assertGreaterEqual(
            resp2["metadata"]["collectionTotal"], resp1["metadata"]["collectionTotal"]
        )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    unittest.main()
