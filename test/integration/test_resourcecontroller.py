import logging
import unittest

import redstone


TEST_INSTANCE_NAME_PREFIX = "my-test-instance"


class ResourceControllerTestCase(unittest.TestCase):
    def tearDown(self):
        self.cleanup_instances()

    def cleanup_instances(self):
        rc = redstone.service("ResourceController")

        to_delete = filter(
            lambda x: x.get("name").startswith(TEST_INSTANCE_NAME_PREFIX),
            rc.list_instances(),
        )
        for inst in to_delete:
            rc.delete_instance(inst.get("id"))

    def test_delete_with_crn(self):
        rc = redstone.service("ResourceController")

        inst_id, crn = rc.create_instance(
            name=TEST_INSTANCE_NAME_PREFIX,
            plan_id=rc.KEYPROTECT_PLAN_ID,
            region="us-south",
        )

        rc.delete_instance(crn)

        self.assertIsNone(rc.get_instance(crn))

    def test_delete_with_id(self):
        rc = redstone.service("ResourceController")

        inst_id, crn = rc.create_instance(
            name=TEST_INSTANCE_NAME_PREFIX,
            plan_id=rc.KEYPROTECT_PLAN_ID,
            region="us-south",
        )

        rc.delete_instance(inst_id)

        self.assertIsNone(rc.get_instance(crn))


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
