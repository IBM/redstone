# Copyright 2020 Mathew Odden <mathewrodden@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import base64
import json
import logging
import os
import sys

import redstone


def lookup_instance(instance_id):
    rc = redstone.service("ResourceController")
    instance = rc.get_instance(instance_id)
    return instance


def pp_json(thing):
    print(json.dumps(thing, indent=4, sort_keys=True))


def _main():
    p = argparse.ArgumentParser()
    p.add_argument("--instance-id", "-i")

    subp = p.add_subparsers(dest="action")

    ilp = subp.add_parser("list-instances")

    lp = subp.add_parser("list")

    cp = subp.add_parser("create")
    cp.add_argument("name")
    cp.add_argument("--data")
    cp.add_argument("--exportable", action="store_true")

    gp = subp.add_parser("get")
    gp.add_argument("key_id")

    dp = subp.add_parser("delete")
    dp.add_argument("key_id", nargs="+")

    gmp = subp.add_parser("get_metadata")
    gmp.add_argument("key_id")

    rsp = subp.add_parser("restore")
    rsp.add_argument("key_id")
    rsp.add_argument("data")

    wp = subp.add_parser("wrap")
    wp.add_argument("key_id")
    wp.add_argument("--data")
    wp.add_argument("--aad")

    uwp = subp.add_parser("unwrap")
    uwp.add_argument("key_id")
    uwp.add_argument("data")
    uwp.add_argument("--aad")
    uwp.add_argument("--override-handle")

    rwp = subp.add_parser("rewrap")
    rwp.add_argument("key_id")
    rwp.add_argument("data")
    rwp.add_argument("--aad")

    rotate_p = subp.add_parser("rotate")
    rotate_p.add_argument("key_id")
    rotate_p.add_argument("--data")

    set_delete_p = subp.add_parser("set_key_for_delete")
    set_delete_p.add_argument("key_id", nargs="+")

    unset_delete_p = subp.add_parser("unset_key_for_delete")
    unset_delete_p.add_argument("key_id", nargs="+")

    disable_p = subp.add_parser("disable")
    disable_p.add_argument("key_id", nargs="+")

    enable_p = subp.add_parser("enable")
    enable_p.add_argument("key_id", nargs="+")

    get_reg_p = subp.add_parser("get_registrations")
    get_reg_p.add_argument("key_id")
    get_reg_p.add_argument("--crn")

    get_all_reg_p = subp.add_parser("get_all_registrations")
    get_all_reg_p.add_argument("--crn")

    create_imp_token_p = subp.add_parser("create_import_token")
    create_imp_token_p.add_argument("--expiration")
    create_imp_token_p.add_argument("--max_allowed_retrievals")

    get_imp_token_p = subp.add_parser("get_import_token")

    args = p.parse_args()

    if not args.action:
        p.print_usage()

    if args.action == "list-instances":
        rc = redstone.service("ResourceController")

        instances = rc.list_instances()
        kms_instances = list(
            filter(
                lambda x: x["type"] == "service_instance"
                and x.get("sub_type") == "kms",
                instances,
            )
        )

        render_list(
            kms_instances,
            fields=["guid", "name", "region_id"],
            titles=["ID", "NAME", "REGION"],
        )
        return

    instance_id = args.instance_id or os.environ.get("KP_INSTANCE_ID")
    if not instance_id:
        print("No instance ID given, set KP_INSTANCE_ID or pass --instance-id")
        return 1

    instance_data = lookup_instance(instance_id)
    if not instance_data:
        print("No instace found for ID: %s" % instance_id)
        return 1

    kp = redstone.service(
        "KeyProtect", service_instance_id=instance_id, region=instance_data["region_id"]
    )

    if args.action == "list":
        fields = ["id", "name", "extractable"]
        render_list(kp.keys(), fields=fields, titles=map(lambda x: x.upper(), fields))
    elif args.action == "create":
        key_data = None
        if args.data:
            key_data = args.data
        key = kp.create(args.name, raw_payload=key_data, root=not args.exportable)
        pp_json(key)
    elif args.action == "get":
        key = kp.get(args.key_id)
        pp_json(key)
    elif args.action == "get_metadata":
        key = kp.get_key_metadata(args.key_id)
        pp_json(key)
    elif args.action == "delete":
        for key_id in args.key_id:
            resp = kp.delete(key_id)
            print("Deleted key %s" % key_id)
    elif args.action == "restore":
        key_id = args.key_id
        key_data = None
        if args.data:
            key_data = args.data
        key = kp.restore(key_id, payload=key_data)
        print("Restored key %s" % key_id)
        pp_json(key)

    elif args.action == "wrap":
        plaintext = None
        if args.data:
            plaintext = args.data.encode()
        resp = kp.wrap(args.key_id, plaintext, args.aad)
        pp_json(resp)
    elif args.action == "unwrap":
        if args.override_handle:
            unpacked = json.loads(base64.b64decode(args.data.encode()).decode())
            unpacked["handle"] = args.override_handle
            data = base64.b64encode(json.dumps(unpacked).encode()).decode()
        else:
            data = args.data
        res = kp.unwrap(args.key_id, data, args.aad)
        print(base64.b64encode(res).decode())
    elif args.action == "rewrap":
        plaintext = None
        if args.data:
            plaintext = args.data.encode()
        resp = kp.rewrap(args.key_id, plaintext, args.aad)
        pp_json(resp)
    elif args.action == "rotate":
        new_key_data = None
        if args.data:
            new_key_data = args.data.encode()
        res = kp.rotate(args.key_id, new_key_data)
        print(res)
    elif args.action == "set_key_for_delete":
        for key_id in args.key_id:
            kp.set_key_for_delete(key_id)
            print("Set key %s for delete" % key_id)
    elif args.action == "unset_key_for_delete":
        for key_id in args.key_id:
            kp.unset_key_for_delete(key_id)
            print("Unset key %s for delete" % key_id)
    elif args.action == "disable":
        for key_id in args.key_id:
            kp.disable(key_id)
            print("Disabled key %s" % key_id)
    elif args.action == "enable":
        for key_id in args.key_id:
            resp = kp.enable(key_id)
            print("Enabled key %s" % key_id)
    elif args.action == "get_registrations":
        crn = None
        if args.crn:
            crn = args.crn.encode()
        registrations = kp.get_registrations(args.key_id, crn)
        pp_json(registrations)
    elif args.action == "get_all_registrations":
        crn = None
        if args.crn:
            crn = args.crn.encode()
        all_registrations = kp.get_all_registrations(crn)
        pp_json(all_registrations)
    elif args.action == "create_import_token":
        expiration = None
        max_allowed_retrievals = None
        if args.expiration:
            expiration = args.expiration
        if args.max_allowed_retrievals:
            max_allowed_retrievals = args.max_allowed_retrievals
        res = kp.create_import_token(expiration, max_allowed_retrievals)
        print(res)
    elif args.action == "get_import_token":
        res = kp.get_import_token()
        print(res)

def render_list(data, fields, titles):

    lengths = {}

    for datum in data:
        for field in fields:
            lengths[field] = max(len(str(datum.get(field, 0))), lengths.get(field, 0))

    fmt_str = " ".join(map(lambda x: "%%(%s)-%ds" % (x, lengths.get(x, 0) + 3), fields))

    print(fmt_str % dict(zip(fields, titles)))
    for datum in data:
        print(fmt_str % datum)


def main():
    logging.basicConfig(level=logging.INFO)
    sys.exit(_main())


if __name__ == "__main__":
    main()
