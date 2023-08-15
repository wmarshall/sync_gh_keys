#!/usr/bin/env python3
import argparse
import os
import re
from collections import namedtuple
from pathlib import Path

import requests

ssh_key_types = {
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "ssh-ed25519",
    "ssh-dss",
    "ssh-rsa",
}
key_type_regex = "|".join(f"(?:{re.escape(k)})" for k in ssh_key_types)
authorized_key_regex = rf"^(?:(?P<options>.*)\s+)?(?P<keytype>{key_type_regex})\s+(?P<key>\S+)(?:\s+(?P<comment>.*))?$"


AuthorizedKey = namedtuple(
    "AuthorizedKey", field_names=["options", "keytype", "key", "comment"]
)


def parse_key(line: str) -> AuthorizedKey:
    match = re.match(authorized_key_regex, line)
    if match:
        return AuthorizedKey(
            options=match["options"],
            keytype=match["keytype"],
            key=match["key"],
            comment=match["comment"],
        )
    raise Exception(f"Failed to match {line} against {authorized_key_regex}")


def serialize_key(key: AuthorizedKey) -> str:
    return " ".join(f for f in key if f)


def get_keys(username: str) -> set[str]:
    try:
        resp = requests.get(f"https://api.github.com/users/{username}/keys")
        resp.raise_for_status()
        return {ssh_key_obj["key"] for ssh_key_obj in resp.json()}
    except Exception as e:
        print(f"Failed to get keys for {username}", e)
        return set()


def update_authorized_keys(
    sentinel_id: str, authorized_keys_path: str, user_keys: dict[str, set[str]]
):
    authorized_keys_file = Path(authorized_keys_path)
    authorized_keys_file.parent.mkdir(exist_ok=True)
    authorized_keys_lines = []
    if authorized_keys_file.exists():
        with open(authorized_keys_file, "rt") as f:
            authorized_keys_lines = [line.rstrip() for line in f.readlines()]
    existing_authorized_keys = {}
    for i, line in enumerate(authorized_keys_lines):
        if line == "" or line.startswith("#"):
            continue
        try:
            existing_authorized_keys[i] = parse_key(line)
        except Exception as e:
            print(f"{e} on line {i}, ignoring line")

    # remove keys we've synced
    existing_key_lines = {
        i
        for i, key in existing_authorized_keys.items()
        if key.comment.startswith(sentinel_id)
    }
    authorized_keys_lines = [
        line
        for i, line in enumerate(authorized_keys_lines)
        if i not in existing_key_lines
    ]

    # add synced keys
    for username, keys in user_keys.items():
        sentinel_comment = f"{sentinel_id}-{username}"
        for key in keys:
            authorized_key = parse_key(key)._replace(comment=sentinel_comment)
            authorized_keys_lines.append(serialize_key(authorized_key))

    # write back lines
    with open(authorized_keys_file, "wt") as f:
        f.writelines(line + "\n" for line in authorized_keys_lines)


def main():
    parser = argparse.ArgumentParser(
        prog="sync_gh_keys",
        description="Keep a set of GitHub users public keys synced into authorized_keys",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-s",
        "--sentinel-id",
        help="prefix for comment lines marking keys synced by this program",
        default=parser.prog,
    )
    parser.add_argument(
        "-a",
        "--authorized-keys-path",
        help="path to authorized_keys file to sync",
        default=(Path.home() / ".ssh/authorized_keys"),
    )
    parser.add_argument(
        "-u",
        "--users",
        help="comma-separated list of users to sync, can be specified multiple times",
        action="append",
        default=[],
    )
    args = parser.parse_args()
    users: set[str] = set()
    if len(args.users) == 0:
        args.users.append(os.environ.get("SYNC_GH_USERS", ""))
    for user_arg in args.users:
        user_arg: str
        users |= set(u for u in user_arg.split(",") if u != "")
    keys_to_sync = {}
    print(f"Syncing keys for {sorted(users)}")
    for username in sorted(users):
        keys_to_sync[username] = get_keys(username)

    update_authorized_keys(args.sentinel_id, args.authorized_keys_path, keys_to_sync)


if __name__ == "__main__":
    main()
