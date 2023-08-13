#!/usr/bin/env python3
import requests
import json
import argparse
import os
from pathlib import Path
from collections import namedtuple


users = {
    "",
}

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


AuthorizedKey = namedtuple("AuthorizedKey", field_names=["options", "keytype", "key", "comment"])

def parse_key(line:str) -> AuthorizedKey:
    return AuthorizedKey("", "", "", "")

def get_keys(username: str) -> set[str]:
    try:
        resp = requests.get(f"https://api.github.com/users/{username}/keys")
        resp.raise_for_status()
        return {ssh_key_obj["key"] for ssh_key_obj in resp.json()}
    except Exception as e:
        print(f"Failed to get keys for {username}", e)
        return set()


def update_authorized_keys(sentinel_id: str, user_keys: dict[str, set[str]]):
    authorized_keys_file = Path.home() / ".ssh/authorized_keys"
    authorized_keys_file.parent.mkdir(exist_ok=True)
    authorized_keys_lines = []
    if authorized_keys_file.exists():
        with open(authorized_keys_file, "rt") as f:
            authorized_keys_lines = f.readlines()
    authorized_keys = [parse_key(line) for line in authorized_keys_lines]
    # remove keys we've synced
    authorized_keys = [key for key in authorized_keys if not key.comment.startswith(sentinel_id)]
    authorized_keys +=




def main():
    parser = argparse.ArgumentParser(
        prog="sync_gh_keys",
        description="Keep a set of GitHub users public keys synced into authorized_keys"
    )
    parser.add_argument("--sentinel-id", default=parser.prog)
    _ = parser.parse_args()
    keys_to_sync = {}
    for username in users:
        keys_to_sync[username] = get_keys(username)

    update_authorized_keys(sentinel_id, keys_to_sync)


if __name__ == "__main__":
    main()
