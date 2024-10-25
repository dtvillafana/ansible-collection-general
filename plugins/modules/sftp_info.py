#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: sftp_info
author: David Villafana

short_description: List files on remote SFTP server

version_added: "1.0.0"

description:
  - This module allows listing files using SFTP.
  - This module supports file globbing for listing multiple files (however, does not support pathname expansion, e.g. '**' characters).
  - Supports both password and SSH key authentication methods.

requirements:
  - python paramiko

options:
  host:
    description:
    - The IP address or hostname of source SFTP server.
    required: True
    type: str
  port:
    description:
    - The port of source SFTP server.
    required: False
    default: 22
    type: int
  username:
    description:
    - The username for the connection.
    required: True
    type: str
  password:
    description:
    - The password for the connection.
    - Required if private_key is not provided.
    required: False
    type: str
  private_key:
    description:
    - Path to private key file for SSH key authentication.
    - Required if password is not provided.
    required: False
    type: str
  private_key_passphrase:
    description:
    - Passphrase for encrypted private key file.
    required: False
    type: str
  remote_path:
    description:
    - The path to the source file or glob pattern on the remote server.
    required: True
    type: str
  host_key_algorithms:
    description:
    - List of allowed host key algorithms.
    - If not specified, Paramiko's default algorithms will be used.
    required: False
    type: list
    elements: str
"""

EXAMPLES = r"""
- name: list files using globbing
  dtvillafana.general.sftp_info:
    host: 1.2.3.4
    username: foo
    password: bar
    remote_path: '/remote/path/*.txt'
    host_key_algorithms:
      - 'ssh-ed25519'
      - 'ecdsa-sha2-nistp256'

- name: list all files in a directory
  dtvillafana.general.sftp_info:
    host: 1.2.3.4
    username: foo
    password: bar
    remote_path: '/remote/path/'
    host_key_algorithms:
      - 'ssh-ed25519'
      - 'ecdsa-sha2-nistp256'

- name: list files using password protected SSH key
  dtvillafana.general.sftp_info:
    host: 1.2.3.4
    username: foo
    private_key: '/path/to/private_key'
    private_key_passphrase: 'optional_passphrase'
    remote_path: '/remote/path/*.txt'
    host_key_algorithms:
      - 'ssh-ed25519'
      - 'ecdsa-sha2-nistp256'

- name: list files in a directory using SSH key
  dtvillafana.general.sftp_info:
    host: 1.2.3.4
    username: foo
    private_key: '/path/to/private_key'
    remote_path: '/remote/path/files.*'
"""

RETURN = r"""
msg:
    description: The result message of the download operation
    type: str
    returned: always
    sample: '"list retrieved" or "directory empty"'
changed:
    description: Whether any local files were changed
    type: bool
    returned: always
    sample: true
files:
    description: List of files
    type: list
    returned: always
    sample: ["/local/path/file1.txt", "/local/path/file2.txt"]
"""

import os
from io import StringIO
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule, missing_required_lib
import fnmatch
from typing import IO

try:
    import paramiko

    has_paramiko = True
except ImportError:
    has_paramiko = False


def get_connect_params(module: AnsibleModule) -> dict[str, any]:
    """Get connection parameters for SSH client."""
    params: dict[str, any] = {
        "hostname": module.params["host"],
        "username": module.params["username"],
        "port": module.params["port"],
    }

    # Add authentication parameters based on method
    if module.params["private_key"]:
        try:
            privkey_str: str = module.params["private_key"]
            privkey_file: IO = (
                StringIO(privkey_str)
                if privkey_str.startswith("----")
                else open(privkey_str, "r")
            )
            if module.params["private_key_passphrase"]:
                pkey = paramiko.RSAKey.from_private_key(
                    privkey_file, password=module.params["private_key_passphrase"]
                )
                privkey_file.close()
            else:
                pkey = paramiko.RSAKey.from_private_key(privkey_file)
            params["pkey"] = pkey
        except Exception as e:
            module.fail_json(msg=f"Failed to load private key: {str(e)}")
    elif module.params["password"]:
        params["password"] = module.params["password"]
    else:
        module.fail_json(msg="Either password or private_key must be provided")

    if module.params["host_key_algorithms"]:
        params["server_host_key_algorithms"] = module.params["host_key_algorithms"]
    return params


def get_remote_files(sftp: paramiko.SFTPClient, remote_path: str) -> list[str] | str:
    """Get list of remote files based on the given path."""
    if any(char in remote_path for char in ["*", "?", "]", "["]):
        glob_expression = os.path.basename(remote_path)
        remote_dir = os.path.dirname(remote_path)
        attr_list: paramiko.SFTPAttributes = sftp.listdir_attr(remote_dir)
        all_files: list[str] = list(
            map(
                lambda x: x.filename,
                filter(lambda x: str(x.longname).startswith("-"), attr_list),
            )
        )
        return fnmatch.filter(all_files, glob_expression)
    elif remote_path.endswith("/"):
        attr_list: paramiko.SFTPAttributes = sftp.listdir_attr(remote_path)
        return list(
            map(
                lambda x: x.filename,
                filter(lambda x: str(x.longname).startswith("-"), attr_list),
            )
        )
    elif str(sftp.lstat(remote_path)).startswith("-"):
        return [os.path.basename(remote_path)]
    else:
        attr_list: paramiko.SFTPAttributes = sftp.listdir_attr(remote_path)
        if list(
            map(
                lambda x: x.filename,
                filter(lambda x: str(x.longname).startswith("-"), attr_list),
            )
        ):
            attr_list: paramiko.SFTPAttributes = sftp.listdir_attr(remote_path + "/")
            return list(
                map(
                    lambda x: x.filename,
                    filter(lambda x: str(x.longname).startswith("-"), attr_list),
                )
            )
        else:
            raise LookupError(f"Unhandled remote path value: {remote_path}")


def process_files(
    module: AnsibleModule, sftp: paramiko.SFTPClient, remote_files: list[str]
) -> dict[str, any]:
    """Process file list."""
    result = {"files": remote_files}

    result["msg"] = (
        f"{len(result['files'])} file(s) listed successfully"
        if len(remote_files) >= 1
        else f"No files found in {module.params['remote_path']}"
    )
    return result


def run_module(module: AnsibleModule) -> None:
    """Main function to run the Ansible module."""
    if not has_paramiko:
        module.fail_json(msg=missing_required_lib("paramiko"))

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(**get_connect_params(module))

        with ssh.open_sftp() as sftp:
            remote_files = get_remote_files(sftp, module.params["remote_path"])
            result = process_files(module, sftp, remote_files)

        module.exit_json(**result)
    except Exception as err:
        module.fail_json(msg=f"Error occurred: {to_native(err)}")


def main():
    spec = dict(
        host=dict(type="str", required=True),
        port=dict(default=22, type="int"),
        username=dict(type="str", required=True),
        password=dict(type="str", required=False, no_log=True),
        private_key=dict(type="str", required=False, no_log=True),
        private_key_passphrase=dict(type="str", required=False, no_log=True),
        remote_path=dict(type="str", required=True),
        host_key_algorithms=dict(type="list", elements="str", required=False),
    )

    module = AnsibleModule(
        argument_spec=spec,
        supports_check_mode=False,
        mutually_exclusive=[["password", "private_key"]],
        required_one_of=[["password", "private_key"]],
    )

    if module.check_mode:
        module.exit_json(
            changed=False,
            msg="Check mode not supported for file retrieval. Open a PR on the github repo if you want this functionality.",
        )

    run_module(module)


if __name__ == "__main__":
    main()
