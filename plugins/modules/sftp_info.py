#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: sftp_info

short_description: List files on remote SFTP server

version_added: "1.0.0"

description:
  - This module allows listing files using SFTP.
  - This module supports file globbing for listing multiple files (however, does not support pathname expansion, e.g. '**' characters).
  - Supports both password and SSH key authentication methods.

author:
  - David Villafana (@dtvillafana)

requirements:
  - python paramiko<4.0

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
    - Supports legacy algorithms like 'ssh-dss' for older servers.
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

- name: connect to legacy server with ssh-dss
  dtvillafana.general.sftp_info:
    host: 1.2.3.4
    username: foo
    password: bar
    remote_path: '/remote/path/file.txt'
    host_key_algorithms:
      - 'ssh-dss'
      - 'ssh-rsa'

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
    description: List of file objects with detailed information
    type: list
    returned: always
    sample: [
        {
            "full_path": "/remote/path/file1.txt",
            "date": "2024-01-15T10:30:45Z",
            "size_bytes": 1024
        },
        {
            "full_path": "/remote/path/file2.txt",
            "date": "2024-01-16T14:22:33Z",
            "size_bytes": 2048
        }
    ]
"""

import os
from io import StringIO
from datetime import datetime
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule, missing_required_lib
import fnmatch
from typing import IO, Any

try:
    import paramiko
    from paramiko.transport import Transport
    from paramiko import SSHException


    has_paramiko = True
except ImportError:
    has_paramiko = False


def get_connect_params(module: AnsibleModule) -> dict[str, any]:
    """Get connection parameters for SSH client."""
    params = {
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

    return params


def configure_host_key_algorithms(ssh_client, host_key_algorithms):
    """Configure host key algorithms for the SSH client."""
    if host_key_algorithms:
        # Get the transport object and configure host key algorithms
        transport = ssh_client.get_transport()
        if transport is not None:
            # Set the preferred host key algorithms
            transport.get_security_options().key_types = host_key_algorithms


def create_file_object(
    attr: paramiko.SFTPAttributes, full_path: str
) -> dict[str, str | int | None]:
    """Create a file object with the required attributes."""
    # Convert Unix timestamp to ISO 8601 format
    date_iso = datetime.fromtimestamp(attr.st_mtime).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {"full_path": full_path, "date": date_iso, "size_bytes": attr.st_size}


def get_remote_files(
    sftp: paramiko.SFTPClient, remote_path: str
) -> list[dict[str, Any]]:
    """Get list of remote file objects based on the given path."""
    if any(char in remote_path for char in ["*", "?", "]", "["]):
        # Handle glob patterns
        glob_expression = os.path.basename(remote_path)
        remote_dir = os.path.dirname(remote_path)
        attr_list = sftp.listdir_attr(remote_dir)

        # Filter for regular files only
        file_attrs = [attr for attr in attr_list if str(attr.longname).startswith("-")]

        # Apply glob pattern matching
        matching_files = []
        for attr in file_attrs:
            if fnmatch.fnmatch(attr.filename, glob_expression):
                full_path = os.path.join(remote_dir, attr.filename).replace("\\", "/")
                matching_files.append(create_file_object(attr, full_path))

        return matching_files

    elif remote_path.endswith("/"):
        # Handle directory listing
        attr_list = sftp.listdir_attr(remote_path)
        file_objects = []

        for attr in attr_list:
            if str(attr.longname).startswith("-"):  # Regular files only
                full_path = os.path.join(remote_path, attr.filename).replace("\\", "/")
                file_objects.append(create_file_object(attr, full_path))

        return file_objects

    elif str(sftp.lstat(remote_path)).startswith("-"):
        # Handle single file
        attr = sftp.lstat(remote_path)
        return [create_file_object(attr, remote_path)]

    else:
        # Handle directory without trailing slash
        try:
            attr_list = sftp.listdir_attr(remote_path)
            file_objects = []

            for attr in attr_list:
                if str(attr.longname).startswith("-"):  # Regular files only
                    full_path = os.path.join(remote_path, attr.filename).replace(
                        "\\", "/"
                    )
                    file_objects.append(create_file_object(attr, full_path))

            if file_objects:
                return file_objects
            else:
                # Try with trailing slash
                attr_list = sftp.listdir_attr(remote_path + "/")
                for attr in attr_list:
                    if str(attr.longname).startswith("-"):  # Regular files only
                        full_path = os.path.join(remote_path, attr.filename).replace(
                            "\\", "/"
                        )
                        file_objects.append(create_file_object(attr, full_path))
                return file_objects

        except Exception:
            raise LookupError(f"Unhandled remote path value: {remote_path}")


def process_files(
    module: AnsibleModule, remote_files: list[dict[str, str | int | None]]
) -> dict[str, list[dict[str, str | int | None]] | str]:
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

    sftp = None
    transport = None
    e: SSHException = SSHException("SSH failed to connect - generic")
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_params = get_connect_params(module=module)

        # Configure host key algorithms before connecting if specified
        if module.params["host_key_algorithms"]:
            for x in range(10):
                try:
                    # Create a fresh transport on each attempt
                    transport = paramiko.Transport(
                        (module.params["host"], module.params["port"])
                    )

                    # Set the host key algorithms on the transport's security options
                    security_options = transport.get_security_options()
                    security_options.key_types = module.params["host_key_algorithms"]

                    # Start the transport
                    transport.start_client()
                    break
                except Exception as err:
                    e = err
                    if transport:
                        transport.close()
                        transport = None
                    continue

            if transport is None or not transport.is_active():
                raise e

            # Authenticate using the transport
            if "pkey" in connect_params:
                transport.auth_publickey(
                    connect_params["username"], connect_params["pkey"]
                )
            elif "password" in connect_params:
                transport.auth_password(
                    connect_params["username"], connect_params["password"]
                )

            # Create SFTP client from the transport
            sftp = paramiko.SFTPClient.from_transport(transport)
        else:
            # Use standard connection method
            for x in range(10):
                try:
                    ssh.connect(**connect_params)
                    break
                except Exception as err:
                    e = err
                    continue
            sftp = ssh.open_sftp()

        if sftp:
            remote_files = get_remote_files(sftp, module.params["remote_path"])
            result = process_files(module, remote_files)
        else:
            raise e

        module.exit_json(**result)
    except Exception as err:
        module.fail_json(msg=f"Error occurred: {to_native(err)}")
    finally:
        if sftp:
            sftp.close()
        if module.params["host_key_algorithms"] and transport:
            transport.close()
        else:
            ssh.close()


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
