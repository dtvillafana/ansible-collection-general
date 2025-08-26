#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: sftp_send

short_description: Send data directly to SFTP server from where ansible runs

version_added: "1.0.0"

description:
  - This module allows sending files and text using SFTP.
  - The module sends from wherever the playbook is run.
  - It checks if the file already exists at the destination with the same content before uploading. If read permissions are not granted, the file will be overwritten.
    - Supports both password and SSH key authentication methods.

author:
  - David Villafana (@dtvillafana)

requirements:
  - python paramiko<4.0

options:
  host:
    description:
    - The IP address or hostname of destination SFTP server.
    required: True
    type: str
  port:
    description:
    - The port of destination SFTP server.
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
  src:
    description:
    - The text content to send or the path to the source file.
    - If this is a path to a file, the content of the file will be sent.
    - If this is a string, the string content will be sent directly.
    required: True
    type: str
  dest_path:
    description:
    - The destination filename.
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
- name: Send sftp file using string content
  dtvillafana.general.sftp_send:
      host: 1.2.3.4
      username: foo
      password: bar
      src: "This is the content to send"
      dest_path: '/dest/file.txt'
      host_key_algorithms:
        - 'ssh-ed25519'
        - 'ecdsa-sha2-nistp256'

- name: send sftp file using a local file path
  dtvillafana.general.sftp_send:
      host: 1.2.3.4
      username: foo
      password: bar
      src: "/path/to/local/file.txt"
      dest_path: '/dest/file.txt'

- name: send file using SSH key
  dtvillafana.general.sftp_send:
    host: 1.2.3.4
    username: foo
    private_key: '/path/to/private_key'
    private_key_passphrase: 'optional_passphrase'
    dest_path: '/remote/path/file.txt'
    src: '/local/path/file.txt'
    host_key_algorithms:
      - 'ssh-ed25519'
      - 'ecdsa-sha2-nistp256'

- name: connect to legacy server with ssh-dss
  dtvillafana.general.sftp_send:
    host: 1.2.3.4
    username: foo
    password: bar
    dest_path: '/remote/path/file.txt'
    src: '/local/path/file.txt'
    host_key_algorithms:
      - 'ssh-dss'
      - 'ssh-rsa'

- name: send file using password protected SSH key
  dtvillafana.general.sftp_send:
    host: 1.2.3.4
    username: foo
    private_key: '/path/to/private_key'
    private_key_passphrase: 'optional_passphrase'
    dest_path: '/remote/path/file.txt'
    src: '/local/path/file.txt'
    host_key_algorithms:
      - 'ssh-ed25519'
      - 'ecdsa-sha2-nistp256'
"""

RETURN = r"""
msg:
    description: The result message of the upload operation
    type: str
    returned: always
    sample: '"File uploaded successfully" or "File already exists at destination"'
changed:
    description: Whether the remote file was changed
    type: bool
    returned: always
    sample: true
"""

import os
import hashlib
from io import StringIO
from typing import IO
from ansible.module_utils._text import to_native, to_text
from ansible.module_utils.basic import AnsibleModule, missing_required_lib

try:
    import paramiko
    from paramiko.transport import Transport

    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False


def get_file_hash(file_obj):
    """Calculate MD5 hash of file object."""
    hash_md5 = hashlib.md5()
    for chunk in iter(lambda: file_obj.read(4096), b""):
        hash_md5.update(chunk)
    return hash_md5.hexdigest()


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


def main():

    spec = dict(
        host=dict(type="str", required=True),
        port=dict(default=22, type="int"),
        username=dict(type="str", required=True),
        password=dict(type="str", required=False, no_log=True),
        private_key=dict(type="str", required=False, no_log=True),
        private_key_passphrase=dict(type="str", required=False, no_log=True),
        src=dict(type="str", required=True),
        dest_path=dict(type="str", required=True),
        host_key_algorithms=dict(type="list", elements="str", required=False),
    )

    module = AnsibleModule(
        argument_spec=spec,
        supports_check_mode=False,
        mutually_exclusive=[["password", "private_key"]],
        required_one_of=[["password", "private_key"]],
    )

    if not HAS_PARAMIKO:
        module.fail_json(
            msg=missing_required_lib("paramiko"),
        )

    result = {"changed": False}

    if module.check_mode:
        module.exit_json(
            changed=False,
            msg="Check mode not supported for file retrieval. Create a PR on the github repo if you want this functionality.",
        )

    src = module.params["src"]
    if os.path.isfile(src):
        try:
            with open(src, "rb") as f:
                content = f.read()
        except IOError as e:
            module.fail_json(
                msg=f"Unable to read source file: {to_native(e)}", **result
            )
    else:
        content = to_text(src).encode("utf-8")

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        transport = None

        # Configure host key algorithms before connecting if specified
        if module.params["host_key_algorithms"]:
            # Create a custom transport to set host key algorithms
            transport = paramiko.Transport(
                (module.params["host"], module.params["port"])
            )

            # Set the host key algorithms on the transport's security options
            security_options = transport.get_security_options()
            security_options.key_types = module.params["host_key_algorithms"]

            # Start the transport
            transport.start_client()

            # Authenticate using the transport
            connect_params = get_connect_params(module=module)

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
            connect_params = get_connect_params(module=module)
            ssh.connect(**connect_params)
            sftp = ssh.open_sftp()

        try:
            # Check if file exists and compare content
            try:
                with sftp.file(module.params["dest_path"], "rb") as remote_file:
                    remote_hash = get_file_hash(remote_file)

                local_hash = hashlib.md5(content).hexdigest()

                if remote_hash == local_hash:
                    result["msg"] = (
                        "File already exists at destination with the same content."
                    )
                    module.exit_json(**result)
            except IOError:
                # File doesn't exist or read permissions not granted, continue with upload
                pass

            with sftp.file(module.params["dest_path"], "wb") as f:
                f.write(content)
            result["changed"] = True
            result["msg"] = (
                f"File uploaded successfully to {to_native(module.params['dest_path'])}"
            )
        except Exception as err:
            module.fail_json(msg=f"SFTP upload failed: {to_native(err)}", **result)
        finally:
            if sftp:
                sftp.close()
            if module.params["host_key_algorithms"] and transport:
                transport.close()
            else:
                ssh.close()
    except Exception as err:
        module.fail_json(msg=f"Client error occurred: {to_native(err)}", **result)

    module.exit_json(**result)


if __name__ == "__main__":
    main()
