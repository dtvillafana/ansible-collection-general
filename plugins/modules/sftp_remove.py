#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: sftp_remove

short_description: Remove a file from an SFTP server

version_added: "1.0.0"

description:
  - This module allows removing a file from an SFTP server.
  - The module connects to the SFTP server and removes the specified file.
    - Supports both password and SSH key authentication methods.

author:
  - David Villafana (@dtvillafana)

requirements:
  - python paramiko<4.0

options:
  host:
    description:
    - The IP address or hostname of the destination SFTP server.
    required: True
    type: str
  port:
    description:
    - The port of the destination SFTP server.
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
    - The path of the file to be removed on the remote SFTP server.
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
- name: Remove file from SFTP server
  sftp_remove:
    host: 1.2.3.4
    username: foo
    password: bar
    remote_path: '/path/to/remote/file.txt'
    host_key_algorithms:
      - 'ssh-ed25519'
      - 'ecdsa-sha2-nistp256'

- name: remove file using password protected SSH key
  dtvillafana.general.sftp_remove:
    host: 1.2.3.4
    username: foo
    private_key: '/path/to/private_key'
    private_key_passphrase: 'optional_passphrase'
    remote_path: '/remote/path/file.txt'
    host_key_algorithms:
      - 'ssh-ed25519'
      - 'ecdsa-sha2-nistp256'

- name: connect to legacy server with ssh-dss
  dtvillafana.general.sftp_remove:
    host: 1.2.3.4
    username: foo
    password: bar
    remote_path: '/remote/path/file.txt'
    host_key_algorithms:
      - 'ssh-dss'
      - 'ssh-rsa'

- name: remove file in a directory using SSH key
  dtvillafana.general.sftp_remove:
    host: 1.2.3.4
    username: foo
    private_key: '/path/to/private_key'
    remote_path: '/remote/path/file.txt'
"""

RETURN = r"""
msg:
    description: The result message of the remove operation
    type: str
    returned: always
    sample: '"File successfully removed" or "File not found"'
"""

from io import StringIO
from typing import IO
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule, missing_required_lib

try:
    import paramiko
    from paramiko.transport import Transport
    from paramiko import SSHException

    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False


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
        remote_path=dict(type="str", required=True),
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
        result["msg"] = "Check mode not supported..."
        module.exit_json(**result)

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

        try:
            if sftp:
                sftp.remove(module.params["remote_path"])
                result["changed"] = True
                result["msg"] = f"File {module.params['remote_path']} successfully removed"
            else:
                raise e
        except IOError as e:
            if e.errno == 2:  # No such file or directory
                result["msg"] = f"File {module.params['remote_path']} not found"
            else:
                module.fail_json(
                    msg=f"SFTP remove operation failed: {to_native(e)}", **result
                )
        finally:
            if sftp:
                sftp.close()
            ssh.close()

    except Exception as err:
        module.fail_json(msg=f"Client error occurred: {to_native(err)}", **result)

    module.exit_json(**result)


if __name__ == "__main__":
    main()
