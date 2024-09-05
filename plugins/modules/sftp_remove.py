#!/usr/bin/python

# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: sftp_remove
author:
  - David Villafaña <https://github.com/dtvillafana>

short_description: Remove a file from an SFTP server.

description:
  - This module allows removing a file from an SFTP server.
  - The module connects to the SFTP server and removes the specified file.

requirements:
  - python paramiko

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
    required: True
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
"""

RETURN = r"""
msg:
    description: The result message of the remove operation
    type: str
    returned: always
    sample: "File successfully removed" or "File not found"
"""

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule, missing_required_lib

try:
    import paramiko

    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False


def main():

    spec = dict(
        host=dict(type="str", required=True),
        port=dict(default=22, type="int"),
        username=dict(type="str", required=True),
        password=dict(type="str", required=True, no_log=True),
        remote_path=dict(type="str", required=True),
        host_key_algorithms=dict(type="list", elements="str", required=False),
    )

    module = AnsibleModule(argument_spec=spec, supports_check_mode=True)

    if not HAS_PARAMIKO:
        module.fail_json(
            msg=missing_required_lib("paramiko"),
        )

    result = {"changed": False}

    if module.check_mode:
        module.exit_json(**result)

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_params = {
            "hostname": module.params["host"],
            "username": module.params["username"],
            "password": module.params["password"],
            "port": module.params["port"],
        }

        if module.params["host_key_algorithms"]:
            connect_params["server_host_key_algorithms"] = module.params[
                "host_key_algorithms"
            ]

        ssh.connect(**connect_params)

        sftp = ssh.open_sftp()
        try:
            sftp.remove(module.params["remote_path"])
            result["changed"] = True
            result["msg"] = f"File {module.params['remote_path']} successfully removed"
        except IOError as e:
            if e.errno == 2:  # No such file or directory
                result["msg"] = f"File {module.params['remote_path']} not found"
            else:
                module.fail_json(
                    msg=f"SFTP remove operation failed: {to_native(e)}", **result
                )
        finally:
            sftp.close()
            ssh.close()
    except Exception as err:
        module.fail_json(msg=f"Client error occurred: {to_native(err)}", **result)

    module.exit_json(**result)


if __name__ == "__main__":
    main()
