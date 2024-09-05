#!/usr/bin/python

# Copyright: (c) 2024, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
import os
import hashlib
from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule, missing_required_lib
import fnmatch
try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

__metaclass__ = type

DOCUMENTATION = r'''
---
module: sftp_get
author:
  - David Villafaña <https://github.com/dtvillafana>

short_description: Retrieve files from SFTP server to where Ansible runs.

description:
  - This module allows retrieving files using SFTP.
  - The module retrieves files to wherever the playbook is run.
  - It supports file globbing for retrieving multiple files.
  - It checks if the file already exists at the destination with the same content before downloading.

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
    required: True
    type: str
  remote_path:
    description:
    - The path to the source file or glob pattern on the remote server.
    required: True
    type: str
  local_path:
    description:
    - The local destination directory or file name, directory names must end with '/'.
    required: True
    type: str
  host_key_algorithms:
    description:
    - List of allowed host key algorithms.
    - If not specified, Paramiko's default algorithms will be used.
    required: False
    type: list
    elements: str
'''

EXAMPLES = r"""
- name: Retrieve a single file via SFTP
  mycompany.mymodules.sftp_get:
    host: 1.2.3.4
    username: foo
    password: bar
    remote_path: '/remote/path/file.txt'
    local_path: '/local/path/'

- name: Retrieve multiple files using globbing
  mycompany.mymodules.sftp_get:
    host: 1.2.3.4
    username: foo
    password: bar
    remote_path: '/remote/path/*.txt'
    local_path: '/local/path/'
    host_key_algorithms:
      - 'ssh-ed25519'
      - 'ecdsa-sha2-nistp256'
"""

RETURN = r"""
msg:
    description: The result message of the download operation
    type: str
    returned: always
    sample: "1 file(s) downloaded successfully" or "All files already exist at destination"
changed:
    description: Whether any local files were changed
    type: bool
    returned: always
    sample: true
downloaded_files:
    description: List of files that were downloaded
    type: list
    returned: always
    sample: ["/local/path/file1.txt", "/local/path/file2.txt"]
"""


def get_file_hash(file_obj):
    """Calculate MD5 hash of file object."""
    hash_md5 = hashlib.md5()
    for chunk in iter(lambda: file_obj.read(4096), b""):
        hash_md5.update(chunk)
    return hash_md5.hexdigest()


def main():
    spec = dict(
        host=dict(type='str', required=True),
        port=dict(default=22, type='int'),
        username=dict(type='str', required=True),
        password=dict(type='str', required=True, no_log=True),
        remote_path=dict(type='str', required=True),
        local_path=dict(type='str', required=True),
        host_key_algorithms=dict(type='list', elements='str', required=False)
    )

    module = AnsibleModule(
        argument_spec=spec,
        supports_check_mode=True
    )

    if not HAS_PARAMIKO:
        module.fail_json(msg=missing_required_lib("paramiko"))

    result = {'changed': False, 'downloaded_files': []}

    if module.check_mode:
        result["msg"] = "Check mode not supported for file retrieval"
        module.exit_json(**result)

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_params = {
            'hostname': module.params['host'],
            'username': module.params['username'],
            'password': module.params['password'],
            'port': module.params['port']
        }

        local_path: str = module.params['local_path']
        remote_path: str = module.params['remote_path']

        if module.params['host_key_algorithms']:
            connect_params['server_host_key_algorithms'] = module.params['host_key_algorithms']

        ssh.connect(**connect_params)

        sftp = ssh.open_sftp()
        try:
            glob_expression: str = ""
            remote_files = ""
            if any(char in remote_path for char in ['*', '?', ']', '[']):
                glob_expression = os.path.basename(remote_path)
                remote_path = os.path.dirname(remote_path)
                remote_files = sftp.listdir(remote_path)
            elif remote_path[-1] == '/':
                remote_files = sftp.listdir(remote_path)
            else:
                remote_files = remote_path

            if not remote_files:
                module.fail_json(msg=f"No files found matching {remote_path}")

            if (remote_path[-1] == '/' or glob_expression) and local_path[-1] != '/':
                module.fail_json(msg=f"invalid local_path: {local_path}  -- local_path must be a directory string ending with '/'")

            if type(remote_files) is list:
                if glob_expression:
                    remote_files = fnmatch.filter(remote_files, glob_expression)
                for remote_file in remote_files:
                    local_file = os.path.join(local_path, remote_file)

                    # Check if file exists locally and compare content
                    if os.path.exists(local_file):
                        with open(local_file, 'rb') as f:
                            local_hash = get_file_hash(f)

                        with sftp.file(remote_file, 'rb') as f:
                            remote_hash = get_file_hash(f)

                        if local_hash == remote_hash:
                            continue  # Skip this file, it's already up to date

                    # Download the file
                    sftp.get(os.path.join(remote_path, remote_file), local_file)
                    result['changed'] = True
                    result['downloaded_files'].append(local_file)
            else:
                local_file = os.path.join(local_path, remote_files) if local_path[-1] == '/' else local_path
                sftp.get(remote_path, local_path)
                result['changed'] = True
                result['downloaded_files'].append(local_file)

            if result['changed']:
                result['msg'] = f"{len(result['downloaded_files'])} file(s) downloaded successfully"
            else:
                result['msg'] = "All files already exist at destination with the same content"

        except Exception as err:
            module.fail_json(msg=f'SFTP download failed: {to_native(err)}', **result)
        finally:
            sftp.close()
            ssh.close()
    except Exception as err:
        module.fail_json(msg=f'Client error occurred: {to_native(err)}', **result)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
