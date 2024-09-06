#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
---
module: sftp_get

short_description: Retrieve files from SFTP server to where Ansible runs

description:
    - This module allows retrieving files using SFTP.
    - The module retrieves files to wherever the playbook is run.
    - The module supports file globbing for retrieving multiple files (however, does not support pathname expansion, e.g. '**' characters).
    - It checks if the file already exists at the destination with the same content before downloading.

version_added: "1.0.0"

author:
  - David Villafana (@dtvillafana)

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
    - The path to the source file or directory or glob pattern on the remote server.
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

EXAMPLES = r'''
- name: Retrieve a single file via SFTP
  dtvillafana.general.sftp_get:
    host: 1.2.3.4
    username: foo
    password: bar
    remote_path: '/remote/path/file.txt'
    local_path: '/local/path/'

- name: Retrieve multiple files using globbing
  dtvillafana.general.sftp_get:
    host: 1.2.3.4
    username: foo
    password: bar
    remote_path: '/remote/path/*.txt'
    local_path: '/local/path/'
    host_key_algorithms:
      - 'ssh-ed25519'
      - 'ecdsa-sha2-nistp256'

- name: Retrieve all files in a directory
  dtvillafana.general.sftp_get:
    host: 1.2.3.4
    username: foo
    password: bar
    remote_path: '/remote/path/'
    local_path: '/local/path/'
    host_key_algorithms:
      - 'ssh-ed25519'
      - 'ecdsa-sha2-nistp256'
'''

RETURN = r'''
msg:
    description: The result message of the download operation
    type: str
    returned: always
    sample: '"1 file(s) downloaded successfully" or "All files already exist at destination"'
changed:
    description: Whether any local files were changed
    type: bool
    returned: always
    sample: true
files:
    description: List of files that were downloaded
    type: list
    returned: always
    sample: ["/local/path/file1.txt", "/local/path/file2.txt"]
'''

try:
    import paramiko

    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False
import os
import hashlib
import fnmatch
from typing import List, Dict, Any
import traceback

from ansible.module_utils._text import to_native
from ansible.module_utils.basic import AnsibleModule, missing_required_lib


def get_file_hash(file_obj: Any) -> str:
    '''Calculate MD5 hash of file object.'''
    hash_md5 = hashlib.md5()
    for chunk in iter(lambda: file_obj.read(4096), b""):
        hash_md5.update(chunk)
    return hash_md5.hexdigest()


def get_connect_params(module: AnsibleModule) -> Dict[str, Any]:
    '''Get connection parameters for SSH client.'''
    params = {
        "hostname": module.params["host"],
        "username": module.params["username"],
        "password": module.params["password"],
        "port": module.params["port"],
    }
    if module.params["host_key_algorithms"]:
        params["server_host_key_algorithms"] = module.params["host_key_algorithms"]
    return params


def get_remote_paths(
    sftp: paramiko.SFTPClient, remote_path: str
) -> List[str]:
    '''Get list of remote files based on the given path.'''
    remote_dir = os.path.dirname(remote_path)
    if any(char in remote_path for char in ["*", "?", "]", "["]):
        glob_expression = os.path.basename(remote_path)
        attr_list: paramiko.SFTPAttributes = sftp.listdir_attr(remote_dir)
        all_paths: List[str] = list(
            map(
                lambda x: os.path.join(remote_dir, x),
                fnmatch.filter(
                    map(
                        lambda x: x.filename,
                        filter(
                            lambda x: str(x.longname).startswith("-"),
                            attr_list),
                    ),
                    glob_expression)
            )
        )
        return all_paths
    elif remote_path.endswith("/"):
        attr_list: paramiko.SFTPAttributes = sftp.listdir_attr(remote_path)
        return list(
            map(
                lambda x: os.path.join(remote_dir, x.filename),
                filter(lambda x: str(x.longname).startswith("-"), attr_list),
            )
        )
    elif str(sftp.lstat(remote_path)).startswith("-"):
        return [remote_path]
    else:
        attr_list: paramiko.SFTPAttributes = sftp.listdir_attr(remote_path)
        if list(
            map(
                lambda x: os.path.join(remote_path, x.filename),
                filter(lambda x: str(x.longname).startswith("-"), attr_list),
            )
        ):
            attr_list: paramiko.SFTPAttributes = sftp.listdir_attr(remote_path + "/")
            return list(
                map(
                    lambda x: os.path.join(remote_path, x.filename),
                    filter(lambda x: str(x.longname).startswith("-"), attr_list),
                )
            )


def validate_paths(module: AnsibleModule, remote_paths: List[str]) -> None:
    '''Validate remote and local paths.'''
    if not remote_paths:
        module.fail_json(msg=f"No files found matching {module.params['remote_path']}")

    if (
        module.params["remote_path"].endswith("/") or len(remote_paths) > 1
    ) and not module.params["local_path"].endswith("/"):
        module.fail_json(
            msg=f"invalid local_path: {module.params['local_path']} -- local_path must be a directory string ending with '/' when multiple files would be retrieved"
        )


def download_file(
    sftp: paramiko.SFTPClient, local_path: str, remote_path: str
) -> bool:
    '''Download a single file if it doesn't exist or has different content.'''
    if os.path.exists(local_path) and os.path.isfile(local_path):
        with open(local_path, "rb") as f:
            local_hash = get_file_hash(f)
        with sftp.file(remote_path, "rb") as f:
            remote_hash = get_file_hash(f)
        if local_hash == remote_hash:
            return False

    sftp.get(remotepath=remote_path, localpath=local_path)
    return True


def process_files(
    module: AnsibleModule, sftp: paramiko.SFTPClient, remote_paths: List[str]
) -> Dict[str, Any]:
    '''Process and download files.'''
    result = {"changed": False, "files": []}
    remote_path = module.params["remote_path"]
    local_path = module.params["local_path"]

    for remote_path in remote_paths:
        remote_file: str = os.path.basename(remote_path)
        local_file = (
            os.path.join(local_path, remote_file)
            if
            os.path.isdir(local_path)
            else
            local_path
        )
        print(f"local_file: {local_file} - remote_path: {remote_path}")
        if download_file(
            sftp,
            local_file,
            remote_path
        ):
            result["changed"] = True
            result["files"].append(local_file)

    result["msg"] = (
        f"{len(result['files'])} file(s) downloaded successfully"
        if result["changed"]
        else "All files already exist at destination with the same content"
    )
    return result


def run_module(module: AnsibleModule) -> None:
    '''Main function to run the Ansible module.'''
    if not HAS_PARAMIKO:
        module.fail_json(msg=missing_required_lib("paramiko"))

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(**get_connect_params(module))

        with ssh.open_sftp() as sftp:
            remote_files = get_remote_paths(sftp, module.params["remote_path"])
            validate_paths(module, remote_files)
            result = process_files(module, sftp, remote_files)

        module.exit_json(**result)
    except Exception as err:
        stack_trace = traceback.format_exc()
        module.fail_json(msg=f"Error occurred: {to_native(err)} -- target: {module.params['remote_path']} -- {stack_trace}")


def main():
    spec = dict(
        host=dict(type="str", required=True),
        port=dict(default=22, type="int"),
        username=dict(type="str", required=True),
        password=dict(type="str", required=True, no_log=True),
        remote_path=dict(type="str", required=True),
        local_path=dict(type="str", required=True),
        host_key_algorithms=dict(type="list", elements="str", required=False),
    )

    module = AnsibleModule(argument_spec=spec, supports_check_mode=False)

    if module.check_mode:
        module.exit_json(
            changed=False,
            msg="Check mode not supported for file retrieval. Create a PR on the github repo if you want this functionality.",
        )

    run_module(module)


if __name__ == "__main__":
    main()
