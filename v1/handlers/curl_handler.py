# handlers/curl_handler.py

import subprocess
from utils.helpers import (
    command_exists,
    is_windows,
    is_linux,
    extract_url_and_flags,
    determine_proposed_filename,
    store_partial_hash
)
from download_logic.download_handler import handle_download_logic


def handle_curl(command_args):
    url, flags = extract_url_and_flags(command_args)
    if url is None:
        print("Error: No URL provided to curl.")
        return

    proposed_filename = determine_proposed_filename(url)

    # Ensure output file is specified
    if not any(flag in flags for flag in ['-O', '--output']):
        flags += ['-o', proposed_filename]

    action, partial_hash = handle_download_logic(url)

    if is_windows():
        if not command_exists("curl"):
            print("The 'curl' command is not available on this Windows system.")
            return
    elif is_linux():
        if not command_exists("curl"):
            print("Error: 'curl' command not found on Linux. Please install curl.")
            return

    if action == 0:
        full_command = ["curl"] + flags + [url]
        print(f"Executing command: {' '.join(full_command)}")
        try:
            result = subprocess.run(full_command, check=True)
            if result.returncode == 0:
                print("curl command executed successfully!")
                if partial_hash:
                    store_partial_hash(proposed_filename, partial_hash)
        except subprocess.CalledProcessError as error:
            print(f"Error during curl execution: {error}")
    elif action == -1:
        print("Download canceled by server instruction.")
    elif action == 1:
        print("Download remains paused as per server instruction.")
    else:
        print("Unknown action received from server.")
