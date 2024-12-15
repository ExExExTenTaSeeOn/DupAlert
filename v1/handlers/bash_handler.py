# handlers/bash_handler.py

import subprocess
import os
from utils.helpers import (
    command_exists,
    is_windows,
    is_linux,
    is_macos
)


def handle_bash_script(script_path, script_args):
    if not os.path.isfile(script_path):
        print(f"Error: Bash script '{script_path}' does not exist.")
        return

    if is_windows():
        if not command_exists("bash"):
            print("The 'bash' command is not available on this Windows system.")
            return
    elif is_linux() or is_macos():
        if not command_exists("bash"):
            print("Error: 'bash' command not found. Please install bash on your system.")
            return
    else:
        print("Error: Unsupported operating system for executing Bash scripts.")
        return

    command = ["bash", script_path] + script_args
    print(f"Executing command: {' '.join(command)}")

    try:
        result = subprocess.run(command, check=True)
        if result.returncode == 0:
            print("Bash script executed successfully!")
    except subprocess.CalledProcessError as error:
        print(f"Error during Bash script execution: {error}")
