# handlers/python_handler.py

import subprocess
import os
import platform
from utils.helpers import command_exists


def handle_python_script(script_path, script_args):
    if not os.path.isfile(script_path):
        print(f"Error: Python script '{script_path}' does not exist.")
        return

    system_name = platform.system().lower()

    if system_name == "windows":
        # On Windows, python3 may not exist as a command.
        # Check for 'python' first, which is common on Windows.
        if command_exists("python"):
            python_executable = "python"
        elif command_exists("py"):
            # If python not found, try 'py' launcher.
            python_executable = "py"
        else:
            print("Error: Python is not installed or not found in PATH on Windows.")
            return
    else:
        # On Linux/macOS, 'python3' is often the executable for Python 3.
        if command_exists("python3"):
            python_executable = "python3"
        elif command_exists("python"):
            python_executable = "python"
        else:
            print("Error: Python is not installed or not found in PATH.")
            return

    command = [python_executable, script_path] + script_args
    print(f"Executing command: {' '.join(command)}")

    try:
        # On Windows, if using 'py', we might need to specify -3 for Python 3 explicitly:
        # If desired, you can modify the logic below:
        # if python_executable == "py":
        #     command.insert(1, "-3")

        result = subprocess.run(command, check=True)
        if result.returncode == 0:
            print("Python script executed successfully!")
    except subprocess.CalledProcessError as error:
        print(f"Error during Python script execution: {error}")
