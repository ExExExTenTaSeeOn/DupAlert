# ddas.py

import sys
import os
from handlers.wget_handler import handle_wget
from handlers.curl_handler import handle_curl
from handlers.python_handler import handle_python_script
from handlers.bash_handler import handle_bash_script
from utils.helpers import print_usage


def main():
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    subcommand = sys.argv[1]
    subcommand_args = sys.argv[2:]

    if subcommand in ['-h', '--help']:
        print_usage()
        sys.exit(0)

    if subcommand.lower() == "hello":
        print("Hello, World!")
    elif subcommand.lower() == "wget":
        handle_wget(subcommand_args)
    elif subcommand.lower() == "curl":
        handle_curl(subcommand_args)
    else:
        script_path = subcommand
        script_args = subcommand_args
        _, ext = os.path.splitext(script_path)
        ext = ext.lower()

        if ext == ".py":
            handle_python_script(script_path, script_args)
        elif ext == ".sh":
            handle_bash_script(script_path, script_args)
        else:
            print(f"Unknown command or unsupported script type: {subcommand}")
            print_usage()


if __name__ == "__main__":
    main()
