#!/usr/bin/env python3
import sys
import os
import platform

try:
    import xattr
except ImportError:
    xattr = None


def is_windows():
    return platform.system().lower() == "windows"


def is_linux():
    return platform.system().lower() == "linux"


def is_macos():
    return platform.system().lower() == "darwin"


def show_metadata(file_path):
    if not os.path.isfile(file_path):
        print(f"Error: '{file_path}' is not a file.")
        return

    if is_windows():
        # Windows ADS logic remains the same
        ads_path = f"{file_path}:file_hash_check_parts"
        try:
            with open(ads_path, "r") as ads:
                hash_data = ads.read().strip()
            print(f"file_hash_check_parts (ADS) for '{file_path}': {hash_data}")
        except Exception as e:
            print(f"No ADS named 'file_hash_check_parts' found for '{file_path}'. Error: {e}")
    elif is_linux() or is_macos():
        if xattr is None:
            print("xattr module not installed. Cannot read extended attributes.")
            return
        try:
            # Using pyxattr functional interface
            hash_data = xattr.getxattr(
                file_path, b"user.file_hash_check_parts")
            hash_data = hash_data.decode('utf-8', errors='replace').strip()
            print(f"user.file_hash_check_parts for '{file_path}': {hash_data}")
        except OSError as e:
            # If the attribute doesn't exist, OSError is raised
            print(f"No 'user.file_hash_check_parts' attribute found for '{file_path}'. Error: {e}")
        except Exception as e:
            print(f"Error reading extended attribute: {e}")
    else:
        print("Unsupported platform for this metadata demonstration.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: show_metadata.py <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]
    show_metadata(file_path)
