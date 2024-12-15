#!/usr/bin/env python3
import sys
import os
import platform
import ctypes
from ctypes import wintypes
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import requests
import json
import uuid
import socket
import subprocess

# Attempt to import xattr for Linux/macOS
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

def normalize_path(path):
    """
    Normalizes the file path to ensure consistency.
    """
    return os.path.normcase(os.path.abspath(path))

def has_required_metadata(file_path):
    """
    Checks if the given file has the 'file_hash_check_parts' metadata.
    Returns the hash string if metadata exists, None otherwise.
    """
    if not os.path.isfile(file_path):
        return None

    normalized_path = normalize_path(file_path)

    if is_windows():
        # Windows ADS
        ads_path = f"{normalized_path}:file_hash_check_parts"
        try:
            with open(ads_path, "r") as ads:
                hash_data = ads.read().strip()
            return hash_data if hash_data else None
        except Exception:
            return None
    elif is_linux() or is_macos():
        if xattr is None:
            return None
        try:
            hash_data = xattr.getxattr(file_path, b"user.file_hash_check_parts")
            return hash_data.decode('utf-8').strip() if hash_data else None
        except (OSError, IOError):
            return None
        except Exception:
            return None
    else:
        # Unsupported platform
        return None

def get_system_info():
    """Gets system information and returns it as a dictionary."""
    system_info = {}

    def get_device_id():
        try:
            if platform.system() == "Linux":
                with open("/etc/machine-id", "r") as f:
                    return f.read().strip()
            elif platform.system() == "Windows":
                return str(uuid.uuid1())
            elif platform.system() == "Darwin":
                return subprocess.check_output(
                    "system_profiler SPHardwareDataType | grep 'UUID:'", 
                    shell=True
                ).decode().split(":")[1].strip()
            else:
                return "Platform not supported for device ID"
        except FileNotFoundError:
            return get_mac_address()  # Fallback
        except Exception as e:
            print(f"Error getting device ID: {e}")
            return "Unknown"

    def get_device_name():
        try:
            return socket.gethostname()
        except Exception as e:
            print(f"Error getting device name: {e}")
            return "Unknown"

    def get_current_user():
        try:
            if platform.system() == "Windows":
                return os.environ.get("USERNAME")
            else:
                return os.environ.get("USER")
        except Exception as e:
            print(f"Error getting current user: {e}")
            return "Unknown"

    def get_mac_address():
        try:
            if platform.system() == "Windows":
                result = subprocess.check_output(
                    ["getmac", "/fo", "csv", "/nh"]
                ).decode().strip().split(",")[0].replace('"', '')
                if result == "":
                    result = subprocess.check_output(
                        ["ipconfig", "/all"]
                    ).decode()
                    mac_address_lines = [
                        line for line in result.splitlines() 
                        if "Physical Address" in line
                    ]
                    if mac_address_lines:
                        mac_address = mac_address_lines[0].split(":")[1].strip().replace("-", ":")
                        return mac_address
                    else:
                        return "MAC not found"
                return result
            elif platform.system() == "Linux":
                result = subprocess.check_output(["ip", "link"]).decode()
                for line in result.splitlines():
                    if "link/ether" in line:
                        return line.split()[2]
                return "MAC not found"
            elif platform.system() == "Darwin":
                result = subprocess.check_output(
                    "ifconfig en0 | grep ether", shell=True
                ).decode().split()[1]
                return result
            else:
                return "Platform not supported for MAC address"
        except Exception as e:
            print(f"Error getting MAC address: {e}")
            return "Unknown"

    system_info["device_id"] = get_device_id()
    system_info["device_name"] = get_device_name()
    system_info["current_user"] = get_current_user()
    system_info["mac_address"] = get_mac_address()

    return system_info

# Dictionaries for tracking
# Key: partial_hash_verify (string), Value: normalized file path
tracked_files = {}

# Key: normalized file path, Value: partial_hash_verify (string)
path_to_hash = {}

def add_to_tracking(normalized_path, hash_data):
    """
    Add file to both dictionaries if not already present.
    """
    if hash_data and normalized_path:
        if normalized_path not in path_to_hash:
            tracked_files[hash_data] = normalized_path
            path_to_hash[normalized_path] = hash_data
            print(f"Added to tracking: {normalized_path} (Hash: {hash_data})")

def remove_from_tracking_by_path(normalized_path):
    """
    Removes a file from both dictionaries using its path.
    Returns the hash_data for logging purposes.
    """
    hash_data = None
    if normalized_path in path_to_hash:
        hash_data = path_to_hash[normalized_path]
        del path_to_hash[normalized_path]

        if hash_data in tracked_files:
            del tracked_files[hash_data]

        print(f"Removed from tracking: {normalized_path} (Hash: {hash_data})")
    return hash_data

def initialize_cache(path):
    """
    Initializes the tracking dictionaries with existing files that have the required metadata.
    """
    print("Initializing cache...")
    for root, dirs, files in os.walk(path):
        # Optional: Exclude certain system directories for performance on Windows
        excluded_dirs = {"C:\\Windows", "C:\\Program Files", "C:\\ProgramData"}
        if is_windows() and any(os.path.commonpath([root, ex_dir]) == ex_dir for ex_dir in excluded_dirs):
            continue

        for file in files:
            file_path = os.path.join(root, file)
            hash_data = has_required_metadata(file_path)
            if hash_data:
                normalized = normalize_path(file_path)
                add_to_tracking(normalized, hash_data)
    print(f"Cache initialized with {len(tracked_files)} files.")

def send_delete_request(partial_hash_verify):
    """
    Sends a POST request to the Flask server to delete the record associated with the given hash.
    """
    url = "http://127.0.0.1:5050/delete_record"
    system_info = get_system_info()
    payload = {
        "partial_hash_verify": partial_hash_verify,
        "device_info": system_info
    }
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print(f"Successfully deleted record from server: {partial_hash_verify}")
        elif response.status_code == 404:
            print(f"No record found on server for hash: {partial_hash_verify}")
        else:
            print(f"Failed to delete record on server. Status Code: {response.status_code}, Response: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error communicating with server: {e}")

class FileEventHandler(FileSystemEventHandler):
    """
    Custom event handler that processes events only for files with specific metadata.
    """

    def on_created(self, event):
        if not event.is_directory:
            hash_data = has_required_metadata(event.src_path)
            normalized_src = normalize_path(event.src_path)
            if hash_data:
                add_to_tracking(normalized_src, hash_data)
                print(f"[CREATED] Added to tracking: {normalized_src} (Hash: {hash_data})")

    def on_modified(self, event):
        if not event.is_directory:
            hash_data = has_required_metadata(event.src_path)
            normalized_src = normalize_path(event.src_path)

            if hash_data:
                if normalized_src not in path_to_hash:
                    add_to_tracking(normalized_src, hash_data)
                    print(f"[MODIFIED] Added to tracking: {normalized_src} (Hash: {hash_data})")
                else:
                    print(f"[MODIFIED] {normalized_src} (Hash: {hash_data})")
            else:
                # File lost metadata
                if normalized_src in path_to_hash:
                    hash_removed = remove_from_tracking_by_path(normalized_src)
                    if hash_removed:
                        send_delete_request(hash_removed)

    def on_moved(self, event):
        if not event.is_directory:
            hash_data = has_required_metadata(event.dest_path)
            normalized_src = normalize_path(event.src_path)
            normalized_dest = normalize_path(event.dest_path)

            if hash_data:
                # Destination file has metadata
                if normalized_src in path_to_hash:
                    # Remove old
                    hash_removed = remove_from_tracking_by_path(normalized_src)
                    if hash_removed:
                        send_delete_request(hash_removed)
                add_to_tracking(normalized_dest, hash_data)
                print(f"[MOVED] File moved to: {normalized_dest} (Hash: {hash_data}) with metadata.")
            else:
                # Destination lacks metadata
                if normalized_src in path_to_hash:
                    hash_removed = remove_from_tracking_by_path(normalized_src)
                    if hash_removed:
                        send_delete_request(hash_removed)
                    print(f"[MOVED] File moved and lost metadata: {normalized_src}")

    def on_deleted(self, event):
        if not event.is_directory:
            normalized_src = normalize_path(event.src_path)
            if normalized_src in path_to_hash:
                hash_data = path_to_hash[normalized_src]
                print(f"[DELETED] {normalized_src} (Hash: {hash_data})")
                hash_removed = remove_from_tracking_by_path(normalized_src)
                if hash_removed:
                    send_delete_request(hash_removed)

def monitor_directory(path_to_monitor):
    if not os.path.exists(path_to_monitor):
        print(f"Error: The path {path_to_monitor} does not exist.")
        sys.exit(1)

    event_handler = FileEventHandler()
    observer = Observer()
    observer.schedule(event_handler, path_to_monitor, recursive=True)

    observer.start()
    print(f"Monitoring started on: {path_to_monitor}")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        observer.stop()
        print("Monitoring stopped.")
    observer.join()

if __name__ == "__main__":
    if is_windows():
        path_to_monitor = "C:\\"
    else:
        path_to_monitor = os.path.expanduser("~")

    print(f"Monitoring: {path_to_monitor}")
    initialize_cache(path_to_monitor)
    monitor_directory(path_to_monitor)
