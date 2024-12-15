# download_logic/download_handler.py

import random
import time

import platform
import os
import subprocess
import uuid
import socket

from utils.helpers import (
    fetch_head,
    check_server_capabilities,
    determine_partial_download_size,
    partial_download_and_hash,
    get_domain_from_url,
    send_data_to_server,
    determine_proposed_filename
)

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
                return subprocess.check_output("system_profiler SPHardwareDataType | grep 'UUID:'", shell=True).decode().split(":")[1].strip()
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
                result = subprocess.check_output(["getmac", "/fo", "csv", "/nh"]).decode().strip().split(",")[0].replace('"', '')
                if result == "":
                    result = subprocess.check_output(["ipconfig", "/all"]).decode()
                    mac_address_lines = [line for line in result.splitlines() if "Physical Address" in line]
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
                result = subprocess.check_output("ifconfig en0 | grep ether", shell=True).decode().split()[1]
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
print(get_system_info())

def handle_download_logic(url):
    download_id = random.randint(100000, 999999)
    domain = get_domain_from_url(url)

    headers = fetch_head(url)
    content_length = headers.get('content-length')
    if content_length:
        try:
            total_bytes = int(content_length)
        except:
            total_bytes = None
    else:
        total_bytes = None

    mime = headers.get('content-type', 'Unknown')
    start_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    filename = determine_proposed_filename(url)

    download_meta_data = {
        "id": download_id,
        "url": url,
        "filename": filename,
        "mime": mime,
        "totalBytes": total_bytes if total_bytes is not None else "Unknown",
        "bytesReceived": 0,
        "danger": "safe",
        "state": "in_progress",
        "paused": True,
        "incognito": False,
        "startTime": start_time,
        "canResume": True,
        "referrer": "None",
        "finalUrl": url,
        "error": "None",
        "endTime": "Unknown"
    }

    fetched_meta_data = headers
    download_details = {
        "id": download_id,
        "downloadFileName": filename,
        "domain": domain
    }

    capabilities = check_server_capabilities(url)

    if total_bytes is not None:
        partial_size = determine_partial_download_size(total_bytes)
        if partial_size and partial_size > 0:
            print(f"Partial download size determined: {partial_size} bytes.")
            partial_hash = partial_download_and_hash(
                url, partial_size, capabilities)
            if partial_hash:
                print(
                    f"SHA-256 Hash of the downloaded portion: {partial_hash}")
            else:
                print("Failed to compute file_hash_check_parts.")
        else:
            print("No file_hash_check_parts computation required.")
            partial_hash = None
    else:
        print("Unknown total size. Skipping file_hash_check_parts.")
        partial_hash = None
    aaa = get_system_info()
    action = send_data_to_server(
        download_id, download_meta_data, fetched_meta_data, download_details, partial_hash, aaa)
    if action is None:
        print("No valid action received from server. Defaulting to cancel.")
        action = -1

    return action, partial_hash
