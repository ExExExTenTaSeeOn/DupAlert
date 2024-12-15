# utils/helpers.py

"""
Utility functions for the ddas CLI tool.
"""

import shutil
import platform
import urllib.parse
import hashlib
import requests
import os
import subprocess

try:
    import xattr  # For Linux/macOS if installed
except ImportError:
    xattr = None


def is_windows():
    return platform.system().lower() == "windows"


def is_linux():
    return platform.system().lower() == "linux"


def is_macos():
    return platform.system().lower() == "darwin"


def command_exists(command):
    return shutil.which(command) is not None


def extract_url_and_flags(args):
    url = None
    flags = []
    for i in range(len(args) - 1, -1, -1):
        if args[i].startswith('http://') or args[i].startswith('https://'):
            url = args[i]
            flags = args[:i] + args[i+1:]
            break
    if url is None:
        non_flag_args = [arg for arg in args if not arg.startswith('-')]
        if len(non_flag_args) == 1 and (non_flag_args[0].startswith('http://') or non_flag_args[0].startswith('https://')):
            url = non_flag_args[0]
            flags = [arg for arg in args if arg != url]
    return url, flags


def fetch_head(url):
    try:
        resp = requests.head(url, allow_redirects=True, timeout=10)
        if resp.status_code < 400:
            headers = dict((k.lower(), v) for k, v in resp.headers.items())
            return headers
        else:
            return {}
    except Exception as e:
        print(f"Failed to fetch HEAD for {url}: {e}")
        return {}


def check_server_capabilities(url):
    capabilities = {
        'range_supported': False,
        'streaming_supported': False
    }
    try:
        head_resp = requests.head(url, allow_redirects=True, timeout=10)
        if head_resp.ok:
            accept_ranges = head_resp.headers.get('Accept-Ranges')
            if accept_ranges and accept_ranges.lower() == 'bytes':
                capabilities['range_supported'] = True

        get_resp = requests.get(url, stream=True, timeout=10)
        if get_resp.ok:
            transfer_encoding = get_resp.headers.get('Transfer-Encoding')
            if transfer_encoding and transfer_encoding.lower() == 'chunked':
                capabilities['streaming_supported'] = True
            else:
                for chunk in get_resp.iter_content(chunk_size=1024):
                    if chunk:
                        capabilities['streaming_supported'] = True
                        break
        get_resp.close()
    except Exception as e:
        print(f"Error checking server capabilities for {url}: {e}")
    return capabilities


def determine_partial_download_size(total_bytes):
    MB = 1024 * 1024
    if total_bytes < MB:
        return total_bytes
    elif MB <= total_bytes < 10 * MB:
        return MB
    else:
        # Original logic for larger files
        if total_bytes < 25 * MB:
            return int(2.5 * MB)
        elif total_bytes < 50 * MB:
            return int(5 * MB)
        elif total_bytes < 1024 * MB:
            return int(10 * MB)
        else:
            return int(20 * MB)


def partial_download_and_hash(url, download_size, capabilities):
    downloaded_data = bytearray()
    try:
        if capabilities['range_supported']:
            headers = {'Range': f'bytes=0-{download_size-1}'}
            resp = requests.get(url, headers=headers, stream=True, timeout=20)
            if resp.status_code == 206:
                for chunk in resp.iter_content(chunk_size=4096):
                    if chunk:
                        bytes_needed = download_size - len(downloaded_data)
                        if bytes_needed <= 0:
                            break
                        piece = chunk[:bytes_needed]
                        downloaded_data.extend(piece)
                        if len(downloaded_data) >= download_size:
                            break
            else:
                print("Server did not honor Range header.")
                return None
        elif capabilities['streaming_supported']:
            resp = requests.get(url, stream=True, timeout=20)
            if resp.ok:
                for chunk in resp.iter_content(chunk_size=4096):
                    if chunk:
                        bytes_needed = download_size - len(downloaded_data)
                        if bytes_needed <= 0:
                            break
                        piece = chunk[:bytes_needed]
                        downloaded_data.extend(piece)
                        if len(downloaded_data) >= download_size:
                            break
            else:
                print("Failed to GET the URL for streaming.")
                return None
        else:
            print("No range or streaming support for partial download.")
            return None

        if len(downloaded_data) < download_size:
            print(f"Downloaded {len(downloaded_data)} instead of {download_size} bytes.")
            return None

        sha256_hash = hashlib.sha256(downloaded_data).hexdigest()
        return sha256_hash
    except Exception as e:
        print(f"Error during partial download and hashing: {e}")
        return None


def get_domain_from_url(url):
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.hostname if parsed.hostname else "unknown-domain"
    except:
        return "unknown-domain"


def send_data_to_server(id_value, download_meta_data, fetched_meta_data, download_details, partial_hash, deviceInfo):
    payload = {
        "id": id_value,
        "data": {
            "download_meta_data": download_meta_data,
            "fetched_complete_metadata": fetched_meta_data,
            "downloadFileNameDomainUrlDetails": download_details,
            "partial_hash": partial_hash,
            "device_info": deviceInfo
        }
    }

    try:
        # resp = requests.post("http://127.0.0.1:5050/process_download", json=payload, timeout=10) #local Host
        resp = requests.post("https://f614-103-102-86-3.ngrok-free.app", json=payload, timeout=10)
        if resp.ok:
            result = resp.json()
            return result.get("action", None)
        else:
            print(f"Server responded with an error: {resp.status_code} {resp.text}")
            return None
    except Exception as e:
        print(f"Failed to communicate with the server: {e}")
        return None


def determine_proposed_filename(url):
    return os.path.basename(urllib.parse.urlparse(url).path) or "downloaded_file"


def print_usage():
    usage_text = """
Usage: ddas <command> [options]

Available commands:
  hello                         Print 'Hello, World!'
  wget [wget_options] <URL>     Run native wget with the specified arguments
  curl [curl_options] <URL>     Run native curl with the specified arguments
  <script.py> [args]            Execute a Python script with optional arguments
  <script.sh> [args]            Execute a Bash script with optional arguments

Help:
  -h, --help                    Show this help message and exit
    """
    print(usage_text.strip())


def store_partial_hash(file_path, hash_value):
    # Replacing 'partial_hash' with 'file_hash_check_parts'
    if is_windows():
        store_partial_hash_ads(file_path, hash_value)
    elif is_linux() or is_macos():
        store_partial_hash_xattr(file_path, hash_value)
    else:
        print(f"Unsupported platform for attaching metadata to '{file_path}'.")


def store_partial_hash_ads(filename, hash_value):
    ads_name = f"{filename}:file_hash_check_parts"
    try:
        with open(ads_name, "w") as ads:
            ads.write(hash_value)
        print(f"file_hash_check_parts stored as ADS in '{filename}'.")
    except Exception as e:
        print(f"Failed to store file_hash_check_parts in ADS: {e}")


def store_partial_hash_xattr(filename, hash_value):
    if xattr is None:
        print("xattr module not installed. Cannot store extended attributes.")
        return

    try:
        # Using pyxattr's functional interface
        # Attribute keys must be bytes, and conventionally start with 'user.'
        xattr.setxattr(filename, b"user.file_hash_check_parts",
                       hash_value.encode('utf-8'))
        print(f"file_hash_check_parts stored as extended attribute in '{filename}'.")
    except Exception as e:
        print(
            f"Failed to store file_hash_check_parts in extended attributes: {e}")
