#!/usr/bin/env python3
import sys
import shutil
import platform
import os
import requests
import hashlib
import time
import random
import urllib.parse
import subprocess


def is_windows():
    return platform.system().lower() == "windows"


def is_linux():
    return platform.system().lower() == "linux"


def command_exists(command):
    return shutil.which(command) is not None


def print_usage():
    usage_text = """
Usage: ddas <command> [options]

Available commands:
  hello                         Print 'Hello, World!'
  wget [wget_options] <URL>     Run native wget with the specified arguments
  curl [curl_options] <URL>     Run native curl with the specified arguments
  <script.py> [args]            Execute a Python script with optional arguments
  <script.sh> [args]            Execute a Bash script with optional arguments
"""
    print(usage_text.strip())


def extract_url_and_flags(args):
    """
    Extract URL and flags from the given args.
    We'll try to find a URL that starts with http:// or https://.
    If found, that is considered the URL and the rest are flags.
    """
    url = None
    # We'll scan from the end to find a URL
    for i in range(len(args)-1, -1, -1):
        if args[i].startswith('http://') or args[i].startswith('https://'):
            url = args[i]
            flags = args[:i] + args[i+1:]
            break

    if url is None:
        # No URL found
        flags = args
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
                # Try reading a small chunk
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
    if total_bytes < 10 * MB:
        return None
    elif total_bytes >= 10 * MB and total_bytes < 25 * MB:
        return int(2.5 * MB)
    elif total_bytes >= 25 * MB and total_bytes < 50 * MB:
        return int(5 * MB)
    elif total_bytes >= 50 * MB and total_bytes < 1024 * MB:
        return int(10 * MB)
    elif total_bytes >= 1024 * MB:
        return int(20 * MB)
    else:
        return None


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
            print(f"Downloaded {len(downloaded_data)
                                } instead of {download_size}")
            return None

        # Compute SHA-256
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


def send_data_to_server(
    id_value,
    downloadMetaData,
    fetchedMetaData,
    downloadFileNameDomainUrlDetails,
    partialHash
):
    """
    Emulate the background.js logic:
    POST to http://127.0.0.1:5500/process_download
    Body includes:
        id, data: { 
            download_meta_data, 
            fetched_complete_metadata,
            downloadFileNameDomainUrlDetails,
            partial_hash 
        }
    Expect result.action in response.
    """
    payload = {
        "id": id_value,
        "data": {
            "download_meta_data": downloadMetaData,
            "fetched_complete_metadata": fetchedMetaData,
            "downloadFileNameDomainUrlDetails": downloadFileNameDomainUrlDetails,
            "partial_hash": partialHash
        }
    }

    try:
        resp = requests.post(
            "http://127.0.0.1:5500/process_download", json=payload, timeout=10)
        if resp.ok:
            result = resp.json()
            return result.get("action", None)
        else:
            print(f"Server responded with an error: {
                  resp.status_code} {resp.text}")
            return None
    except Exception as e:
        print(f"Failed to communicate with the server: {e}")
        return None


def handle_download_logic(url, proposed_filename):
    """
    This integrates the logic from background.js:
    - Generate an ID
    - Prepare metadata
    - HEAD request, partial hash if needed
    - Send to server, get action
    """

    # Generate a random ID for the download
    download_id = random.randint(100000, 999999)
    domain = get_domain_from_url(url)

    # Fetch HEAD to get metadata like content-length, content-type
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

    # Construct download metadata (simulating downloadItem from background.js)
    downloadMetaData = {
        "id": download_id,
        "url": url,
        "filename": proposed_filename if proposed_filename else "Unknown File",
        "mime": mime,
        "totalBytes": total_bytes if total_bytes is not None else "Unknown",
        "bytesReceived": 0,
        "danger": "safe",
        "state": "in_progress",
        "paused": True,  # Simulating that we "paused" before download
        "incognito": False,
        "startTime": start_time,
        "canResume": True,
        "referrer": "None",
        "finalUrl": url,
        "error": "None",
        "endTime": "Unknown"
    }

    fetchedMetaData = headers  # from HEAD request

    downloadFileNameDomainUrlDetails = {
        "id": download_id,
        "downloadFileName": proposed_filename if proposed_filename else "Unknown File",
        "domain": domain
    }

    # Check capabilities
    capabilities = check_server_capabilities(url)

    partialHash = None
    if total_bytes is not None:
        partial_size = determine_partial_download_size(total_bytes)
        if partial_size:
            print(f"Partial download size determined: {partial_size} bytes.")
            partialHash = partial_download_and_hash(
                url, partial_size, capabilities)
            if partialHash:
                print(
                    f"SHA-256 Hash of the first {partial_size} bytes: {partialHash}")
            else:
                print("Failed to compute partial hash.")
        else:
            print("No hash computation required for this download size.")
    else:
        print("Unknown total size. Skipping partial hash.")

    # Send data to server
    action = send_data_to_server(download_id, downloadMetaData,
                                 fetchedMetaData, downloadFileNameDomainUrlDetails, partialHash)
    if action is None:
        print("No valid action received from server. Defaulting to cancel.")
        action = -1

    return action


def handle_wget(command_args):
    url, flags = extract_url_and_flags(command_args)
    if url is None:
        print("Error: No URL provided to wget.")
        return

    # Derive a proposed filename from URL if no explicit filename is given in flags
    # This is a simplistic approach. In reality, wget determines filename from URL or content-disposition.
    proposed_filename = os.path.basename(
        urllib.parse.urlparse(url).path) or "downloaded_file"

    # Perform logic akin to background.js
    action = handle_download_logic(url, proposed_filename)

    if is_windows() and not command_exists("wget"):
        print("The 'wget' command is not available on this Windows system.")
        print("This feature is implemented in future updates.")
        # Action is irrelevant since we can't run wget
        return
    elif is_linux() and not command_exists("wget"):
        print("Error: 'wget' command not found on Linux. Please install wget.")
        return

    # Based on action:
    if action == 0:
        # Resume = execute wget
        full_command = ["wget"] + flags + [url]
        print(f"Executing command: {' '.join(full_command)}")
        try:
            result = subprocess.run(full_command, check=True)
            if result.returncode == 0:
                print("wget command executed successfully!")
        except subprocess.CalledProcessError as error:
            print(f"Error during wget execution: {error}")
    elif action == -1:
        # Cancel
        print("Download canceled by server instruction.")
    elif action == 1:
        # Keep paused
        print("Download remains paused as per server instruction.")


def handle_curl(command_args):
    url, flags = extract_url_and_flags(command_args)
    if url is None:
        print("Error: No URL provided to curl.")
        return

    proposed_filename = os.path.basename(
        urllib.parse.urlparse(url).path) or "downloaded_file"

    # Perform logic akin to background.js
    action = handle_download_logic(url, proposed_filename)

    if is_windows() and not command_exists("curl"):
        print("The 'curl' command is not available on this Windows system.")
        print("This feature is implemented in future updates.")
        return
    elif is_linux() and not command_exists("curl"):
        print("Error: 'curl' command not found on Linux. Please install curl.")
        return

    # Based on action:
    if action == 0:
        # Resume = execute curl
        full_command = ["curl"] + flags + [url]
        print(f"Executing command: {' '.join(full_command)}")
        try:
            result = subprocess.run(full_command, check=True)
            if result.returncode == 0:
                print("curl command executed successfully!")
        except subprocess.CalledProcessError as error:
            print(f"Error during curl execution: {error}")
    elif action == -1:
        print("Download canceled by server instruction.")
    elif action == 1:
        print("Download remains paused as per server instruction.")


def main():
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    subcommand = sys.argv[1]
    subcommand_args = sys.argv[2:]

    if subcommand.lower() == "hello":
        print("Hello, World!")
    elif subcommand.lower() == "wget":
        handle_wget(subcommand_args)
    elif subcommand.lower() == "curl":
        handle_curl(subcommand_args)
    else:
        # Handle scripts or unknown commands
        print(f"Unknown command: {subcommand}")
        print_usage()


if __name__ == "__main__":
    main()
