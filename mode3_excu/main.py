#!/usr/bin/env python3
import os
import subprocess
import time
import mail
import shutil
import datetime
import hashlib

def read_old_files():
    """Read the list of already processed files."""
    old_files = set()
    if os.path.exists("old.txt"):
        with open("old.txt", "r") as f:
            content = f.read().strip()
            if content:
                for line in content.split("\n"):
                    if line:
                        old_files.add(line)
    return old_files

def write_old_files(old_files):
    """Write the list of processed files."""
    with open("old.txt", "w") as f:
        for file in old_files:
            f.write(f"{file}\n")

def get_new_files(dic_dir, old_files):
    """Get list of new files in dic directory."""
    all_files = set()
    for filename in os.listdir(dic_dir):
        file_path = os.path.join(dic_dir, filename)
        if os.path.isfile(file_path):
            all_files.add(filename)
    
    return all_files - old_files

def get_file_hash(file_path):
    """Get SHA256 hash of a file."""
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            # Read and update hash in chunks of 4K
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error calculating hash: {e}")
        return None

def copy_found_hash_with_sha256(found_hash_path, sha256_value):
    """Copy found.hash to found directory with SHA256 value as filename."""
    # Ensure found directory exists
    found_dir = os.path.join("found")
    if not os.path.exists(found_dir):
        os.makedirs(found_dir)
    
    # Use SHA256 hash as filename
    dest_filename = f"{sha256_value}.hash"
    dest_path = os.path.join(found_dir, dest_filename)
    
    # Copy file
    try:
        shutil.copy2(found_hash_path, dest_path)
        print(f"Copied found.hash to {dest_path}")
        return True
    except Exception as e:
        print(f"Error copying found.hash: {e}")
        return False

def main():
    # Initialize variables
    dic_dir = "../dic"
    found_hash_path = "found.hash"
    
    # Ensure dic directory exists
    if not os.path.exists(dic_dir):
        os.makedirs(dic_dir)
    
    # Get list of processed files
    old_files = read_old_files()
    
    # Get initial hash of found.hash
    prev_hash = get_file_hash(found_hash_path) if os.path.exists(found_hash_path) else None
    
    while True:
        # Get new files
        new_files = get_new_files(dic_dir, old_files)
        
        if not new_files:
            print("No new files to process. Waiting...")
            time.sleep(10)
            continue
        
        for file in new_files:
            print(f"Processing {file}...")
            
            # Run brainflayer command
            cmd = f"./brainflayer_warpwallet -f ../dic/{file} -a address.hash -o found.hash"
            try:
                process = subprocess.run(cmd, shell=True, check=True)
                print(f"Finished processing {file}")
                
                # Mark file as processed
                old_files.add(file)
                write_old_files(old_files)
                
                # Check if found.hash has changed
                current_hash = get_file_hash(found_hash_path)
                if current_hash != prev_hash:
                    print(f"found.hash content changed!")
                    if prev_hash:
                        print(f"Previous hash: {prev_hash}")
                    print(f"Current hash: {current_hash}")
                    
                    # Copy found.hash with SHA256 as filename
                    copy_found_hash_with_sha256(found_hash_path, current_hash)
                    # Send email notification
                    mail.send_success_email("", file)
                    prev_hash = current_hash
                
            except subprocess.CalledProcessError as e:
                print(f"Error processing {file}: {e}")
        
        # Check for any new files that might have been added during processing
        time.sleep(5)

if __name__ == "__main__":
    main() 