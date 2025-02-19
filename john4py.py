import os
import sys
import platform
import hashlib
import concurrent.futures
import time
from threading import Event
from termcolor import colored

# Function to detect the hash type based on the length of the hash
def detect_hash_algorithm(hash_value):
    hash_length = len(hash_value)
    if hash_length == 32:
        return "md5"
    elif hash_length == 40:
        return "sha1"
    elif hash_length == 64:
        return "sha256"
    elif hash_length == 60 and hash_value.startswith("$2a$"):
        return "bcrypt"
    else:
        return None  # Unknown hash type

# Function to hash passwords
def hash_password(password, hash_algorithm="md5"):
    if hash_algorithm == "md5":
        return hashlib.md5(password.encode()).hexdigest()
    elif hash_algorithm == "sha1":
        return hashlib.sha1(password.encode()).hexdigest()
    elif hash_algorithm == "sha256":
        return hashlib.sha256(password.encode()).hexdigest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")

# Multi-threaded function for cracking the hash using a wordlist
def crack_with_wordlist(hash_value, wordlist, hash_algorithm, start, end, stop_event, result):
    with open(wordlist, "r", encoding="utf-8", errors="ignore") as file:
        for i, line in enumerate(file):
            if i < start:  # Skip to the start index
                continue
            if i > end:  # Stop when reaching the end index
                break
            password = line.strip()
            hashed_password = hash_password(password, hash_algorithm)

            # Check if cracking has been stopped
            if stop_event.is_set():
                return None

            print(colored(f"[+] Trying password: {password}", "yellow"))
            if hashed_password == hash_value:
                result.append(password)  # Save correct password
                stop_event.set()  # Stop all threads
                print(colored(f"[+] Correct password found: {password}", "green"))
                return password
            time.sleep(0.1)  # Slow down to make output visible
    return None

# Function to display ASCII banner from file
def display_banner():
    try:
        # Get the directory of the current script
        script_dir = os.path.dirname(os.path.realpath(sys.argv[0]))
        banner_path = os.path.join(script_dir, "john4py_banner.txt")  # Use the correct file name
        with open(banner_path, "r", encoding="utf-8", errors="ignore") as banner_file:
            banner = banner_file.read()
        print(colored(banner, "cyan"))
    except FileNotFoundError:
        print(colored("[!] Banner file not found in the script directory.", "red"))
    except UnicodeDecodeError:
        print(colored("[!] Failed to decode the banner file. Check its encoding.", "red"))

# Pause the terminal to prevent it from closing
def pause_terminal():
    if platform.system() == "Windows":
        os.system("pause")
    else:
        input(colored("\n[+] Press Enter to exit...", "yellow"))

# Main function for running the cracking tool
def main():
    try:
        # Display ASCII banner
        display_banner()

        # Ask user for the hash to crack
        hash_to_crack = input(colored("[+] Enter the hash to crack: ", "cyan"))

        # Automatically detect hash algorithm
        hash_algorithm = detect_hash_algorithm(hash_to_crack)
        if not hash_algorithm:
            print(colored("[-] Unknown hash type. Please specify the hash algorithm manually.", "red"))
            return

        print(colored(f"[+] Detected hash algorithm: {hash_algorithm}", "green"))

        # Dynamically locate wordlist file
        script_dir = os.path.dirname(os.path.realpath(sys.argv[0]))
        wordlist = os.path.join(script_dir, "rockyou.txt")  # Build the absolute path to rockyou.txt
        
        if not os.path.exists(wordlist):
            print(colored(f"[!] Wordlist file not found: {wordlist}", "red"))
            return

        # Thread stop event
        stop_event = Event()
        result = []

        # Wordlist-based cracking with multi-threading
        print(colored("[+] Starting wordlist-based cracking...", "yellow"))
        num_threads = 8  # Set the number of threads based on your CPU
        total_lines = sum(1 for _ in open(wordlist, "r", encoding="utf-8", errors="ignore"))
        chunk_size = total_lines // num_threads

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = []
            for i in range(num_threads):
                start = i * chunk_size
                end = (i + 1) * chunk_size if i < num_threads - 1 else total_lines
                futures.append(executor.submit(crack_with_wordlist, hash_to_crack, wordlist, hash_algorithm, start, end, stop_event, result))

            for future in concurrent.futures.as_completed(futures):
                if stop_event.is_set():
                    break

        if result:
            print(colored("[+] Cracking completed!", "green"))
        else:
            print(colored("[-] Password not found in the wordlist.", "red"))

    except Exception as e:
        # Print any exception that occurs
        print(colored(f"[!] An error occurred: {e}", "red"))
    finally:
        pause_terminal()

if __name__ == "__main__":
    main()
