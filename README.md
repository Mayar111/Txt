# Function to automatically detect PIDs of relevant processes (e.g., javaw.exe)
def get_relevant_pids():
    relevant_pids = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            # Check for processes that might be related to PoS software
            if proc.info['name'] in ['javaw.exe', 'java.exe', 'python.exe', 'node.exe']:  # Add other relevant names here if needed
                print(f"Detected relevant process: {proc.info['name']} (PID: {proc.info['pid']})")
                relevant_pids.append(proc.info['pid'])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return relevant_pids

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
