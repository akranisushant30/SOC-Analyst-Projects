import psutil
import time
import os

# 1. Suspicious Rules
SUSPICIOUS_PARENTS = ['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe']
SUSPICIOUS_CHILDREN = ['cmd.exe', 'powershell.exe', 'wmic.exe', 'scrcons.exe']
TEMP_PATHS = ['\\temp\\', '\\tmp\\', '\\appdata\\local\\temp']

def monitor_agent():
    print("="*50)
    print("  SOC MONITORING AGENT: PROCESS & SERVICE AUDIT  ")
    print("="*50)
    print("[*] Monitoring started... (Press Ctrl+C to stop)\n")

    # processes list 
    observed_pids = set()
    for p in psutil.process_iter():
        observed_pids.add(p.pid)

    try:
        while True:
            for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe']):
                try:
                    pid = proc.info['pid']
                    if pid not in observed_pids:
                        # New Process found
                        name = proc.info['name'].lower()
                        ppid = proc.info['ppid']
                        exe_path = proc.info['exe'].lower() if proc.info['exe'] else "Unknown"
                        
                        # Parent details
                        parent_name = psutil.Process(ppid).name().lower() if psutil.pid_exists(ppid) else "N/A"

                        print(f"[*] NEW PROCESS: {name} (PID: {pid}) | Parent: {parent_name}")

                        # A. Parent-Child Anomaly Detection 
                        if parent_name in SUSPICIOUS_PARENTS and name in SUSPICIOUS_CHILDREN:
                            print(f"    [!!!] ALERT: Suspicious Relationship! {parent_name} spawned {name}")

                        # B. Unauthorized Path Detection
                        if any(folder in exe_path for folder in TEMP_PATHS):
                            print(f"    [!] WARNING: Process running from suspicious directory: {exe_path}")

                        observed_pids.add(pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n[!] Monitoring stopped by user.")

if __name__ == "__main__":
    monitor_agent()