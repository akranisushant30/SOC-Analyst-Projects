import winreg
import json
import time
import os 
from datetime import datetime
#Targets
Targets = [
    {"hive" : winreg.HKEY_CURRENT_USER, "path" : r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "name" : "User_Startup"},
    {"hive": winreg.HKEY_LOCAL_MACHINE, "path": r"Software\Microsoft\Windows\CurrentVersion\Run", "name": "System_Startup"},
    {"hive": winreg.HKEY_LOCAL_MACHINE, "path": r"Software\Policies\Microsoft\Windows Defender", "name": "Defender_Policies"}
]
BASELINE_FILE = "registry_baseline.json"
LOG_file = "Security_alerts.log"
#BaseLine Function
def create_baseline():
    overall_baseline={}
    for target in Targets:
        try:
            # Open the registry key with Read-Only permissions
            key = winreg.OpenKey(target["hive"], target["path"],0,winreg.KEY_READ)
            # Query the key to find out how many values (entries) it contains
            num_entries = winreg.QueryInfoKey(key)[1]
            print(f"Total entries {num_entries}\n")
            current_entries = {}
            for i in range(num_entries):
                # Enumerate through each value index to get Name and Data
                name,value,_ = winreg.EnumValue(key,i)
                current_entries[name]=str(value)
            # Map the entries to the target name in our dictionary
            overall_baseline[target["name"]] = current_entries
            print(f"Final Baseline Data:", overall_baseline)
            winreg.CloseKey(key)
        except FileNotFoundError:
            print(f"Error [!] : Path Not Found in Registry -> {target['path']}")
    # Save the captured data permanently into a JSON file
    with open(BASELINE_FILE,'w') as f:
        json.dump(overall_baseline,f,indent=4)
    print(f"[Success] Baseline file created: {BASELINE_FILE}")

def write_log(message):
    """Adds a timestamped security alert to the log file and console"""
    timestamp = datetime.now().strftime("%d-%m-%y : %H:%M:%S")
    log_entry=f"[{timestamp}] {message}\n"
    with open(LOG_file,"a") as f:
        f.write(log_entry)
    print(log_entry.strip())

def monitor_registry():
    """Continuously compares current registry state against the saved baseline"""
    if not os.path.exists(BASELINE_FILE):
        print("[Error] Create Baseline file first.")
        return
    # Load the previously saved 'trusted' state
    with open(BASELINE_FILE,"r") as f:
        baseline = json.load(f)
    print(f"[*] Shield Active. Monitoring {len(Targets)} location in every 10s..")
    
    try:
        while True:
            for target in Targets:
                t_name = target["name"]
                try:
                    #Scan Current Registry 
                    key = winreg.OpenKey(target["hive"],target["path"],0,winreg.KEY_READ)
                    num_entries = winreg.QueryInfoKey(key)[1]
                    current_data = {winreg.EnumValue(key,i)[0]:str(winreg.EnumValue(key,i)[1]) for i in range (num_entries)}
                    winreg.CloseKey(key)

                    #Comparing
                    old_data = baseline.get(t_name,{})

                    #check for Addition/Modification
                    for name,value in current_data.items():
                        if name not in old_data:
                            msg = f"CRITICAL ALERT: New entry in {t_name} -> {name}:{value}"
                            write_log(msg)
                            old_data[name] = value #update baseline to avoid spam
                        elif old_data[name] != value:
                            msg = f"WARNING: Modification in {t_name} -> {name}:{value} changed its Value!"
                            write_log(msg)
                            old_data[name]=value
                    #Check For Deletion
                    for name in list(old_data.keys()):
                        if name not in current_data:
                            msg=f"INFO: Entry Deleted from {t_name}->{name}"
                            write_log(msg)
                            del old_data[name]
                except Exception:
                    continue
            # Wait for 10 seconds before the next scan
            time.sleep(10)
    except KeyboardInterrupt:
        print("\n [!] Shield Deactivated")

if __name__ == "__main__":
    if not os.path.exists(BASELINE_FILE):
        print("No Baseline File Found... Creating new one")
        create_baseline()

    monitor_registry()